#!/usr/bin/env python3
"""anchor - firmware base address finder for raw embedded firmware images.

Usage:
    anchor.py <image> --arch {arm,mips32,ppc32} --endian {le,be} [options]

Strategies:
    strings  - correlate pointer values with string offsets
    selfref  - density of pointer words that land inside the image
    arch     - architecture-specific fingerprint (arm cortex-m vector table,
               mips/ppc common prologues + known reset vectors)
"""

# ============================================================================
# Tunable constants
# ============================================================================

DEFAULT_ALIGN = 0x1000
DEFAULT_TOP_N = 5

# Minimum length of a printable ASCII run to consider it a string.
# Higher = fewer strings, faster scoring, more discriminative.
MIN_STRING_LEN = 8

# Scoring weights - combined score = sum(W_x * normalized_score_x)
W_STRINGS = 1.0
W_SELFREF = 1.0
W_ARCH    = 2.0

# Default candidate base ranges per arch (user can override on CLI)
ARCH_RANGES = {
    "arm":    (0x00000000, 0xFFFF0000),
    "mips32": (0x80000000, 0xBFC00000),
    "ppc32":  (0x00000000, 0xFFF00000),
}

# Cortex-M initial SP plausible RAM range (broad; no vendor curation)
CORTEXM_SP_MIN = 0x10000000
CORTEXM_SP_MAX = 0x40000000

# MIPS reset / kseg bases credited when MIPS prologue density fires
MIPS_COMMON_BASES = [0xBFC00000, 0x9FC00000, 0x80000000, 0x80100000, 0x80010000]

# PPC common reset / vector bases credited when PPC prologue density fires
PPC_COMMON_BASES = [0x00000000, 0x00100000, 0x01000000, 0xFFF00000, 0xFFFC0000]

# Minimum number of prologue-pattern matches to fire the arch fingerprint
ARCH_PROLOGUE_MIN = 5

# Words that repeat more than this in the image are treated as opcodes/templates,
# not pointers, and dropped from the pointer set. Prevents dense ARM instruction
# encodings (E2xxxxxx, E3xxxxxx, E4xxxxxx) from producing false base peaks.
MAX_POINTER_FREQUENCY = 32

# ============================================================================

import argparse
import array
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Image
# ---------------------------------------------------------------------------

class Image:
    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian
        self.size = len(data)
        self._words = None

    def words(self) -> array.array:
        if self._words is not None:
            return self._words
        n = self.size // 4
        arr = array.array('I')
        arr.frombytes(bytes(self.data[:n * 4]))
        if (self.endian == 'be') != (sys.byteorder == 'big'):
            arr.byteswap()
        self._words = arr
        return arr


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def find_string_offsets(data: bytes, min_len: int) -> set:
    """Offsets of NUL-terminated printable ASCII runs of length >= min_len."""
    offsets = set()
    pattern = re.compile(rb'[\x20-\x7e]{%d,}\x00' % min_len)
    for m in pattern.finditer(data):
        offsets.add(m.start())
    return offsets


def _is_padding_word(w: int) -> bool:
    if w == 0 or w == 0xFFFFFFFF:
        return True
    b = w & 0xFF
    if w == (b | (b << 8) | (b << 16) | (b << 24)):
        return True
    return False


def extract_pointer_counter(image: Image) -> Counter:
    """Counter of aligned 32-bit words with padding/fill/opcode-like words filtered.

    Also drops any word whose frequency exceeds MAX_POINTER_FREQUENCY - such words
    are almost always instruction encodings (e.g. ARM E2/E3/E4-prefixed opcodes)
    rather than pointers."""
    c = Counter(image.words())
    c.pop(0, None)
    c.pop(0xFFFFFFFF, None)
    for w in list(c.keys()):
        b = w & 0xFF
        if w == (b | (b << 8) | (b << 16) | (b << 24)):
            del c[w]
        elif c[w] > MAX_POINTER_FREQUENCY:
            del c[w]
    return c


# ---------------------------------------------------------------------------
# Generic strategies
# ---------------------------------------------------------------------------

def score_strings(ptr_counter: Counter, string_offsets: set,
                  min_base: int, max_base: int, align: int,
                  image_size: int) -> dict:
    """For each pointer W and string offset O, credit candidate B = W - O.
    Bucket pointers by W & (align-1) so per-O we only visit pointers whose
    residue matches O (guaranteeing (W - O) is aligned)."""
    if not string_offsets:
        return {}
    align_mask = align - 1
    upper = max_base + image_size
    buckets = defaultdict(list)  # residue -> list of (w, count)
    for w, c in ptr_counter.items():
        if min_base <= w <= upper:
            buckets[w & align_mask].append((w, c))
    if not buckets:
        return {}
    scores = defaultdict(float)
    for o in string_offsets:
        bucket = buckets.get(o & align_mask)
        if not bucket:
            continue
        lo_w = min_base + o
        hi_w = max_base + o
        for w, c in bucket:
            if lo_w <= w <= hi_w:
                scores[w - o] += c
    return scores


def score_selfref(ptr_counter: Counter, image_size: int,
                  min_base: int, max_base: int, align: int) -> dict:
    """Count pointer words W with (W - B) in [0, image_size) per candidate B.
    Implemented as a diff array over aligned candidates."""
    if max_base < min_base:
        return {}
    n_cands = (max_base - min_base) // align + 1
    diff = array.array('q', [0]) * (n_cands + 1)
    for w, count in ptr_counter.items():
        lo = w - image_size + 1
        hi = w
        if hi < min_base or lo > max_base:
            continue
        lo_a = min_base if lo <= min_base else ((lo + align - 1) // align) * align
        hi_a = max_base if hi >= max_base else (hi // align) * align
        if hi_a < lo_a:
            continue
        i0 = (lo_a - min_base) // align
        i1 = (hi_a - min_base) // align + 1
        diff[i0] += count
        diff[i1] -= count
    scores = {}
    acc = 0
    for i in range(n_cands):
        acc += diff[i]
        if acc:
            scores[min_base + i * align] = float(acc)
    return scores


# ---------------------------------------------------------------------------
# Architecture-specific strategies
# ---------------------------------------------------------------------------

def score_arm(image: Image, min_base: int, max_base: int, align: int) -> dict:
    """ARM: detect Cortex-M vector table at offset 0.
    - word[0] plausible RAM address (initial SP)
    - word[1] reset handler with Thumb LSB set
    - word[2..15] mostly Thumb-flagged, cluster within a small span
    Propose the base implied by the handler cluster."""
    words = image.words()
    if len(words) < 16:
        return {}
    sp = words[0]
    reset = words[1]
    if not (CORTEXM_SP_MIN <= sp <= CORTEXM_SP_MAX):
        return {}
    if not (reset & 1):
        return {}
    thumb_count = sum(1 for i in range(2, 16)
                      if (words[i] & 1) and words[i] not in (0, 0xFFFFFFFF))
    if thumb_count < 3:
        return {}
    handlers = [words[i] & ~1 for i in range(1, 16)
                if (words[i] & 1) and words[i] not in (0, 0xFFFFFFFF)]
    if not handlers:
        return {}
    lo = min(handlers)
    hi = max(handlers)
    align_mask = align - 1
    base = lo & ~align_mask
    if not (min_base <= base <= max_base):
        return {}
    if (hi - base) >= image.size:
        return {}
    return {base: 1.0}


def _count_pattern(words: array.array, mask: int, value: int) -> int:
    return sum(1 for w in words if (w & mask) == value)


def score_mips32(image: Image, min_base: int, max_base: int, align: int) -> dict:
    """MIPS32: fire on density of `addiu $sp, $sp, -N` prologues (0x27BD_FFxx).
    When fired, credit common MIPS reset / kseg bases."""
    words = image.words()
    matches = sum(1 for w in words
                  if (w & 0xFFFF0000) == 0x27BD0000 and (w & 0xFFFF) >= 0xFF00)
    if matches < ARCH_PROLOGUE_MIN:
        return {}
    scores = {}
    align_mask = align - 1
    for b in MIPS_COMMON_BASES:
        if min_base <= b <= max_base and (b & align_mask) == 0:
            scores[b] = 1.0
    return scores


def score_ppc32(image: Image, min_base: int, max_base: int, align: int) -> dict:
    """PPC32: fire on density of `stwu r1, -N(r1)` prologues (0x9421_FFxx / negative disp).
    When fired, credit common PPC reset / vector bases."""
    words = image.words()
    matches = sum(1 for w in words
                  if (w & 0xFFFF0000) == 0x94210000 and (w & 0x8000))
    if matches < ARCH_PROLOGUE_MIN:
        return {}
    scores = {}
    align_mask = align - 1
    for b in PPC_COMMON_BASES:
        if min_base <= b <= max_base and (b & align_mask) == 0:
            scores[b] = 1.0
    return scores


ARCH_SCORERS = {
    "arm":    score_arm,
    "mips32": score_mips32,
    "ppc32":  score_ppc32,
}


# ---------------------------------------------------------------------------
# Scoring / ranking
# ---------------------------------------------------------------------------

def normalize(scores: dict) -> dict:
    if not scores:
        return {}
    mx = max(scores.values())
    if mx <= 0:
        return {b: 0.0 for b in scores}
    return {b: v / mx for b, v in scores.items()}


def combine(strings_n: dict, selfref_n: dict, arch_n: dict) -> dict:
    total = defaultdict(float)
    for b, v in strings_n.items():
        total[b] += W_STRINGS * v
    for b, v in selfref_n.items():
        total[b] += W_SELFREF * v
    for b, v in arch_n.items():
        total[b] += W_ARCH * v
    return total


def rank(total: dict, top_n: int):
    return sorted(total.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(image_path, image_size, arch, endian,
                 min_base, max_base, align, ranked, raw_strings):
    print("anchor - firmware base address finder")
    print("image  : %s (%d bytes)" % (image_path, image_size))
    print("arch   : %s / %s" % (arch, endian))
    print("range  : 0x%08x - 0x%08x  align 0x%x" % (min_base, max_base, align))
    print()
    if not ranked:
        print("no candidates found.")
        print("consider widening --min / --max, lowering --align, or verifying arch/endian.")
        return
    print("top candidates:")
    for i, (base, _score) in enumerate(ranked, 1):
        hits = int(raw_strings.get(base, 0))
        print("  %d. 0x%08x   ptr hit count: %d" % (i, base, hits))


# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

def analyze(image: Image, arch: str, min_base: int, max_base: int, align: int):
    ptr_counter = extract_pointer_counter(image)
    string_offsets = find_string_offsets(image.data, MIN_STRING_LEN)

    raw_strings = score_strings(ptr_counter, string_offsets,
                                min_base, max_base, align, image.size)
    raw_selfref = score_selfref(ptr_counter, image.size,
                                min_base, max_base, align)
    raw_arch = ARCH_SCORERS[arch](image, min_base, max_base, align)

    n_strings = normalize(raw_strings)
    n_selfref = normalize(raw_selfref)
    n_arch    = normalize(raw_arch)

    total = combine(n_strings, n_selfref, n_arch)
    return total, raw_strings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_int(s: str) -> int:
    return int(s, 0)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="anchor",
        description="firmware base address finder for raw embedded images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("image", help="raw firmware image")
    ap.add_argument("--arch", choices=sorted(ARCH_RANGES.keys()),
                    required=True, help="target architecture")
    ap.add_argument("--endian", choices=["le", "be"],
                    required=True, help="target endianness")
    ap.add_argument("--min", dest="min_base", type=parse_int,
                    help="minimum candidate base (default: per-arch)")
    ap.add_argument("--max", dest="max_base", type=parse_int,
                    help="maximum candidate base (default: per-arch)")
    ap.add_argument("--align", type=parse_int, default=DEFAULT_ALIGN,
                    help="candidate alignment (default: 0x%x)" % DEFAULT_ALIGN)
    ap.add_argument("--offset", type=parse_int, default=0,
                    help="start offset within image (default: 0)")
    ap.add_argument("--size", type=parse_int, default=0,
                    help="size of region to analyze (default: to end)")
    ap.add_argument("--top", type=int, default=DEFAULT_TOP_N,
                    help="number of candidates to print (default: %d)" % DEFAULT_TOP_N)

    args = ap.parse_args(argv)

    path = Path(args.image)
    if not path.exists():
        print("error: %s: no such file" % path)
        return 1
    data = path.read_bytes()
    if args.size:
        data = data[args.offset:args.offset + args.size]
    elif args.offset:
        data = data[args.offset:]
    if len(data) < 16:
        print("error: image too small (%d bytes) to analyze" % len(data))
        return 1

    lo_default, hi_default = ARCH_RANGES[args.arch]
    min_base = args.min_base if args.min_base is not None else lo_default
    max_base = args.max_base if args.max_base is not None else hi_default
    if min_base > max_base:
        print("error: --min > --max")
        return 2
    if args.align <= 0 or (args.align & (args.align - 1)):
        print("error: --align must be a positive power of two")
        return 2
    align_mask = args.align - 1
    if min_base & align_mask:
        min_base = (min_base + align_mask) & ~align_mask
    if max_base & align_mask:
        max_base = max_base & ~align_mask

    img = Image(data, args.endian)
    total_scores, raw_strings = analyze(
        img, args.arch, min_base, max_base, args.align)
    ranked = rank(total_scores, args.top)

    print_report(str(path), len(data), args.arch, args.endian,
                 min_base, max_base, args.align, ranked, raw_strings)

    return 0 if ranked else 1


if __name__ == "__main__":
    sys.exit(main())
