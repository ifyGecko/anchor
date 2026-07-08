#!/usr/bin/env python3
"""anchor - firmware base address finder for raw embedded firmware images.

Usage:
    anchor.py <image> --arch {arm,mips32,ppc32} --endian {le,be} [options]
    anchor.py --self-test

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

# Self-test cases. Extend or edit freely.
SELF_TEST_CASES = [
    {"arch": "arm",    "endian": "le", "base": 0x08000000, "flavor": "cortexm"},
    {"arch": "arm",    "endian": "le", "base": 0x10000000, "flavor": "cortexm"},
    {"arch": "arm",    "endian": "le", "base": 0x20000000, "flavor": "cortexm"},
    {"arch": "mips32", "endian": "be", "base": 0xBFC00000, "flavor": "generic"},
    {"arch": "mips32", "endian": "le", "base": 0x80010000, "flavor": "generic"},
    {"arch": "ppc32",  "endian": "be", "base": 0x00100000, "flavor": "generic"},
]

# ============================================================================

import argparse
import array
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
                 min_base, max_base, align,
                 ranked, per_strategy, explain):
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
    for i, (base, score) in enumerate(ranked, 1):
        print("  %d. 0x%08x   score=%7.3f" % (i, base, score))
        if explain:
            s = per_strategy["strings"].get(base, 0.0)
            r = per_strategy["selfref"].get(base, 0.0)
            a = per_strategy["arch"].get(base, 0.0)
            print("       strings=%.3f  selfref=%.3f  arch=%.3f" % (s, r, a))


# ---------------------------------------------------------------------------
# Analysis entry point (used by main and self-test)
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
    per_strategy = {"strings": n_strings, "selfref": n_selfref, "arch": n_arch}
    return total, per_strategy, {
        "n_strings": len(string_offsets),
        "n_ptrs": sum(ptr_counter.values()),
        "n_unique_ptrs": len(ptr_counter),
    }


# ---------------------------------------------------------------------------
# Self-test: build baremetal blobs and validate
# ---------------------------------------------------------------------------

C_SOURCE_COMMON = r"""
#include <stdint.h>

const char s1[] = "anchor_test_alpha_bravo_charlie";
const char s2[] = "anchor_test_delta_echo_foxtrot_golf";
const char s3[] = "anchor_test_hotel_india_juliet_kilo";
const char s4[] = "anchor_test_lima_mike_november_oscar";
const char s5[] = "anchor_test_papa_quebec_romeo_sierra";
const char s6[] = "anchor_test_tango_uniform_victor";
const char s7[] = "anchor_test_whiskey_xray_yankee_zulu";
const char s8[] = "anchor_test_the_quick_brown_fox_jumps";
const char s9[] = "anchor_test_lorem_ipsum_dolor_sit_amet";
const char s10[] = "anchor_test_consectetur_adipiscing_elit";

const char * const string_table[] = {
    s1, s2, s3, s4, s5, s6, s7, s8, s9, s10
};

int compute_a(int x) { return x * 2 + 1; }
int compute_b(int x) { return compute_a(x) + 3; }
int compute_c(int x) { return compute_b(x) * compute_a(x); }
int compute_d(int x) { return compute_c(x) - compute_b(x); }
int compute_e(int x) { return compute_d(x) + compute_a(x) * 5; }
int compute_f(int x) { return compute_e(x) * 2 - compute_c(x); }
int compute_g(int x) { return compute_f(x) + compute_d(x) - 7; }
int compute_h(int x) { return compute_g(x) ^ compute_e(x); }

typedef int (*fn_t)(int);
const fn_t fn_table[] = {
    compute_a, compute_b, compute_c, compute_d,
    compute_e, compute_f, compute_g, compute_h
};

volatile int sink;

int main_(void) {
    int r = 0;
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 8; j++) {
            r += fn_table[j](i);
        }
        for (int j = 0; j < 10; j++) {
            const char *p = string_table[j];
            r += (int)(uintptr_t)p;
        }
    }
    sink = r;
    return r;
}

int _start(void) {
    return main_();
}
"""

C_SOURCE_ARM_VECTORS = r"""
void nmi_handler(void)  { while (1) { } }
void hf_handler(void)   { while (1) { } }

extern int _start(void);

__attribute__((section(".vectors"), used))
void * const vectors[16] = {
    (void*)0x20008000,
    (void*)_start,
    (void*)nmi_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
};
"""

LINKER_SCRIPT_ARM = r"""
ENTRY(_start)
SECTIONS
{
    . = %#x;
    .text : {
        KEEP(*(.vectors))
        *(.text*)
        *(.rodata*)
        *(.data*)
        . = ALIGN(4);
    }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.ARM.*) *(.debug*) }
}
"""

LINKER_SCRIPT_GENERIC = r"""
ENTRY(_start)
SECTIONS
{
    . = %#x;
    .text : {
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.sdata*)
        . = ALIGN(4);
    }
    /DISCARD/ : {
        *(.comment) *(.note*) *(.eh_frame*) *(.debug*)
        *(.MIPS.*) *(.reginfo) *(.mdebug*) *(.pdr) *(.gnu.attributes)
    }
}
"""

TOOLCHAINS = {
    ("arm",    "le"): ("arm-none-eabi-gcc",    "arm-none-eabi-objcopy",
                       ["-mcpu=cortex-m3", "-mthumb"], []),
    ("arm",    "be"): ("arm-none-eabi-gcc",    "arm-none-eabi-objcopy",
                       ["-mcpu=cortex-m3", "-mthumb", "-mbig-endian"], []),
    ("mips32", "be"): ("mips-linux-gnu-gcc",   "mips-linux-gnu-objcopy",
                       ["-mabi=32", "-EB"], ["-EB"]),
    ("mips32", "le"): ("mipsel-linux-gnu-gcc", "mipsel-linux-gnu-objcopy",
                       ["-mabi=32", "-EL"], ["-EL"]),
    ("ppc32",  "be"): ("powerpc-linux-gnu-gcc","powerpc-linux-gnu-objcopy",
                       ["-m32"], []),
}


def build_test_firmware(arch, endian, base, workdir):
    """Build a raw baremetal firmware blob for (arch, endian) at load address base.
    Returns (path, None) on success, (None, reason) on skip/fail."""
    key = (arch, endian)
    if key not in TOOLCHAINS:
        return None, "no toolchain mapping for %s/%s" % (arch, endian)
    gcc, objcopy, gcc_extra, ld_extra = TOOLCHAINS[key]
    if not shutil.which(gcc):
        return None, "missing %s" % gcc
    if not shutil.which(objcopy):
        return None, "missing %s" % objcopy

    src = workdir / ("firmware_%s_%s_%08x.c" % (arch, endian, base))
    ld = workdir / ("firmware_%s_%s_%08x.ld" % (arch, endian, base))
    elf = workdir / ("firmware_%s_%s_%08x.elf" % (arch, endian, base))
    bin_ = workdir / ("firmware_%s_%s_%08x.bin" % (arch, endian, base))

    source = C_SOURCE_COMMON
    if arch == "arm":
        source = C_SOURCE_ARM_VECTORS + C_SOURCE_COMMON
        ld_text = LINKER_SCRIPT_ARM % base
    else:
        ld_text = LINKER_SCRIPT_GENERIC % base

    src.write_text(source)
    ld.write_text(ld_text)

    cmd = [gcc] + gcc_extra + [
        "-Os", "-nostdlib", "-nostartfiles", "-ffreestanding",
        "-fno-pic", "-fno-pie", "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
        "-static",
        "-Wl,--build-id=none", "-Wl,-no-pie",
        "-T", str(ld),
        str(src),
        "-o", str(elf),
    ]
    # MIPS: avoid PIC/abicalls that break absolute addressing
    if arch == "mips32":
        cmd.insert(1, "-mno-abicalls")
        cmd.insert(1, "-mno-shared")
    # PPC uses libgcc helpers (_restgpr_*, _savegpr_*) for prologue/epilogue.
    # Since we -nostdlib, link libgcc.a back in.
    if arch == "ppc32":
        r_lg = subprocess.run([gcc, "-print-libgcc-file-name"],
                              capture_output=True)
        if r_lg.returncode == 0:
            libgcc = r_lg.stdout.decode().strip()
            if libgcc:
                cmd.append(libgcc)
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        return None, "compile failed: %s" % r.stderr.decode("utf-8", "replace").strip()

    r = subprocess.run([objcopy, "-O", "binary", str(elf), str(bin_)],
                       capture_output=True)
    if r.returncode != 0:
        return None, "objcopy failed: %s" % r.stderr.decode("utf-8", "replace").strip()

    if not bin_.exists() or bin_.stat().st_size < 64:
        return None, "output binary too small (%d bytes)" % (bin_.stat().st_size if bin_.exists() else 0)

    return bin_, None


def run_self_test():
    print("anchor self-test")
    print("-" * 60)
    total = len(SELF_TEST_CASES)
    passes = fails = skips = 0
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        for i, case in enumerate(SELF_TEST_CASES, 1):
            arch = case["arch"]
            endian = case["endian"]
            expected = case["base"]
            print("[%d/%d] %s/%s  base=0x%08x  %s" %
                  (i, total, arch, endian, expected, case["flavor"]))
            path, reason = build_test_firmware(arch, endian, expected, wd)
            if path is None:
                print("        SKIP: %s" % reason)
                skips += 1
                print()
                continue
            data = path.read_bytes()
            print("        built %s (%d bytes)" % (path.name, len(data)))
            img = Image(data, endian)
            lo, hi = ARCH_RANGES[arch]
            total_scores, per_strategy, stats = analyze(img, arch, lo, hi, DEFAULT_ALIGN)
            ranked = rank(total_scores, DEFAULT_TOP_N)
            top_bases = [b for b, _ in ranked]
            listed = "  ".join("0x%08x" % b for b in top_bases) if top_bases else "(none)"
            print("        top-%d: %s" % (DEFAULT_TOP_N, listed))
            if expected in top_bases:
                rank_pos = top_bases.index(expected) + 1
                print("        PASS: correct base at rank #%d" % rank_pos)
                passes += 1
            else:
                print("        FAIL: correct base 0x%08x not in top-%d" %
                      (expected, DEFAULT_TOP_N))
                fails += 1
            print()
    print("-" * 60)
    print("summary: %d pass, %d fail, %d skip (of %d)" %
          (passes, fails, skips, total))
    return 0 if fails == 0 else 1


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
    ap.add_argument("image", nargs="?", help="raw firmware image")
    ap.add_argument("--arch", choices=sorted(ARCH_RANGES.keys()),
                    help="target architecture (required unless --self-test)")
    ap.add_argument("--endian", choices=["le", "be"],
                    help="target endianness (required unless --self-test)")
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
    ap.add_argument("--explain", action="store_true",
                    help="show per-strategy contribution for each candidate")
    ap.add_argument("--self-test", action="store_true",
                    help="build baremetal test firmware images and validate anchor")

    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.image:
        print("error: image path required (or use --self-test)")
        return 2
    if not args.arch:
        print("error: --arch is required")
        return 2
    if not args.endian:
        print("error: --endian is required")
        return 2

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
    total_scores, per_strategy, stats = analyze(
        img, args.arch, min_base, max_base, args.align)
    ranked = rank(total_scores, args.top)

    print_report(str(path), len(data), args.arch, args.endian,
                 min_base, max_base, args.align,
                 ranked, per_strategy, args.explain)

    return 0 if ranked else 1


if __name__ == "__main__":
    sys.exit(main())
