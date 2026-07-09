# ghidra_anchor_jython - firmware base load address finder for raw baremetal
# images. Jython 2.7 sibling of ghidra_anchor.py; functionally equivalent.
#
# Ghidra headless post-analysis script. Takes NO arguments.
# All required inputs (arch, endian, image bytes, decoded instructions, defined
# data, strings) are pulled from currentProgram.
#
# Strategies (mirror anchor.py) with Ghidra-based refinements:
#     strings  - correlate pointer values with string offsets. Strings prefer
#                Ghidra-defined string data; falls back to a printable-ASCII
#                regex scan for coverage.
#     selfref  - density of pointer words that land inside the image, using a
#                weighted pointer set that (a) EXCLUDES any word slot Ghidra
#                proved to be a decoded instruction and (b) BOOSTS any word
#                slot Ghidra pre-typed as a pointer/address data element.
#     arch     - architecture-specific fingerprint:
#                  arm    -> Cortex-M vector-table check on words[0..15]
#                  mips32 -> `addiu $sp, $sp, -N` prologue density (Ghidra
#                            listing preferred, raw-word fallback)
#                  ppc32  -> `stwu r1, -N(r1)` prologue density (same fallback)
#
# The refinement that matters most in practice is the instruction filter:
# anchor.py has no way to tell an ARM E2/E3/E4 opcode template apart from a
# real pointer and relies on a coarse "words that repeat > 32x are opcodes"
# heuristic. Ghidra tells us definitively which byte ranges are decoded
# instructions, so we drop those word slots from the pointer candidate set.
#
# NOTE: We deliberately DO NOT treat undecoded data as instructions. If Ghidra
# missed a function (very common on ARM where the disassembler is conservative)
# those words remain in the pointer pool - the reverse engineer is expected to
# clean up missed functions and re-run for a better result.
#
# FUTURE WORK: an optional pre-pass could (a) invoke a "find missed functions"
# routine before scoring or (b) apply a heuristic where a run of N words that
# disassembles cleanly (no invalid instructions, no impossible register writes)
# is treated as code even if Ghidra did not create the instructions. Arbitrary
# data will not disassemble into N valid instructions in a row - real
# instruction encoding rules are rigid enough that random bytes fail quickly.
# Not implemented in this version.
#
# By default, the script rebases the program to the top-ranked base. Toggle
# REBASE_ON_TOP_PICK below to disable.
#
#@author   anchor
#@category Analysis.Firmware
#@runtime  Jython

from __future__ import print_function

# ============================================================================
# Tunable constants (match anchor.py where possible)
# ============================================================================

DEFAULT_ALIGN = 0x1000
DEFAULT_TOP_N = 5

MIN_STRING_LEN = 8

W_STRINGS = 1.0
W_SELFREF = 1.0
W_ARCH    = 2.0

ARCH_RANGES = {
    "arm":    (0x00000000, 0xFFFF0000),
    "mips32": (0x80000000, 0xBFC00000),
    "ppc32":  (0x00000000, 0xFFF00000),
}

CORTEXM_SP_MIN = 0x10000000
CORTEXM_SP_MAX = 0x40000000

MIPS_COMMON_BASES = [0xBFC00000, 0x9FC00000, 0x80000000, 0x80100000, 0x80010000]
PPC_COMMON_BASES  = [0x00000000, 0x00100000, 0x01000000, 0xFFF00000, 0xFFFC0000]

ARCH_PROLOGUE_MIN     = 5
MAX_POINTER_FREQUENCY = 32

# Extra weight applied to word slots Ghidra explicitly typed as pointer/address.
PTR_DATA_BOOST = 2

# Auto-rebase the program to the top candidate at the end of analysis.
# Set to False to only print candidates and leave the image base unchanged.
REBASE_ON_TOP_PICK = True

# ============================================================================

import re
from array import array
from collections import defaultdict

from jarray import zeros as _jzeros

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data    import Pointer


# ---------------------------------------------------------------------------
# Ghidra glue
# ---------------------------------------------------------------------------

def detect_arch_and_endian():
    """Return (arch_key, endian_key) or (None, None) if unsupported."""
    lang = currentProgram.getLanguage()
    proc = lang.getProcessor().toString().lower()
    endian = "be" if lang.isBigEndian() else "le"
    ptr_bits = lang.getLanguageDescription().getSize()
    if ptr_bits != 32:
        return None, None
    if "arm" in proc:
        return "arm", endian
    if "mips" in proc:
        return "mips32", endian
    if "powerpc" in proc or proc == "ppc":
        return "ppc32", endian
    return None, None


def largest_initialized_block():
    """Pick the largest initialized memory block. For raw firmware this is the
    single loaded blob; if the user has added MMIO / SRAM regions after loading,
    we still target the flat image blob."""
    best = None
    for blk in currentProgram.getMemory().getBlocks():
        if not blk.isInitialized():
            continue
        if best is None or blk.getSize() > best.getSize():
            best = blk
    return best


def read_block_bytes(block):
    """Return the block's contents as a Python str (Jython 2.7 bytes)."""
    size = int(block.getSize())
    ba = _jzeros(size, 'b')
    block.getBytes(block.getStart(), ba)
    out = bytearray(size)
    for i in xrange(size):
        v = ba[i]
        if v < 0:
            v += 256
        out[i] = v
    return str(out)


def words_from_bytes(data, endian):
    n = len(data) // 4
    if n == 0:
        return []
    import struct
    fmt = ('>' if endian == 'be' else '<') + ('I' * n)
    return list(struct.unpack(fmt, data[:n * 4]))


def _block_address_set(block):
    return AddressSet(block.getStart(), block.getEnd())


def instruction_word_slots(block):
    """Set of word slots (block-relative offset // 4) that hold ANY byte of a
    decoded instruction. These are proven-not-pointers."""
    listing = currentProgram.getListing()
    start = block.getStart()
    slots = set()
    it = listing.getInstructions(_block_address_set(block), True)
    for insn in it:
        s = int(insn.getMinAddress().subtract(start))
        e = int(insn.getMaxAddress().subtract(start))
        w0 = s // 4
        w1 = e // 4
        for w in xrange(w0, w1 + 1):
            slots.add(w)
    return slots


def pointer_typed_word_slots(block):
    """Set of 4-byte-aligned word slots Ghidra typed as Pointer."""
    listing = currentProgram.getListing()
    start = block.getStart()
    slots = set()
    it = listing.getDefinedData(_block_address_set(block), True)
    for data in it:
        dt = data.getDataType()
        if isinstance(dt, Pointer):
            off = int(data.getAddress().subtract(start))
            if off % 4 == 0 and data.getLength() == 4:
                slots.add(off // 4)
    return slots


def ghidra_string_offsets(block):
    """Block-relative offsets of strings Ghidra's analysis has defined."""
    listing = currentProgram.getListing()
    start = block.getStart()
    offsets = set()
    it = listing.getDefinedData(_block_address_set(block), True)
    for data in it:
        try:
            if data.hasStringValue() and data.getLength() >= MIN_STRING_LEN:
                off = int(data.getAddress().subtract(start))
                offsets.add(off)
        except Exception:
            pass
    return offsets


def regex_string_offsets(data_bytes, min_len):
    """Fallback: printable-ASCII NUL-terminated runs, same rule as anchor.py.
    data_bytes is a Python 2 str (== bytes) so a plain str-mode pattern
    matches correctly."""
    pattern = re.compile(r'[\x20-\x7e]{%d,}\x00' % min_len)
    return set(m.start() for m in pattern.finditer(data_bytes))


# ---------------------------------------------------------------------------
# Pointer extraction
# ---------------------------------------------------------------------------

def extract_pointer_counts(words, insn_slots, boost_slots):
    """Weighted {word_value: count} dict.

    - Words at slots Ghidra proved to be instructions are dropped entirely.
    - Zero, all-ones, and byte-fill patterns are dropped (padding).
    - Words at slots Ghidra pre-typed as Pointer contribute PTR_DATA_BOOST
      per occurrence instead of 1.
    - After tallying, values whose (non-boosted) count exceeds
      MAX_POINTER_FREQUENCY are treated as opcode templates and dropped.
      Values that were boosted at least once are exempt: if Ghidra called them
      a pointer we trust that vote.
    """
    counts = {}
    boosted_values = set()
    i = 0
    for w in words:
        if i in insn_slots:
            i += 1
            continue
        if w == 0 or w == 0xFFFFFFFF:
            i += 1
            continue
        b = w & 0xFF
        if w == (b | (b << 8) | (b << 16) | (b << 24)):
            i += 1
            continue
        if i in boost_slots:
            counts[w] = counts.get(w, 0) + PTR_DATA_BOOST
            boosted_values.add(w)
        else:
            counts[w] = counts.get(w, 0) + 1
        i += 1
    for w in list(counts.keys()):
        if w in boosted_values:
            continue
        if counts[w] > MAX_POINTER_FREQUENCY:
            del counts[w]
    return counts


# ---------------------------------------------------------------------------
# Generic strategies (algorithmically identical to anchor.py)
# ---------------------------------------------------------------------------

def score_strings(ptr_counts, string_offsets, min_base, max_base, align,
                  image_size):
    if not string_offsets:
        return {}
    align_mask = align - 1
    upper = max_base + image_size
    buckets = defaultdict(list)
    for w, cnt in ptr_counts.items():
        if min_base <= w <= upper:
            buckets[w & align_mask].append((w, cnt))
    if not buckets:
        return {}
    scores = defaultdict(float)
    for o in string_offsets:
        bucket = buckets.get(o & align_mask)
        if not bucket:
            continue
        lo_w = min_base + o
        hi_w = max_base + o
        for w, cnt in bucket:
            if lo_w <= w <= hi_w:
                scores[w - o] += cnt
    out = {}
    for k, v in scores.items():
        out[k] = v
    return out


def score_selfref(ptr_counts, image_size, min_base, max_base, align):
    if max_base < min_base:
        return {}
    n_cands = (max_base - min_base) // align + 1
    diff = array('l', [0]) * (n_cands + 1)
    for w, cnt in ptr_counts.items():
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
        diff[i0] += cnt
        diff[i1] -= cnt
    scores = {}
    acc = 0
    for i in xrange(n_cands):
        acc += diff[i]
        if acc:
            scores[min_base + i * align] = float(acc)
    return scores


# ---------------------------------------------------------------------------
# Architecture-specific strategies
# ---------------------------------------------------------------------------

def score_arm(words, image_size, min_base, max_base, align):
    """Cortex-M vector-table fingerprint at offset 0."""
    if len(words) < 16:
        return {}
    sp = words[0]
    reset = words[1]
    if not (CORTEXM_SP_MIN <= sp <= CORTEXM_SP_MAX):
        return {}
    if not (reset & 1):
        return {}
    thumb_count = 0
    for i in xrange(2, 16):
        w = words[i]
        if (w & 1) and w not in (0, 0xFFFFFFFF):
            thumb_count += 1
    if thumb_count < 3:
        return {}
    handlers = []
    for i in xrange(1, 16):
        w = words[i]
        if (w & 1) and w not in (0, 0xFFFFFFFF):
            handlers.append(w & ~1)
    if not handlers:
        return {}
    lo = min(handlers)
    hi = max(handlers)
    align_mask = align - 1
    base = lo & ~align_mask
    if not (min_base <= base <= max_base):
        return {}
    if (hi - base) >= image_size:
        return {}
    return {base: 1.0}


def _count_decoded_prologues(block, mnemonic, predicate):
    """Count decoded instructions whose mnemonic matches and where `predicate`
    accepts the Instruction. Predicate exceptions count as 'no match'."""
    listing = currentProgram.getListing()
    it = listing.getInstructions(_block_address_set(block), True)
    n = 0
    for insn in it:
        if insn.getMnemonicString().lower() != mnemonic:
            continue
        try:
            if predicate(insn):
                n += 1
        except Exception:
            pass
    return n


def _mips_addiu_sp_neg(insn):
    """Match `addiu $sp, $sp, -N` for small negative N (function prologue)."""
    r0 = insn.getRegister(0)
    r1 = insn.getRegister(1)
    if r0 is None or r1 is None:
        return False
    n0 = r0.getName().lower()
    n1 = r1.getName().lower()
    if n0 not in ("sp", "$sp", "r29") or n1 not in ("sp", "$sp", "r29"):
        return False
    for i in xrange(insn.getNumOperands()):
        s = insn.getScalar(i)
        if s is not None:
            v = s.getSignedValue()
            return -0x100 <= v < 0
    return False


def _ppc_stwu_r1_neg(insn):
    """Match `stwu r1, -N(r1)` (PPC function prologue)."""
    r0 = insn.getRegister(0)
    if r0 is None or r0.getName().lower() not in ("r1", "sp"):
        return False
    for i in xrange(insn.getNumOperands()):
        s = insn.getScalar(i)
        if s is not None:
            v = s.getSignedValue()
            if v < 0 and v >= -0x10000:
                return True
    return False


def score_mips32(block, words, image_size, min_base, max_base, align):
    """MIPS32: count `addiu $sp, $sp, -N` prologues. Use Ghidra's decoded
    instructions when available; fall back to the raw-word scan from
    anchor.py when Ghidra disassembled almost nothing."""
    decoded = _count_decoded_prologues(block, "addiu", _mips_addiu_sp_neg)
    if decoded < ARCH_PROLOGUE_MIN:
        raw = 0
        for w in words:
            if (w & 0xFFFF0000) == 0x27BD0000 and (w & 0xFFFF) >= 0xFF00:
                raw += 1
        matches = max(decoded, raw)
    else:
        matches = decoded
    if matches < ARCH_PROLOGUE_MIN:
        return {}
    scores = {}
    align_mask = align - 1
    for b in MIPS_COMMON_BASES:
        if min_base <= b <= max_base and (b & align_mask) == 0:
            scores[b] = 1.0
    return scores


def score_ppc32(block, words, image_size, min_base, max_base, align):
    """PPC32: count `stwu r1, -N(r1)` prologues. Same fallback pattern as MIPS."""
    decoded = _count_decoded_prologues(block, "stwu", _ppc_stwu_r1_neg)
    if decoded < ARCH_PROLOGUE_MIN:
        raw = 0
        for w in words:
            if (w & 0xFFFF0000) == 0x94210000 and (w & 0x8000):
                raw += 1
        matches = max(decoded, raw)
    else:
        matches = decoded
    if matches < ARCH_PROLOGUE_MIN:
        return {}
    scores = {}
    align_mask = align - 1
    for b in PPC_COMMON_BASES:
        if min_base <= b <= max_base and (b & align_mask) == 0:
            scores[b] = 1.0
    return scores


# ---------------------------------------------------------------------------
# Scoring / ranking
# ---------------------------------------------------------------------------

def normalize(scores):
    if not scores:
        return {}
    mx = max(scores.values())
    if mx <= 0:
        out = {}
        for b in scores:
            out[b] = 0.0
        return out
    out = {}
    for b, v in scores.items():
        out[b] = v / mx
    return out


def combine(strings_n, selfref_n, arch_n):
    total = defaultdict(float)
    for b, v in strings_n.items():
        total[b] += W_STRINGS * v
    for b, v in selfref_n.items():
        total[b] += W_SELFREF * v
    for b, v in arch_n.items():
        total[b] += W_ARCH * v
    return total


def rank(total, top_n):
    items = list(total.items())
    items.sort(key=lambda kv: (-kv[1], kv[0]))
    return items[:top_n]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(image_name, image_size, arch, endian, min_base, max_base,
                 align, ranked, raw_strings,
                 insn_slot_count, ptr_slot_count, string_count):
    print("anchor - firmware base address finder")
    print("image  : %s (%d bytes)" % (image_name, image_size))
    print("arch   : %s / %s" % (arch, endian))
    print("range  : 0x%08x - 0x%08x  align 0x%x" % (min_base, max_base, align))
    print("")
    if not ranked:
        print("no candidates found.")
        print("consider adjusting ARCH_RANGES or verifying arch/endian.")
        return
    print("top candidates:")
    i = 1
    for entry in ranked:
        base, _score = entry
        hits = int(raw_strings.get(base, 0))
        print("  %d. 0x%08x   ptr hit count: %d" % (i, base, hits))
        i += 1
    print("")
    print("[ghidra] excluded %d instruction word slots, boosted %d pre-typed "
          "pointer slots, used %d string offsets"
          % (insn_slot_count, ptr_slot_count, string_count))


# ---------------------------------------------------------------------------
# Rebase
# ---------------------------------------------------------------------------

def rebase_image(new_base_value):
    """Rebase currentProgram to the given 32-bit base value. Returns True on
    success, prints failure detail otherwise."""
    factory = currentProgram.getAddressFactory()
    space = factory.getDefaultAddressSpace()
    try:
        new_base = space.getAddress(new_base_value)
    except Exception, ex:
        print("[ghidra] rebase skipped: cannot form address 0x%08x (%s)"
              % (new_base_value, ex))
        return False
    tx = currentProgram.startTransaction("anchor: rebase image to 0x%08x"
                                          % new_base_value)
    ok = False
    try:
        try:
            currentProgram.setImageBase(new_base, True)
            ok = True
        except Exception, ex:
            print("[ghidra] rebase failed: %s" % ex)
    finally:
        currentProgram.endTransaction(tx, ok)
    return ok


# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

def analyze():
    arch, endian = detect_arch_and_endian()
    if arch is None:
        lang_id = currentProgram.getLanguage().getLanguageID().getIdAsString()
        print("ghidra_anchor: unsupported language %s" % lang_id)
        print("ghidra_anchor: only 32-bit arm / mips / powerpc are supported.")
        return

    block = largest_initialized_block()
    if block is None:
        print("ghidra_anchor: no initialized memory blocks in program.")
        return
    if int(block.getSize()) < 16:
        print("ghidra_anchor: image too small (%d bytes)."
              % int(block.getSize()))
        return

    data = read_block_bytes(block)
    words = words_from_bytes(data, endian)

    insn_slots  = instruction_word_slots(block)
    boost_slots = pointer_typed_word_slots(block)

    ptr_counts = extract_pointer_counts(words, insn_slots, boost_slots)

    string_offsets = ghidra_string_offsets(block)
    if len(string_offsets) < 4:
        string_offsets = string_offsets.union(
            regex_string_offsets(data, MIN_STRING_LEN))

    min_base, max_base = ARCH_RANGES[arch]
    align = DEFAULT_ALIGN

    raw_strings = score_strings(ptr_counts, string_offsets,
                                min_base, max_base, align, len(data))
    raw_selfref = score_selfref(ptr_counts, len(data),
                                min_base, max_base, align)
    if arch == "arm":
        raw_arch = score_arm(words, len(data), min_base, max_base, align)
    elif arch == "mips32":
        raw_arch = score_mips32(block, words, len(data),
                                min_base, max_base, align)
    else:  # ppc32
        raw_arch = score_ppc32(block, words, len(data),
                               min_base, max_base, align)

    total = combine(normalize(raw_strings),
                    normalize(raw_selfref),
                    normalize(raw_arch))
    ranked = rank(total, DEFAULT_TOP_N)

    print_report(currentProgram.getName(), len(data), arch, endian,
                 min_base, max_base, align, ranked, raw_strings,
                 len(insn_slots), len(boost_slots), len(string_offsets))

    if not ranked or not REBASE_ON_TOP_PICK:
        return
    top_base = ranked[0][0]
    current_base = currentProgram.getImageBase().getOffset() & 0xFFFFFFFF
    if current_base == top_base:
        print("[ghidra] image base already at 0x%08x, no rebase needed"
              % top_base)
        return
    if rebase_image(top_base):
        print("[ghidra] rebased image to 0x%08x" % top_base)


analyze()
