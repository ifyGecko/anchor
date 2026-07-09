#!/usr/bin/env bash
# ghidra_anchor self-test
#
# Builds every test firmware image declared in tests/Makefile, then imports each
# one into a scratch Ghidra project via analyzeHeadless, runs ghidra_anchor.py
# as the post-script, and confirms the known base address appears in the top-N
# candidate list printed to the Ghidra console.
#
# Usage:
#   ghidra-self-test.sh <ghidra_install_dir>
#
# <ghidra_install_dir> is the top-level Ghidra folder that contains
# support/analyzeHeadless.

set -u
set -o pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <ghidra_install_dir>"
    exit 2
fi

GHIDRA_DIR="$1"

# ghidra_anchor.py is a PyGhidra script; use pyghidraRun in headless mode.
# Fall back to analyzeHeadless only if pyghidraRun is missing (older Ghidra).
if [ -x "$GHIDRA_DIR/support/pyghidraRun" ]; then
    ANALYZE=("$GHIDRA_DIR/support/pyghidraRun" "-H")
elif [ -x "$GHIDRA_DIR/support/analyzeHeadless" ]; then
    ANALYZE=("$GHIDRA_DIR/support/analyzeHeadless")
    echo "warning: pyghidraRun not found; falling back to analyzeHeadless"
    echo "         (script requires PyGhidra runtime; test will likely fail)"
else
    echo "error: neither pyghidraRun nor analyzeHeadless found under $GHIDRA_DIR/support/"
    exit 2
fi

# Ensure the pyghidra Python package is importable; without it PyGhidra will
# either prompt interactively or fail. The launcher expects it in the
# currently-active python3.
if ! python3 -c "import pyghidra" 2>/dev/null; then
    echo "error: pyghidra Python package is not installed for python3"
    echo "       install with:  python3 -m pip install --user pyghidra"
    echo "       (Debian may need --break-system-packages)"
    exit 2
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
POST_SCRIPT="$REPO_DIR/ghidra_anchor.py"
BUILD_DIR="$SCRIPT_DIR/build"
TOP_N=5

if [ ! -f "$POST_SCRIPT" ]; then
    echo "error: ghidra_anchor.py not found at $POST_SCRIPT"
    exit 2
fi

echo "ghidra_anchor self-test"
echo "------------------------------------------------------------"
echo "building test firmware images..."
if ! make -s -C "$SCRIPT_DIR" all; then
    echo "make failed"
    exit 1
fi
echo "  build OK"
echo

# Ghidra language IDs per <arch>_<endian> filename prefix.
# The processor value is passed to analyzeHeadless as -processor.
declare -A LANG_ID=(
    ["arm_le"]="ARM:LE:32:Cortex"
    ["arm_be"]="ARM:BE:32:Cortex"
    ["mips32_le"]="MIPS:LE:32:default"
    ["mips32_be"]="MIPS:BE:32:default"
    ["ppc32_be"]="PowerPC:BE:32:default"
    ["ppc32_le"]="PowerPC:LE:32:default"
)

shopt -s nullglob
bins=( "$BUILD_DIR"/*.bin )
if [ "${#bins[@]}" -eq 0 ]; then
    echo "error: no .bin files found in $BUILD_DIR"
    exit 1
fi

pass=0
fail=0
total=${#bins[@]}
idx=0

# analyzeHeadless can spew a lot; keep per-case logs in a temp dir for
# debugging failures.
LOG_DIR=$(mktemp -d)
trap 'rm -rf "$LOG_DIR"' EXIT

for bin in "${bins[@]}"; do
    idx=$((idx + 1))
    name=$(basename "$bin" .bin)

    # Filename convention: <arch>_<endian>_<base_hex>.bin
    if [[ "$name" =~ ^([a-z0-9]+)_([lb]e)_([0-9a-fA-F]+)$ ]]; then
        arch="${BASH_REMATCH[1]}"
        endian="${BASH_REMATCH[2]}"
        base_hex="${BASH_REMATCH[3]}"
    else
        printf "[%d/%d] %-30s SKIP (unrecognized name)\n" "$idx" "$total" "$name"
        continue
    fi

    key="${arch}_${endian}"
    lang="${LANG_ID[$key]:-}"
    if [ -z "$lang" ]; then
        printf "[%d/%d] %-30s SKIP (no lang mapping for %s)\n" \
               "$idx" "$total" "$name" "$key"
        continue
    fi

    expected=$(printf "0x%08x" "0x$base_hex")

    proj_dir=$(mktemp -d)
    proj_name="anchor_test_${name}_$$"
    log_file="$LOG_DIR/${name}.log"

    "${ANALYZE[@]}" "$proj_dir" "$proj_name" \
        -import "$bin" \
        -loader BinaryLoader \
        -loader-baseAddr 0x00000000 \
        -processor "$lang" \
        -scriptPath "$REPO_DIR" \
        -postScript ghidra_anchor.py \
        -deleteProject \
        -overwrite \
        -analysisTimeoutPerFile 300 \
        >"$log_file" 2>&1
    rc=$?
    rm -rf "$proj_dir"

    if [ $rc -ne 0 ]; then
        printf "[%d/%d] %-30s FAIL (analyzeHeadless exit %d)\n" \
               "$idx" "$total" "$name" "$rc"
        tail -30 "$log_file" | sed 's/^/    /'
        fail=$((fail + 1))
        continue
    fi

    # Extract the hex addresses that appear on "ptr hit count:" lines.
    # analyzeHeadless prefixes script output with "INFO ... (HeadlessAnalyzer)"
    # so we match on the substring rather than positional awk columns.
    tops=$(grep -oE '0x[0-9a-fA-F]{8}[[:space:]]+ptr hit count' "$log_file" \
           | awk '{print $1}')
    rank=$(echo "$tops" | grep -in "^${expected}$" | head -1 | cut -d: -f1)

    if [ -n "$rank" ]; then
        printf "[%d/%d] %-30s PASS  (expected %s at rank #%s)\n" \
               "$idx" "$total" "$name" "$expected" "$rank"
        pass=$((pass + 1))
    else
        printf "[%d/%d] %-30s FAIL  (expected %s not in top-%d)\n" \
               "$idx" "$total" "$name" "$expected" "$TOP_N"
        echo "    top candidates were:"
        echo "$tops" | sed 's/^/      /'
        echo "    full log: $log_file"
        fail=$((fail + 1))
    fi
done

echo
echo "------------------------------------------------------------"
echo "summary: $pass pass, $fail fail (of $total)"
if [ "$fail" -gt 0 ]; then
    # Preserve the log dir on failure so the user can inspect it.
    trap - EXIT
    echo "logs preserved at: $LOG_DIR"
    exit 1
fi
exit 0
