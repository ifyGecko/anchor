#!/usr/bin/env bash
# ghidra_anchor_jython self-test
#
# Builds every test firmware image declared in tests/Makefile, then imports each
# one into a scratch Ghidra project via analyzeHeadless, runs ghidra_anchor_jython.py
# as the post-script (Jython 2.7 runtime), and confirms the known base address
# appears in the top-N candidate list printed to the Ghidra console.
#
# Usage:
#   ghidra-jython-self-test.sh <ghidra_install_dir>
#
# Requirements:
#   - <ghidra_install_dir>/support/analyzeHeadless
#   - The Jython Ghidra Extension installed in the Ghidra install (extract
#     Extensions/Ghidra/*_Jython.zip into Ghidra/Extensions/).

set -u
set -o pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <ghidra_install_dir>"
    exit 2
fi

GHIDRA_DIR="$1"
ANALYZE="$GHIDRA_DIR/support/analyzeHeadless"

if [ ! -x "$ANALYZE" ]; then
    echo "error: $ANALYZE not found or not executable"
    exit 2
fi

# Best-effort check: the Jython extension must be installed into
# $GHIDRA_DIR/Ghidra/Extensions/Jython for headless to pick up .py scripts as
# Jython. If missing, the run will still proceed - the log will surface the
# real error - but we surface a helpful hint here.
if [ ! -d "$GHIDRA_DIR/Ghidra/Extensions/Jython" ]; then
    echo "warning: Jython Ghidra Extension not found under"
    echo "         $GHIDRA_DIR/Ghidra/Extensions/Jython"
    echo "         install with:"
    echo "           unzip $GHIDRA_DIR/Extensions/Ghidra/*_Jython.zip \\"
    echo "                 -d $GHIDRA_DIR/Ghidra/Extensions/"
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
POST_SCRIPT="$REPO_DIR/ghidra_anchor_jython.py"
BUILD_DIR="$SCRIPT_DIR/build"
TOP_N=5

if [ ! -f "$POST_SCRIPT" ]; then
    echo "error: ghidra_anchor_jython.py not found at $POST_SCRIPT"
    exit 2
fi

echo "ghidra_anchor_jython self-test"
echo "------------------------------------------------------------"
echo "building test firmware images..."
if ! make -s -C "$SCRIPT_DIR" all; then
    echo "make failed"
    exit 1
fi
echo "  build OK"
echo

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

LOG_DIR=$(mktemp -d)
trap 'rm -rf "$LOG_DIR"' EXIT

for bin in "${bins[@]}"; do
    idx=$((idx + 1))
    name=$(basename "$bin" .bin)

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
    proj_name="anchor_jython_test_${name}_$$"
    log_file="$LOG_DIR/${name}.log"

    "$ANALYZE" "$proj_dir" "$proj_name" \
        -import "$bin" \
        -loader BinaryLoader \
        -loader-baseAddr 0x00000000 \
        -processor "$lang" \
        -scriptPath "$REPO_DIR" \
        -postScript ghidra_anchor_jython.py \
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
    trap - EXIT
    echo "logs preserved at: $LOG_DIR"
    exit 1
fi
exit 0
