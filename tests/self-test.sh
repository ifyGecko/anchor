#!/usr/bin/env bash
# anchor self-test
#
# Builds every test firmware image declared in tests/Makefile then runs
# anchor.py against each one and confirms the known base address appears
# in anchor's top-N candidate list.
#
# To add a new test case:
#   1. Add its <arch>_<endian>_<basehex> entry to CASES in tests/Makefile
#   2. Re-run this script.
# No changes to anchor.py are required.

set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ANCHOR="$SCRIPT_DIR/../anchor.py"
BUILD_DIR="$SCRIPT_DIR/build"
TOP_N=5

if [ ! -f "$ANCHOR" ]; then
    echo "error: anchor.py not found at $ANCHOR"
    exit 2
fi

echo "anchor self-test"
echo "------------------------------------------------------------"
echo "building test firmware images..."
if ! make -s -C "$SCRIPT_DIR" all; then
    echo "make failed"
    exit 1
fi
echo "  build OK"
echo

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

for bin in "${bins[@]}"; do
    idx=$((idx + 1))
    name=$(basename "$bin" .bin)

    # Parse "<arch>_<endian>_<base>" from filename.
    # arch may be "arm", "mips32", or "ppc32"; endian is "le" or "be";
    # base is the trailing hex chunk.
    if [[ "$name" =~ ^([a-z0-9]+)_([lb]e)_([0-9a-fA-F]+)$ ]]; then
        arch="${BASH_REMATCH[1]}"
        endian="${BASH_REMATCH[2]}"
        base_hex="${BASH_REMATCH[3]}"
    else
        printf "[%d/%d] %-30s SKIP (unrecognized name)\n" "$idx" "$total" "$name"
        continue
    fi

    expected=$(printf "0x%08x" "0x$base_hex")

    output=$(python3 "$ANCHOR" "$bin" --arch "$arch" --endian "$endian" --top $TOP_N 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        printf "[%d/%d] %-30s FAIL (anchor exit %d)\n" "$idx" "$total" "$name" "$rc"
        echo "$output" | sed 's/^/    /'
        fail=$((fail + 1))
        continue
    fi

    tops=$(echo "$output" | awk '/ptr hit count:/ { print $2 }')
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
        fail=$((fail + 1))
    fi
done

echo
echo "------------------------------------------------------------"
echo "summary: $pass pass, $fail fail (of $total)"
if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
