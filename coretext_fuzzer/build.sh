#!/bin/bash
# build.sh - Build CoreText font table fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreText -framework CoreGraphics -framework CoreFoundation"

echo "=== CoreText Font Table Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes
# Create minimal seed: path-selector byte + minimal font table data
for i in $(seq 0 12); do
    printf "\\x$(printf '%02x' $i)" > "corpus/table_${i}.bin"
    # Append some minimal binary data
    dd if=/dev/urandom bs=64 count=1 2>/dev/null >> "corpus/table_${i}.bin"
done
echo "      Done. $(ls corpus/ | wc -l | tr -d ' ') seeds"

echo "[2/2] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_coretext fuzz_coretext.m 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Run: ./fuzz_coretext corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
