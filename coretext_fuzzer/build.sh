#!/bin/bash
# build.sh - Build CoreText font table fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
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

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_coretext fuzz_coretext.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_coretext.o fuzz_coretext.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_coretext fuzz_coretext.o standalone_harness.o
    rm -f fuzz_coretext.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Run: ./fuzz_coretext corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
