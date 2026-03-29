#!/bin/bash
# build.sh - Build cmap variant fuzzer
# cmap_variant_fuzzer has its own main() - no libFuzzer needed, just ASAN
set -e
cd "$(dirname "$0")"

echo "=== cmap Variant Fuzzer ==="
echo ""

mkdir -p corpus crashes

echo "[1/3] Building cmap font generator..."
clang -o build_cmap_fonts build_cmap_fonts.c 2>&1
echo "      Done."

echo "[2/3] Generating cmap test fonts..."
./build_cmap_fonts
cp *.ttf corpus/ 2>/dev/null || true
echo "      Done."

echo "[3/3] Building fuzzer (ASAN + UBSan)..."
clang -framework Foundation -framework CoreText -framework CoreGraphics \
    -fsanitize=address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o cmap_variant_fuzzer cmap_variant_fuzzer.c 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./cmap_variant_fuzzer corpus/"
