#!/bin/bash
# build.sh - Build morx+cmap chain font generator and test harness
set -e
cd "$(dirname "$0")"

echo "=== morx+cmap Chain Font Tools ==="
echo ""

mkdir -p corpus crashes

echo "[1/3] Building chain font generator..."
clang -o build_chain_font build_chain_font.c 2>&1
echo "      Done."

echo "[2/3] Generating chain fonts..."
./build_chain_font
cp *.ttf corpus/ 2>/dev/null || true
echo "      Done."

echo "[3/3] Building ASAN test harness..."
clang -framework Foundation -framework CoreText -framework CoreGraphics \
    -fsanitize=address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o test_chain test_morx_chain.c 2>&1 || echo "      (test_morx_chain.c build skipped - may need ObjC)"
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus fonts: $(ls corpus/*.ttf 2>/dev/null | wc -l | tr -d ' ')"
