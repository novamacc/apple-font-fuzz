# apple-font-fuzz

Continuous fuzzing of Apple CoreText font parsing on macOS using libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer.

## Fuzzers

| Fuzzer | Target | Tables/Features | Zero-Click Vectors |
|--------|--------|----------------|-------------------|
| `coretext_fuzzer` | CoreText + CoreGraphics | 13 tables: glyf, loca, head, hhea, hmtx, maxp, name, post, morx, kern, kerx, GSUB, GPOS | Safari @font-face, Mail HTML, Messages |
| `morx_exploit` | CoreText morx table | Morphing chain state machine exploitation | Web fonts, document fonts |
| `morx_cmap_chain` | CoreText morx+cmap | Combined morx morphing + cmap character mapping chain | Web fonts, document fonts |
| `cmap_variant_fuzzer` | CoreText cmap table | Format 6 cmap subtable OOB read variants | Web fonts, document fonts |

## CI

Runs on `macos-15` every 4 hours via GitHub Actions. Each fuzzer runs for ~5 hours with 3 parallel workers. Crash artifacts are uploaded automatically.

## Local Build

```bash
cd coretext_fuzzer && ./build.sh
./fuzz_coretext corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4
```
