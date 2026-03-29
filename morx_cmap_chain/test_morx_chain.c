/*
 * test_morx_chain.c - Test morx+cmap chain font under ASAN
 *
 * Loads the chain font and exercises CoreText's text shaping pipeline:
 *   1. Load font via CGDataProvider → CGFont → CTFont
 *   2. Call CTFontGetGlyphsForCharacters (triggers cmap OOB glyph IDs)
 *   3. Call CTLineCreateWithAttributedString (triggers morx processing)
 *   4. Draw to a CGBitmapContext (triggers full rasterization pipeline)
 *
 * If morx doesn't bounds-check the OOB glyph IDs from cmap, ASAN
 * will report heap-buffer-overflow in the morx state machine.
 *
 * Build:
 *   clang -framework CoreText -framework CoreGraphics -framework CoreFoundation \
 *         -framework AppKit -fsanitize=address -g -O1 \
 *         -o test_chain test_morx_chain.c
 *
 * Run:
 *   ./test_chain morx_cmap_chain.ttf
 */

#include <CoreText/CoreText.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* Timeout handler */
static volatile int g_timed_out = 0;
static void alarm_handler(int sig) {
    (void)sig;
    g_timed_out = 1;
    printf("\n[HANG] CoreText hung during morx processing (10 second timeout)\n");
    _exit(42);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <font.ttf>\n", argv[0]);
        return 1;
    }

    /* Set alarm — morx processing shouldn't take >10 seconds */
    signal(SIGALRM, alarm_handler);
    alarm(10);

    const char *font_path = argv[1];
    printf("[*] Loading font: %s\n", font_path);

    /* Load font */
    CFStringRef path_str = CFStringCreateWithCString(
        kCFAllocatorDefault, font_path, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault, path_str, kCFURLPOSIXPathStyle, false);
    CFRelease(path_str);

    CGDataProviderRef provider = CGDataProviderCreateWithURL(url);
    if (!provider) {
        printf("[-] CGDataProviderCreateWithURL failed\n");
        CFRelease(url);
        return 1;
    }

    CGFontRef cgFont = CGFontCreateWithDataProvider(provider);
    CGDataProviderRelease(provider);
    CFRelease(url);

    if (!cgFont) {
        printf("[-] CGFontCreateWithDataProvider failed\n");
        return 1;
    }

    CTFontRef ctFont = CTFontCreateWithGraphicsFont(cgFont, 48.0, NULL, NULL);
    if (!ctFont) {
        printf("[-] CTFontCreateWithGraphicsFont failed\n");
        CGFontRelease(cgFont);
        return 1;
    }

    int numGlyphs = (int)CTFontGetGlyphCount(ctFont);
    printf("[+] Font loaded. numGlyphs=%d\n", numGlyphs);

    /* Phase 1: Test CTFontGetGlyphsForCharacters with various chars */
    printf("[*] Phase 1: CTFontGetGlyphsForCharacters (cmap OOB test)\n");
    {
        UniChar test_chars[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            ' ', '!', '@', '#', '$', '%', '^', '&', '*', '(',
        };
        int nchars = sizeof(test_chars) / sizeof(test_chars[0]);
        CGGlyph glyphs[50];
        bool found = CTFontGetGlyphsForCharacters(ctFont, test_chars, glyphs, nchars);
        printf("    found=%s\n", found ? "true" : "false");

        int oob_count = 0;
        for (int i = 0; i < nchars; i++) {
            if (glyphs[i] >= numGlyphs) {
                oob_count++;
                if (oob_count <= 10) {
                    printf("    [OOB] char=0x%04X glyph=%u (numGlyphs=%d)\n",
                           test_chars[i], glyphs[i], numGlyphs);
                }
            }
        }
        printf("    OOB glyph IDs: %d/%d\n", oob_count, nchars);
    }

    /* Phase 2: Text shaping via CTLine (exercises morx) */
    printf("[*] Phase 2: CTLineCreateWithAttributedString (morx shaping test)\n");
    {
        /* Create attributed string with our font */
        CFStringRef text = CFSTR("Hello World! ABCDEFGHIJ 0123456789");
        CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(attrs, kCTFontAttributeName, ctFont);

        CFAttributedStringRef attrStr = CFAttributedStringCreate(
            kCFAllocatorDefault, text, attrs);
        CFRelease(attrs);

        /* Create line — this triggers the full AAT/morx shaping pipeline */
        CTLineRef line = CTLineCreateWithAttributedString(attrStr);
        if (line) {
            printf("    [+] CTLine created successfully\n");

            /* Get glyph runs — forces morx to process all glyphs */
            CFArrayRef runs = CTLineGetGlyphRuns(line);
            CFIndex nruns = CFArrayGetCount(runs);
            printf("    [+] Glyph runs: %ld\n", (long)nruns);

            for (CFIndex r = 0; r < nruns; r++) {
                CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, r);
                CFIndex glyphCount = CTRunGetGlyphCount(run);
                printf("    [+] Run %ld: %ld glyphs\n", (long)r, (long)glyphCount);

                /* Get actual glyph IDs after morx processing */
                CGGlyph *runGlyphs = malloc(sizeof(CGGlyph) * glyphCount);
                CTRunGetGlyphs(run, CFRangeMake(0, 0), runGlyphs);

                int oob = 0;
                for (CFIndex g = 0; g < glyphCount; g++) {
                    if (runGlyphs[g] >= numGlyphs) {
                        oob++;
                        if (oob <= 5) {
                            printf("        [OOB-MORX] glyph[%ld]=%u (numGlyphs=%d)\n",
                                   (long)g, runGlyphs[g], numGlyphs);
                        }
                    }
                }
                if (oob > 0) {
                    printf("        [!] %d OOB glyphs AFTER morx processing!\n", oob);
                }
                free(runGlyphs);
            }

            /* Phase 3: Render to bitmap context (exercises rasterization with OOB glyphs) */
            printf("[*] Phase 3: CGBitmapContext rendering (rasterization test)\n");
            {
                int width = 800, height = 100;
                CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                CGContextRef ctx = CGBitmapContextCreate(
                    NULL, width, height, 8, width * 4,
                    cs, kCGImageAlphaPremultipliedLast);

                if (ctx) {
                    CGContextSetTextPosition(ctx, 10, 50);
                    CTLineDraw(line, ctx);
                    printf("    [+] CTLineDraw completed (no crash)\n");

                    /* Check if any pixels were drawn */
                    uint8_t *pixels = CGBitmapContextGetData(ctx);
                    int nonzero = 0;
                    for (int i = 0; i < width * height * 4 && nonzero < 10; i++) {
                        if (pixels[i] > 0) nonzero++;
                    }
                    printf("    [+] Non-zero pixels: %s\n", nonzero > 0 ? "YES" : "NO");

                    CGContextRelease(ctx);
                }
                CGColorSpaceRelease(cs);
            }

            CFRelease(line);
        } else {
            printf("    [-] CTLineCreateWithAttributedString returned NULL\n");
        }
        CFRelease(attrStr);
    }

    /* Phase 4: Exercise morx with longer text to stress state machine */
    printf("[*] Phase 4: Extended morx stress test\n");
    {
        /* Generate a long string with all printable ASCII */
        char stress[4096];
        int pos = 0;
        for (int rep = 0; rep < 10 && pos < 4000; rep++) {
            for (int ch = 32; ch < 127 && pos < 4000; ch++) {
                stress[pos++] = ch;
            }
        }
        stress[pos] = '\0';

        CFStringRef stressStr = CFStringCreateWithCString(
            kCFAllocatorDefault, stress, kCFStringEncodingASCII);
        CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(attrs, kCTFontAttributeName, ctFont);

        CFAttributedStringRef attrStr = CFAttributedStringCreate(
            kCFAllocatorDefault, stressStr, attrs);

        CTLineRef line = CTLineCreateWithAttributedString(attrStr);
        if (line) {
            CFArrayRef runs = CTLineGetGlyphRuns(line);
            CFIndex nruns = CFArrayGetCount(runs);
            CFIndex total_glyphs = 0;
            int total_oob = 0;

            for (CFIndex r = 0; r < nruns; r++) {
                CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, r);
                CFIndex gc = CTRunGetGlyphCount(run);
                total_glyphs += gc;

                CGGlyph *g = malloc(sizeof(CGGlyph) * gc);
                CTRunGetGlyphs(run, CFRangeMake(0, 0), g);
                for (CFIndex i = 0; i < gc; i++) {
                    if (g[i] >= numGlyphs) total_oob++;
                }
                free(g);
            }
            printf("    [+] Stress test: %ld runs, %ld glyphs, %d OOB\n",
                   (long)nruns, (long)total_glyphs, total_oob);
            CFRelease(line);
        }

        CFRelease(attrStr);
        CFRelease(attrs);
        CFRelease(stressStr);
    }

    /* Cleanup */
    CFRelease(ctFont);
    CGFontRelease(cgFont);

    printf("\n[+] All tests completed. No ASAN violations = morx bounds-checks glyph IDs.\n");
    printf("    If ASAN reported heap-buffer-overflow, we have a morx memory corruption!\n");
    return 0;
}
