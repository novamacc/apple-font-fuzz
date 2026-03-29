/*
 * build_cmap_fonts.c - Programmatic TrueType font builder for cmap format fuzzing
 *
 * Library of font builders for each cmap format (0,2,4,6,8,10,12,13,14).
 * Each builder creates a structurally valid font for that format but with
 * controlled encoding values targeting integer truncation boundaries.
 *
 * Key attack surface: encoding=256 (0x100) stored in 8-bit variable causes
 * truncation to 0, routing data to unexpected format handlers.
 * CVE-2020-27930 achieved RCE via exactly this pattern.
 *
 * Build:
 *   clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *     -framework CoreText -framework CoreGraphics -framework CoreFoundation \
 *     -o build_cmap_fonts build_cmap_fonts.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

// ---- Big-endian write helpers ----
static void w8(uint8_t *p, uint8_t v) { p[0] = v; }
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

// TrueType table checksum
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

// ---- Standard required table builders ----

static size_t build_head(uint8_t *buf) {
    memset(buf, 0, 54);
    w16(buf + 0, 1); w16(buf + 2, 0);           // version 1.0
    w32(buf + 4, 0x5F0F3CF5);                    // magicNumber
    w32(buf + 8, 0);                              // checksumAdjustment (patched later)
    w32(buf + 12, 0x5F0F3CF5);                    // magicNumber duplicate
    w16(buf + 16, 0x000B);                        // flags
    w16(buf + 18, 1000);                          // unitsPerEm
    // dates left as zero
    w16(buf + 36, 0);                             // xMin
    w16(buf + 38, 0);                             // yMin
    w16(buf + 40, 1000);                          // xMax
    w16(buf + 42, 800);                           // yMax
    w16(buf + 44, 0);                             // macStyle
    w16(buf + 46, 8);                             // lowestRecPPEM
    w16(buf + 48, 2);                             // fontDirectionHint
    w16(buf + 50, 1);                             // indexToLocFormat = long
    w16(buf + 52, 0);                             // glyphDataFormat
    return 54;
}

static size_t build_hhea(uint8_t *buf, uint16_t num_hmetrics) {
    memset(buf, 0, 36);
    w16(buf + 0, 1); w16(buf + 2, 0);            // version
    w16(buf + 4, 800);                            // ascent
    w16(buf + 6, (uint16_t)(int16_t)-200);        // descent
    w16(buf + 8, 0);                              // lineGap
    w16(buf + 10, 600);                           // advanceWidthMax
    w16(buf + 34, num_hmetrics);                  // numOfLongHorMetrics
    return 36;
}

static size_t build_hmtx(uint8_t *buf, uint16_t num_glyphs) {
    for (uint16_t i = 0; i < num_glyphs; i++) {
        w16(buf + i * 4, 500);                    // advanceWidth
        w16(buf + i * 4 + 2, 0);                  // lsb
    }
    return num_glyphs * 4;
}

static size_t build_maxp(uint8_t *buf, uint16_t num_glyphs) {
    memset(buf, 0, 32);
    w32(buf + 0, 0x00010000);                     // version 1.0
    w16(buf + 4, num_glyphs);
    w16(buf + 6, 64);                             // maxPoints
    w16(buf + 8, 1);                              // maxContours
    w16(buf + 14, 1);                             // maxZones
    return 32;
}

// Long format loca (indexToLocFormat=1)
static size_t build_loca_long(uint8_t *buf, uint16_t num_glyphs, uint32_t glyf_size) {
    for (uint16_t i = 0; i <= num_glyphs; i++) {
        if (i < num_glyphs)
            w32(buf + i * 4, 0);                  // all glyphs at offset 0
        else
            w32(buf + i * 4, glyf_size);          // end marker
    }
    return (num_glyphs + 1) * 4;
}

// Simple notdef glyph
static size_t build_glyf(uint8_t *buf) {
    memset(buf, 0, 12);
    w16(buf + 0, 0);                              // numberOfContours = 0 (empty)
    w16(buf + 2, 0); w16(buf + 4, 0);            // xMin, yMin
    w16(buf + 6, 0); w16(buf + 8, 0);            // xMax, yMax
    return 12;
}

static size_t build_os2(uint8_t *buf) {
    memset(buf, 0, 96);
    w16(buf + 0, 4);                              // version
    w16(buf + 2, 500);                            // xAvgCharWidth
    w16(buf + 4, 400);                            // usWeightClass
    w16(buf + 6, 5);                              // usWidthClass
    w16(buf + 78, 0x0020);                        // usFirstCharIndex
    w16(buf + 80, 0xFFFF);                        // usLastCharIndex
    w16(buf + 68, 800);                           // sTypoAscender
    w16(buf + 70, (uint16_t)(int16_t)-200);       // sTypoDescender
    return 96;
}

static size_t build_name(uint8_t *buf) {
    // Minimal name table with font family name
    uint8_t name_data[] = {
        0, 0,  // format 0
        0, 1,  // count = 1
        0, 18, // string offset (6 + 12*1 = 18)
        // Name record: platformID=3, encodingID=1, languageID=0x0409, nameID=4
        0, 3, 0, 1, 0x04, 0x09, 0, 4, 0, 10, 0, 0,
        // String data: "CmapFuzz" in UTF-16BE
        0, 'C', 0, 'm', 0, 'a', 0, 'p', 0, 'F'
    };
    memcpy(buf, name_data, sizeof(name_data));
    return sizeof(name_data);
}

static size_t build_post(uint8_t *buf) {
    memset(buf, 0, 32);
    w32(buf + 0, 0x00030000);                     // version 3.0 (no glyph names)
    w32(buf + 4, 0);                              // italicAngle
    w16(buf + 8, (uint16_t)(int16_t)-100);        // underlinePosition
    w16(buf + 10, 50);                            // underlineThickness
    w32(buf + 12, 0);                             // isFixedPitch
    return 32;
}

// =========================================================================
// cmap Format Builders
// Each returns the size of the cmap subtable written at buf
// =========================================================================

/*
 * Format 0: Byte encoding table
 * 256-byte array mapping character codes 0-255 to glyph indices (1 byte each)
 * ATTACK: encoding=256 is EXACTLY one past the 256-byte boundary
 */
static size_t build_cmap_format0(uint8_t *buf) {
    w16(buf + 0, 0);      // format = 0
    w16(buf + 2, 262);    // length = 6 + 256
    w16(buf + 4, 0);      // language
    // Glyph index array: map printable ASCII to glyph 1, rest to 0
    for (int i = 0; i < 256; i++) {
        buf[6 + i] = (i >= 0x20 && i <= 0x7E) ? 1 : 0;
    }
    return 262;
}

/*
 * Format 2: High-byte mapping through table
 * Complex format with subHeaderKeys, subHeaders, and glyphIdArray
 * ATTACK: subHeaderKeys array is 256 uint16s - encoding=256 could index past it
 *         subHeader firstCode/entryCount can cause arithmetic confusion
 */
static size_t build_cmap_format2(uint8_t *buf) {
    // Header: format(2) + length(2) + language(2) = 6
    // subHeaderKeys: 256 * 2 = 512 bytes
    // subHeaders: 2 entries * 8 = 16 bytes
    // glyphIdArray: 256 entries * 2 = 512 bytes
    size_t total = 6 + 512 + 16 + 512;

    w16(buf + 0, 2);                              // format = 2
    w16(buf + 2, (uint16_t)total);                // length
    w16(buf + 4, 0);                              // language

    // subHeaderKeys: index into subHeaders array
    // key[i] = 8 * subHeader_index (0 = first subHeader, 8 = second)
    // Route high bytes 0x00 to subHeader 0, everything else to subHeader 1
    uint8_t *keys = buf + 6;
    for (int i = 0; i < 256; i++) {
        w16(keys + i * 2, (i == 0) ? 0 : 8);
    }

    // subHeaders at offset 518 (6 + 512)
    uint8_t *sh = buf + 518;

    // subHeader 0: firstCode=0x20, entryCount=96, idDelta=0, idRangeOffset
    w16(sh + 0, 0x0020);                          // firstCode
    w16(sh + 2, 96);                              // entryCount
    w16(sh + 4, 0);                               // idDelta
    w16(sh + 6, 16);                              // idRangeOffset (relative to &idRangeOffset)

    // subHeader 1: catches everything else - maps to .notdef
    w16(sh + 8, 0);                               // firstCode
    w16(sh + 10, 0);                              // entryCount = 0, maps nothing
    w16(sh + 12, 0);                              // idDelta
    w16(sh + 14, 0);                              // idRangeOffset

    // glyphIdArray at offset 534 (518 + 16)
    uint8_t *gids = buf + 534;
    for (int i = 0; i < 256; i++) {
        w16(gids + i * 2, (i < 96) ? (i + 1) : 0);
    }

    return total;
}

/*
 * Format 4: Segment mapping to delta values
 * Most common format for BMP characters
 */
static size_t build_cmap_format4(uint8_t *buf) {
    uint16_t segCount = 2;
    uint16_t segCountX2 = segCount * 2;
    size_t total = 14 + segCount * 8;  // header(14) + 4 arrays of segCount uint16s

    w16(buf + 0, 4);                              // format
    w16(buf + 2, (uint16_t)total);                // length
    w16(buf + 4, 0);                              // language
    w16(buf + 6, segCountX2);                     // segCountX2
    w16(buf + 8, 4);                              // searchRange
    w16(buf + 10, 1);                             // entrySelector
    w16(buf + 12, 0);                             // rangeShift

    uint8_t *p = buf + 14;
    // endCode array
    w16(p + 0, 0x007F);  w16(p + 2, 0xFFFF);
    // reservedPad
    p += segCountX2;
    w16(p, 0); p += 2;
    // startCode array
    w16(p + 0, 0x0020);  w16(p + 2, 0xFFFF);
    p += segCountX2;
    // idDelta array
    w16(p + 0, 0);       w16(p + 2, 1);
    p += segCountX2;
    // idRangeOffset array
    w16(p + 0, 0);       w16(p + 2, 0);

    return total;
}

/*
 * Format 6: Trimmed table mapping
 * ATTACK: firstCode + entryCount overflow with encoding=256
 *         entryCount near uint16 max causes massive reads
 */
static size_t build_cmap_format6(uint8_t *buf, uint16_t firstCode, uint16_t entryCount) {
    size_t total = 10 + entryCount * 2;

    w16(buf + 0, 6);                              // format
    w16(buf + 2, (uint16_t)total);                // length
    w16(buf + 4, 0);                              // language
    w16(buf + 6, firstCode);                      // firstCode
    w16(buf + 8, entryCount);                     // entryCount

    // glyphIdArray
    for (uint16_t i = 0; i < entryCount; i++) {
        w16(buf + 10 + i * 2, (i % 255) + 1);
    }

    return total;
}

/* Default format 6 with reasonable values */
static size_t build_cmap_format6_default(uint8_t *buf) {
    return build_cmap_format6(buf, 0x0020, 96);
}

/*
 * Format 8: mixed 16/32-bit coverage
 * Uses is32 bitmap (8192 bytes) + groups
 * ATTACK: is32 bitmap confusion with encoding boundary values
 */
static size_t build_cmap_format8(uint8_t *buf) {
    // Fixed header: format(2) + reserved(2) + length(4) + language(4) = 12
    // is32 array: 8192 bytes
    // nGroups(4) + groups(nGroups * 12)
    uint32_t nGroups = 2;
    size_t total = 12 + 8192 + 4 + nGroups * 12;

    w16(buf + 0, 8);                              // format (uint16)
    w16(buf + 2, 0);                              // reserved
    w32(buf + 4, (uint32_t)total);                // length (uint32)
    w32(buf + 8, 0);                              // language

    // is32 array: all zeros (all 16-bit) except byte for range 0x10000
    uint8_t *is32 = buf + 12;
    memset(is32, 0, 8192);
    is32[0x10000 / 8] |= (1 << (7 - (0x10000 % 8)));  // mark one 32-bit char

    // nGroups
    w32(buf + 12 + 8192, nGroups);

    // Group 0: BMP range
    uint8_t *g = buf + 12 + 8192 + 4;
    w32(g + 0, 0x0020);                           // startCharCode
    w32(g + 4, 0x007F);                           // endCharCode
    w32(g + 8, 1);                                // startGlyphID

    // Group 1: supplementary plane range
    w32(g + 12, 0x10000);                         // startCharCode
    w32(g + 16, 0x10010);                         // endCharCode
    w32(g + 20, 100);                             // startGlyphID

    return total;
}

/*
 * Format 10: Trimmed array (32-bit)
 * Like format 6 but for 32-bit character codes
 */
static size_t build_cmap_format10(uint8_t *buf) {
    uint32_t startCharCode = 0x0020;
    uint32_t numChars = 96;
    size_t total = 20 + numChars * 2;

    w16(buf + 0, 10);                             // format
    w16(buf + 2, 0);                              // reserved
    w32(buf + 4, (uint32_t)total);                // length
    w32(buf + 8, 0);                              // language
    w32(buf + 12, startCharCode);                 // startCharCode
    w32(buf + 16, numChars);                      // numChars

    // glyphs array
    for (uint32_t i = 0; i < numChars; i++) {
        w16(buf + 20 + i * 2, (uint16_t)(i + 1));
    }

    return total;
}

/*
 * Format 12: Segmented coverage (32-bit)
 * Most common format for full Unicode
 * ATTACK: nGroups confusion, startCharCode near boundaries
 */
static size_t build_cmap_format12(uint8_t *buf) {
    uint32_t nGroups = 3;
    size_t total = 16 + nGroups * 12;

    w16(buf + 0, 12);                             // format
    w16(buf + 2, 0);                              // reserved
    w32(buf + 4, (uint32_t)total);                // length
    w32(buf + 8, 0);                              // language
    w32(buf + 12, nGroups);                       // nGroups

    uint8_t *g = buf + 16;
    // Group 0: Basic ASCII
    w32(g + 0, 0x0020);
    w32(g + 4, 0x007E);
    w32(g + 8, 1);

    // Group 1: Latin Extended
    w32(g + 12, 0x00A0);
    w32(g + 16, 0x00FF);
    w32(g + 20, 100);

    // Group 2: CJK area
    w32(g + 24, 0x4E00);
    w32(g + 28, 0x4E0F);
    w32(g + 32, 200);

    return total;
}

/*
 * Format 13: Many-to-one range mappings
 * Like format 12 but all chars in a group map to the SAME glyph
 */
static size_t build_cmap_format13(uint8_t *buf) {
    uint32_t nGroups = 2;
    size_t total = 16 + nGroups * 12;

    w16(buf + 0, 13);                             // format
    w16(buf + 2, 0);                              // reserved
    w32(buf + 4, (uint32_t)total);                // length
    w32(buf + 8, 0);                              // language
    w32(buf + 12, nGroups);

    uint8_t *g = buf + 16;
    // Group 0: all ASCII space to tilde -> glyph 1
    w32(g + 0, 0x0020);
    w32(g + 4, 0x007E);
    w32(g + 8, 1);                                // glyphID (single, not start)

    // Group 1: CJK -> glyph 2
    w32(g + 12, 0x4E00);
    w32(g + 16, 0x9FFF);
    w32(g + 20, 2);

    return total;
}

/*
 * Format 14: Unicode Variation Sequences
 * Contains varSelector records with defaultUVS and nonDefaultUVS tables
 * ATTACK: newest format, least tested. Variation selector + encoding confusion
 */
static size_t build_cmap_format14(uint8_t *buf) {
    // Header: format(2) + length(4) + numVarSelectorRecords(4) = 10
    // Each varSelector record: varSelector(3) + defaultUVSOffset(4) + nonDefaultUVSOffset(4) = 11
    // Default UVS table: numUnicodeValueRanges(4) + ranges(startUnicodeValue(3) + additionalCount(1)) = 4 + N*4
    // Non-default UVS table: numUVSMappings(4) + mappings(unicodeValue(3) + glyphID(2)) = 4 + N*5

    uint32_t numRecords = 2;
    uint32_t headerSize = 10 + numRecords * 11;  // 32

    // Default UVS for record 0: 1 range
    uint32_t defaultUVS0_off = headerSize;
    uint32_t defaultUVS0_size = 4 + 1 * 4;       // 8

    // Non-default UVS for record 1: 2 mappings
    uint32_t nonDefaultUVS1_off = defaultUVS0_off + defaultUVS0_size;
    uint32_t nonDefaultUVS1_size = 4 + 2 * 5;    // 14

    size_t total = nonDefaultUVS1_off + nonDefaultUVS1_size;

    w16(buf + 0, 14);                             // format
    w32(buf + 2, (uint32_t)total);                // length
    w32(buf + 6, numRecords);                     // numVarSelectorRecords

    // VarSelector record 0: VS1 (U+FE00) with default UVS
    uint8_t *r = buf + 10;
    // varSelector is 24-bit (3 bytes)
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x00;      // U+FE00
    w32(r + 3, defaultUVS0_off);                  // defaultUVSOffset
    w32(r + 7, 0);                                // nonDefaultUVSOffset = 0 (none)

    // VarSelector record 1: VS2 (U+FE01) with non-default UVS
    r = buf + 10 + 11;
    r[0] = 0x00; r[1] = 0xFE; r[2] = 0x01;      // U+FE01
    w32(r + 3, 0);                                // defaultUVSOffset = 0 (none)
    w32(r + 7, nonDefaultUVS1_off);               // nonDefaultUVSOffset

    // Default UVS table 0
    uint8_t *duvs = buf + defaultUVS0_off;
    w32(duvs + 0, 1);                             // numUnicodeValueRanges
    duvs[4] = 0x00; duvs[5] = 0x00; duvs[6] = 0x41;  // startUnicodeValue = U+0041 ('A')
    duvs[7] = 25;                                 // additionalCount (A-Z = 26 chars)

    // Non-default UVS table 1
    uint8_t *nduvs = buf + nonDefaultUVS1_off;
    w32(nduvs + 0, 2);                            // numUVSMappings
    // Mapping 0: U+0041 -> glyph 5
    nduvs[4] = 0x00; nduvs[5] = 0x00; nduvs[6] = 0x41;
    w16(nduvs + 7, 5);
    // Mapping 1: U+0042 -> glyph 6
    nduvs[9] = 0x00; nduvs[10] = 0x00; nduvs[11] = 0x42;
    w16(nduvs + 12, 6);

    return total;
}

// =========================================================================
// Full font assembler
// Takes a cmap subtable and wraps it in a complete TrueType font
// =========================================================================

typedef struct {
    uint16_t platformID;
    uint16_t encodingID;
} CmapRecord;

/*
 * Assemble a complete font with the given cmap subtable and encoding records.
 * All encoding records point to the same subtable.
 * Returns allocated font data (caller frees) and sets *out_size.
 */
static uint8_t *assemble_font(
    const uint8_t *cmap_subtable, size_t subtable_size,
    const CmapRecord *records, int num_records,
    uint16_t num_glyphs,
    size_t *out_size)
{
    // Build required tables
    uint8_t head[54];      size_t head_sz = build_head(head);
    uint8_t hhea[36];      size_t hhea_sz = build_hhea(hhea, num_glyphs);
    size_t hmtx_alloc = (num_glyphs + 1) * 4;
    uint8_t *hmtx = calloc(1, hmtx_alloc);
    size_t hmtx_sz = build_hmtx(hmtx, num_glyphs);
    uint8_t maxp[32];      size_t maxp_sz = build_maxp(maxp, num_glyphs);
    uint8_t glyf_buf[12];  size_t glyf_sz = build_glyf(glyf_buf);
    size_t loca_alloc = (num_glyphs + 2) * 4;
    uint8_t *loca = calloc(1, loca_alloc);
    size_t loca_sz = build_loca_long(loca, num_glyphs, (uint32_t)glyf_sz);
    uint8_t os2[96];       size_t os2_sz  = build_os2(os2);
    uint8_t name[64];      size_t name_sz = build_name(name);
    uint8_t post[32];      size_t post_sz = build_post(post);

    // Build cmap table: header + records + subtable
    size_t cmap_hdr_size = 4 + num_records * 8;
    size_t cmap_total = cmap_hdr_size + subtable_size;
    uint8_t *cmap = calloc(1, cmap_total);
    if (!cmap) return NULL;

    w16(cmap + 0, 0);                             // version
    w16(cmap + 2, (uint16_t)num_records);

    uint32_t subtable_off = (uint32_t)cmap_hdr_size;
    for (int i = 0; i < num_records; i++) {
        uint32_t r = 4 + i * 8;
        w16(cmap + r + 0, records[i].platformID);
        w16(cmap + r + 2, records[i].encodingID);
        w32(cmap + r + 4, subtable_off);
    }
    memcpy(cmap + cmap_hdr_size, cmap_subtable, subtable_size);

    // Table directory
    struct {
        const char *tag;
        const uint8_t *data;
        size_t len;
        uint32_t offset;
    } tables[] = {
        {"OS/2", os2,      os2_sz,  0},
        {"cmap", cmap,     cmap_total, 0},
        {"glyf", glyf_buf, glyf_sz, 0},
        {"head", head,     head_sz, 0},
        {"hhea", hhea,     hhea_sz, 0},
        {"hmtx", hmtx,     hmtx_sz, 0},
        {"loca", loca,     loca_sz, 0},
        {"maxp", maxp,     maxp_sz, 0},
        {"name", name,     name_sz, 0},
        {"post", post,     post_sz, 0},
    };
    int num_tables = 10;

    // Calculate offsets (4-byte aligned)
    uint32_t header_size = 12 + num_tables * 16;
    uint32_t offset = header_size;
    for (int i = 0; i < num_tables; i++) {
        tables[i].offset = offset;
        offset += (uint32_t)tables[i].len;
        while (offset % 4) offset++;
    }

    size_t total = offset;
    uint8_t *font = calloc(1, total);
    if (!font) { free(cmap); free(hmtx); free(loca); return NULL; }

    // Write TrueType offset table
    w32(font + 0, 0x00010000);                    // sfVersion
    w16(font + 4, (uint16_t)num_tables);

    // searchRange, entrySelector, rangeShift
    int power2 = 1, es = 0;
    while (power2 * 2 <= num_tables) { power2 *= 2; es++; }
    w16(font + 6, (uint16_t)(power2 * 16));
    w16(font + 8, (uint16_t)es);
    w16(font + 10, (uint16_t)(num_tables * 16 - power2 * 16));

    // Write table directory entries
    for (int i = 0; i < num_tables; i++) {
        uint32_t entry = 12 + i * 16;
        memcpy(font + entry, tables[i].tag, 4);
        w32(font + entry + 4, tt_checksum(tables[i].data, (uint32_t)tables[i].len));
        w32(font + entry + 8, tables[i].offset);
        w32(font + entry + 12, (uint32_t)tables[i].len);
    }

    // Write table data
    for (int i = 0; i < num_tables; i++) {
        memcpy(font + tables[i].offset, tables[i].data, tables[i].len);
    }

    free(cmap);
    free(hmtx);
    free(loca);
    *out_size = total;
    return font;
}

// =========================================================================
// Font generation for all format x encoding x platform combinations
// =========================================================================

// Target encoding values for truncation testing
static const uint16_t TARGET_ENCODINGS[] = {
    0,        // baseline: valid zero
    1,        // common valid encoding
    3,        // Unicode BMP (standard)
    10,       // Unicode full repertoire
    255,      // max uint8 - boundary
    256,      // 0x100 - CRITICAL: truncates to 0 in uint8
    257,      // 0x101 - truncates to 1 in uint8
    512,      // 0x200 - truncates to 0 in uint8
    768,      // 0x300 - truncates to 0 in uint8
    1024,     // 0x400 - truncates to 0 in uint8
    32767,    // 0x7FFF - max signed int16
    32768,    // 0x8000 - sign flip if treated as int16
    65534,    // 0xFFFE - near max
    65535,    // 0xFFFF - max uint16
};
static const int NUM_ENCODINGS = sizeof(TARGET_ENCODINGS) / sizeof(TARGET_ENCODINGS[0]);

// Target platform IDs
static const uint16_t TARGET_PLATFORMS[] = {
    0,  // Unicode
    1,  // Macintosh
    3,  // Windows
    4,  // Custom (rarely used, may confuse parsers)
};
static const int NUM_PLATFORMS = sizeof(TARGET_PLATFORMS) / sizeof(TARGET_PLATFORMS[0]);

// Format names
static const char *FORMAT_NAMES[] = {
    "fmt0_byte_encoding",
    "fmt2_highbyte_mapping",
    "fmt4_segment_delta",
    "fmt6_trimmed_table",
    "fmt8_mixed_coverage",
    "fmt10_trimmed_array32",
    "fmt12_segmented32",
    "fmt13_manytoone",
    "fmt14_variation_sel",
};

static const uint16_t FORMAT_IDS[] = { 0, 2, 4, 6, 8, 10, 12, 13, 14 };
static const int NUM_FORMATS = 9;

/*
 * Build cmap subtable for a given format ID.
 * Writes to buf (must be large enough), returns size.
 */
static size_t build_subtable_for_format(uint16_t format, uint8_t *buf, size_t buf_size) {
    memset(buf, 0, buf_size);
    switch (format) {
        case 0:  return build_cmap_format0(buf);
        case 2:  return build_cmap_format2(buf);
        case 4:  return build_cmap_format4(buf);
        case 6:  return build_cmap_format6_default(buf);
        case 8:  return build_cmap_format8(buf);
        case 10: return build_cmap_format10(buf);
        case 12: return build_cmap_format12(buf);
        case 13: return build_cmap_format13(buf);
        case 14: return build_cmap_format14(buf);
        default: return 0;
    }
}

// Save font to file
static int save_font(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, size, f);
    fclose(f);
    return 0;
}

// =========================================================================
// Special variant builders for high-value attack combinations
// =========================================================================

/*
 * Format 0 with encoding=256: The 256-byte lookup table is indexed by
 * character code. encoding=256 might cause the lookup to read at index 256
 * (one past the array end).
 */
static uint8_t *build_fmt0_enc256_boundary(size_t *out_size) {
    uint8_t subtable[262];
    size_t st_sz = build_cmap_format0(subtable);
    CmapRecord recs[] = {{0, 256}};
    return assemble_font(subtable, st_sz, recs, 1, 2, out_size);
}

/*
 * Format 2 with encoding=256: High-byte mapping uses subHeaderKeys[256]
 * array indexed by high byte. encoding=256 in the header confuses
 * which subHeader gets selected.
 */
static uint8_t *build_fmt2_enc256_highbyte(size_t *out_size) {
    uint8_t subtable[2048];
    size_t st_sz = build_cmap_format2(subtable);
    CmapRecord recs[] = {{0, 256}, {1, 256}};
    return assemble_font(subtable, st_sz, recs, 2, 256, out_size);
}

/*
 * Format 6 with encoding=256 and entryCount near uint16 max
 * firstCode + entryCount wrap: firstCode=0xFF00, entryCount=0x0200
 * means it covers 0xFF00 to 0x0100 (wrapped) -- potential OOB
 */
static uint8_t *build_fmt6_enc256_wrap(size_t *out_size) {
    // Build format 6 with large entryCount that wraps around
    size_t max_entries = 512;  // manageable but triggers wrap logic
    size_t subtable_sz = 10 + max_entries * 2;
    uint8_t *subtable = calloc(1, subtable_sz);
    if (!subtable) return NULL;

    w16(subtable + 0, 6);                         // format
    w16(subtable + 2, (uint16_t)subtable_sz);     // length
    w16(subtable + 4, 0);                         // language
    w16(subtable + 6, 0xFF00);                    // firstCode (near max)
    w16(subtable + 8, (uint16_t)max_entries);     // entryCount (wraps past 0xFFFF)

    for (size_t i = 0; i < max_entries; i++) {
        w16(subtable + 10 + i * 2, (uint16_t)((i % 254) + 1));
    }

    CmapRecord recs[] = {{0, 256}};
    uint8_t *font = assemble_font(subtable, subtable_sz, recs, 1, 256, out_size);
    free(subtable);
    return font;
}

/*
 * Format 14 with encoding=256: Variation selectors are complex and
 * the newest format - least battle-tested in CoreText
 */
static uint8_t *build_fmt14_enc256_variation(size_t *out_size) {
    uint8_t subtable[256];
    size_t st_sz = build_cmap_format14(subtable);
    // Format 14 MUST be platformID=0, encodingID=5 normally
    // Using encoding=256 is the attack
    CmapRecord recs[] = {{0, 256}};
    return assemble_font(subtable, st_sz, recs, 1, 256, out_size);
}

/*
 * Dual cmap records: one valid (0,3) + one poisoned (0,256)
 * Tests if CoreText picks the wrong record based on encoding priority
 */
static uint8_t *build_dual_record_poison(uint16_t format, size_t *out_size) {
    uint8_t subtable[16384];
    size_t st_sz = build_subtable_for_format(format, subtable, sizeof(subtable));
    if (st_sz == 0) return NULL;

    CmapRecord recs[] = {
        {0, 3},    // valid Unicode BMP
        {0, 256},  // poisoned
        {3, 1},    // Windows Unicode BMP
        {3, 256},  // poisoned Windows
    };
    return assemble_font(subtable, st_sz, recs, 4, 256, out_size);
}

/*
 * Format 2 with malicious subHeaders: entryCount that extends past subHeaderKeys
 */
static uint8_t *build_fmt2_malicious_subheaders(size_t *out_size) {
    // Custom format 2 with idRangeOffset pointing outside table
    size_t total = 6 + 512 + 32 + 1024;  // header + keys + subheaders + large glyphIdArray
    uint8_t *subtable = calloc(1, total);
    if (!subtable) return NULL;

    w16(subtable + 0, 2);
    w16(subtable + 2, (uint16_t)total);
    w16(subtable + 4, 0);

    // subHeaderKeys: route ALL high bytes to different subHeaders
    uint8_t *keys = subtable + 6;
    for (int i = 0; i < 256; i++) {
        // Spread across 4 subHeaders
        w16(keys + i * 2, (uint16_t)((i % 4) * 8));
    }

    // 4 subHeaders at offset 518
    uint8_t *sh = subtable + 518;

    // subHeader 0: normal
    w16(sh + 0, 0); w16(sh + 2, 128); w16(sh + 4, 0); w16(sh + 6, 32);

    // subHeader 1: entryCount=65535 -- massive, will read past table
    w16(sh + 8, 0); w16(sh + 10, 255); w16(sh + 12, 0); w16(sh + 14, 32);

    // subHeader 2: idRangeOffset pointing far outside
    w16(sh + 16, 0); w16(sh + 18, 64); w16(sh + 20, 0); w16(sh + 22, 0xFFF0);

    // subHeader 3: negative idDelta (sign confusion)
    w16(sh + 24, 0); w16(sh + 26, 32); w16(sh + 28, (uint16_t)(int16_t)-256); w16(sh + 30, 32);

    // glyphIdArray
    uint8_t *gids = subtable + 550;
    for (int i = 0; i < 512; i++) {
        w16(gids + i * 2, (uint16_t)((i % 254) + 1));
    }

    CmapRecord recs[] = {{0, 256}, {1, 0}};
    uint8_t *font = assemble_font(subtable, total, recs, 2, 256, out_size);
    free(subtable);
    return font;
}

// =========================================================================
// Main: generate full font matrix
// =========================================================================

int main(int argc, char **argv) {
    const char *outdir = "/tmp/cmap_fuzz";
    if (argc > 1) outdir = argv[1];

    mkdir(outdir, 0755);

    printf("=== cmap Font Builder - Generating Fuzzing Corpus ===\n");
    printf("Output directory: %s\n\n", outdir);

    int total_fonts = 0;
    int failed = 0;

    // Phase 1: Full matrix - format x encoding x platform
    printf("--- Phase 1: Full Matrix (format x encoding x platform) ---\n");
    for (int fi = 0; fi < NUM_FORMATS; fi++) {
        uint16_t format = FORMAT_IDS[fi];
        uint8_t subtable[16384];
        size_t st_sz = build_subtable_for_format(format, subtable, sizeof(subtable));
        if (st_sz == 0) {
            printf("[SKIP] Format %d: builder returned 0\n", format);
            continue;
        }

        for (int ei = 0; ei < NUM_ENCODINGS; ei++) {
            uint16_t enc = TARGET_ENCODINGS[ei];
            for (int pi = 0; pi < NUM_PLATFORMS; pi++) {
                uint16_t plat = TARGET_PLATFORMS[pi];

                CmapRecord recs[] = {{plat, enc}};
                size_t font_size;
                uint8_t *font = assemble_font(subtable, st_sz, recs, 1, 256, &font_size);
                if (!font) {
                    failed++;
                    continue;
                }

                char path[512];
                snprintf(path, sizeof(path), "%s/%s_enc%u_plat%u.ttf",
                         outdir, FORMAT_NAMES[fi], enc, plat);

                if (save_font(path, font, font_size) == 0) {
                    total_fonts++;
                } else {
                    failed++;
                }
                free(font);
            }
        }
        printf("  Format %2d (%s): generated %d variants\n",
               format, FORMAT_NAMES[fi], NUM_ENCODINGS * NUM_PLATFORMS);
    }

    // Phase 2: Special high-value attack fonts
    printf("\n--- Phase 2: Special Attack Fonts ---\n");

    struct {
        const char *name;
        uint8_t *(*builder)(size_t *);
    } specials[] = {
        {"fmt0_enc256_boundary", build_fmt0_enc256_boundary},
        {"fmt2_enc256_highbyte", build_fmt2_enc256_highbyte},
        {"fmt6_enc256_wrap", build_fmt6_enc256_wrap},
        {"fmt14_enc256_variation", build_fmt14_enc256_variation},
        {"fmt2_malicious_subheaders", build_fmt2_malicious_subheaders},
    };
    int num_specials = sizeof(specials) / sizeof(specials[0]);

    for (int i = 0; i < num_specials; i++) {
        size_t sz;
        uint8_t *font = specials[i].builder(&sz);
        if (font) {
            char path[512];
            snprintf(path, sizeof(path), "%s/special_%s.ttf", outdir, specials[i].name);
            if (save_font(path, font, sz) == 0) {
                total_fonts++;
                printf("  [OK] %s (%zu bytes)\n", specials[i].name, sz);
            }
            free(font);
        } else {
            printf("  [FAIL] %s\n", specials[i].name);
            failed++;
        }
    }

    // Phase 3: Dual-record poison fonts for each format
    printf("\n--- Phase 3: Dual-Record Poison Fonts ---\n");
    for (int fi = 0; fi < NUM_FORMATS; fi++) {
        size_t sz;
        uint8_t *font = build_dual_record_poison(FORMAT_IDS[fi], &sz);
        if (font) {
            char path[512];
            snprintf(path, sizeof(path), "%s/dual_poison_%s.ttf",
                     outdir, FORMAT_NAMES[fi]);
            if (save_font(path, font, sz) == 0) {
                total_fonts++;
                printf("  [OK] dual_%s (%zu bytes)\n", FORMAT_NAMES[fi], sz);
            }
            free(font);
        } else {
            printf("  [FAIL] dual_%s\n", FORMAT_NAMES[fi]);
            failed++;
        }
    }

    printf("\n=== SUMMARY ===\n");
    printf("Total fonts generated: %d\n", total_fonts);
    printf("Failures: %d\n", failed);
    printf("Output: %s/\n", outdir);

    return 0;
}
