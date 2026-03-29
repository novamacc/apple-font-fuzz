/*
 * fuzz_coretext.m — God-Level CoreText Font Table Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: CoreText + CoreGraphics font parsing
 *
 * WHY FONTS ARE A TOP ZERO-CLICK VECTOR:
 *   - Safari/WebKit auto-loads web fonts (zero-click via CSS @font-face)
 *   - Mail renders HTML email with custom fonts (zero-click)
 *   - Messages renders rich text with fonts (zero-click)
 *   - iOS SpringBoard renders notification text with embedded fonts
 *   - CoreText runs IN-PROCESS — crash = code execution opportunity
 *   - Google P0 found dozens of font CVEs in Apple's CoreText
 *   - Our morx exploit (Tool #7) confirmed OOB read already
 *
 * We fuzz by constructing minimal TrueType/OpenType fonts with
 * mutated table data and forcing CoreText to fully process them:
 *   - Font creation (CGFont + CTFont)
 *   - Glyph lookup (cmap)
 *   - Glyph metrics (hhea, hmtx, vhea, vmtx)
 *   - Outline rendering (glyf, loca, CFF)
 *   - Text shaping (morx, kerx, GSUB, GPOS, kern)
 *   - Name table parsing
 *   - Full text layout via CTLine
 *
 * FUZZING STRATEGY:
 *   Fuzz data replaces individual font tables in a valid TrueType font.
 *   This lets the fuzzer focus mutations on one table at a time while
 *   keeping the rest of the font valid enough to parse.
 *
 * Build:
 *   clang -framework Foundation -framework CoreText \
 *         -framework CoreGraphics -framework CoreFoundation \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_coretext fuzz_coretext.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <string.h>

#pragma mark - Minimal TrueType Font Builder

/*
 * Build a minimal valid TrueType font with the specified
 * table replaced by fuzz data. The font has:
 *   - head, hhea, maxp, OS/2, name, cmap, post, glyf, loca
 *   - One glyph (space) at GID 0
 *
 * The target_tag table gets replaced with fuzz data.
 */

/* Minimal head table (54 bytes) */
static const uint8_t g_head[] = {
    0x00,0x01,0x00,0x00, /* version 1.0 */
    0x00,0x01,0x00,0x00, /* fontRevision */
    0x00,0x00,0x00,0x00, /* checksumAdjustment (placeholder) */
    0x5F,0x0F,0x3C,0xF5, /* magicNumber */
    0x00,0x0B,            /* flags */
    0x04,0x00,            /* unitsPerEm = 1024 */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* created */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* modified */
    0x00,0x00,            /* xMin */
    0x00,0x00,            /* yMin */
    0x04,0x00,            /* xMax = 1024 */
    0x04,0x00,            /* yMax = 1024 */
    0x00,0x00,            /* macStyle */
    0x00,0x08,            /* lowestRecPPEM = 8 */
    0x00,0x02,            /* fontDirectionHint */
    0x00,0x01,            /* indexToLocFormat = 1 (long) */
    0x00,0x00,            /* glyphDataFormat */
};

/* Minimal hhea table (36 bytes) */
static const uint8_t g_hhea[] = {
    0x00,0x01,0x00,0x00, /* version */
    0x03,0x20,            /* ascender = 800 */
    0xFE,0xC0,            /* descender = -320 */
    0x00,0x00,            /* lineGap */
    0x04,0x00,            /* advanceWidthMax = 1024 */
    0x00,0x00,            /* minLeftSideBearing */
    0x00,0x00,            /* minRightSideBearing */
    0x04,0x00,            /* xMaxExtent = 1024 */
    0x00,0x01,            /* caretSlopeRise */
    0x00,0x00,            /* caretSlopeRun */
    0x00,0x00,            /* caretOffset */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* reserved */
    0x00,0x00,            /* metricDataFormat */
    0x00,0x01,            /* numHMetrics = 1 */
};

/* Minimal maxp table (32 bytes) */
static const uint8_t g_maxp[] = {
    0x00,0x01,0x00,0x00, /* version */
    0x00,0x01,            /* numGlyphs = 1 */
    0x00,0x40,            /* maxPoints */
    0x00,0x01,            /* maxContours */
    0x00,0x00,            /* maxCompositePoints */
    0x00,0x00,            /* maxCompositeContours */
    0x00,0x01,            /* maxZones */
    0x00,0x00,            /* maxTwilightPoints */
    0x00,0x01,            /* maxStorage */
    0x00,0x01,            /* maxFunctionDefs */
    0x00,0x01,            /* maxInstructionDefs */
    0x00,0x01,            /* maxStackElements */
    0x00,0x00,            /* maxSizeOfInstructions */
    0x00,0x00,            /* maxComponentElements */
    0x00,0x00,            /* maxComponentDepth */
};

/* Minimal hmtx: 1 entry (4 bytes) */
static const uint8_t g_hmtx[] = {
    0x02,0x00,            /* advanceWidth = 512 */
    0x00,0x00,            /* leftSideBearing = 0 */
};

/* Format 4 cmap: maps U+0020 (space) to GID 0 */
static const uint8_t g_cmap[] = {
    0x00,0x00,            /* version */
    0x00,0x01,            /* numTables = 1 */
    0x00,0x03,            /* platformID = Windows */
    0x00,0x01,            /* encodingID = Unicode BMP */
    0x00,0x00,0x00,0x0C, /* offset to subtable */
    /* Format 4 subtable */
    0x00,0x04,            /* format = 4 */
    0x00,0x20,            /* length = 32 */
    0x00,0x00,            /* language */
    0x00,0x04,            /* segCountX2 = 4 (2 segments) */
    0x00,0x04,            /* searchRange */
    0x00,0x01,            /* entrySelector */
    0x00,0x00,            /* rangeShift */
    0x00,0x20,            /* endCode[0] = 0x0020 */
    0xFF,0xFF,            /* endCode[1] = 0xFFFF */
    0x00,0x00,            /* reservedPad */
    0x00,0x20,            /* startCode[0] = 0x0020 */
    0xFF,0xFF,            /* startCode[1] = 0xFFFF */
    0x00,0x00,            /* idDelta[0] = 0 */
    0x00,0x01,            /* idDelta[1] */
    0x00,0x00,            /* idRangeOffset[0] */
    0x00,0x00,            /* idRangeOffset[1] */
};

/* Minimal name table */
static const uint8_t g_name[] = {
    0x00,0x00,            /* format */
    0x00,0x01,            /* count = 1 */
    0x00,0x12,            /* stringOffset */
    /* record 0: family name */
    0x00,0x03,            /* platformID = Windows */
    0x00,0x01,            /* encodingID */
    0x04,0x09,            /* languageID */
    0x00,0x01,            /* nameID = Font Family */
    0x00,0x08,            /* length = 8 */
    0x00,0x00,            /* offset */
    /* string data: "Fuzz" in UTF-16BE */
    0x00,0x46, 0x00,0x75, 0x00,0x7A, 0x00,0x7A
};

/* Minimal post table */
static const uint8_t g_post[] = {
    0x00,0x03,0x00,0x00, /* format 3.0 (no glyph names) */
    0x00,0x00,0x00,0x00, /* italicAngle */
    0xFE,0xC0,            /* underlinePosition */
    0x00,0x50,            /* underlineThickness */
    0x00,0x00,0x00,0x00, /* isFixedPitch */
    0x00,0x00,0x00,0x00, /* minMemType42 */
    0x00,0x00,0x00,0x00, /* maxMemType42 */
    0x00,0x00,0x00,0x00, /* minMemType1 */
    0x00,0x00,0x00,0x00, /* maxMemType1 */
};

/* Minimal glyf table: one empty glyph */
static const uint8_t g_glyf[] = {
    0x00,0x00,            /* numberOfContours = 0 (empty) */
    0x00,0x00,            /* xMin */
    0x00,0x00,            /* yMin */
    0x02,0x00,            /* xMax = 512 */
    0x02,0x00,            /* yMax = 512 */
};

/* Minimal loca table (long format): 2 entries for 1 glyph */
static const uint8_t g_loca[] = {
    0x00,0x00,0x00,0x00, /* offset of glyph 0 */
    0x00,0x00,0x00,0x0A, /* offset after glyph 0 (= glyf length) */
};

/* OS/2 table (78 bytes, version 1) */
static const uint8_t g_os2[] = {
    0x00,0x01,            /* version */
    0x02,0x00,            /* xAvgCharWidth = 512 */
    0x01,0x90,            /* usWeightClass = 400 */
    0x00,0x05,            /* usWidthClass = 5 */
    0x00,0x00,            /* fsType */
    0x00,0x64,            /* ySubscriptXSize */
    0x00,0x64,            /* ySubscriptYSize */
    0x00,0x00,            /* ySubscriptXOffset */
    0x00,0x32,            /* ySubscriptYOffset */
    0x00,0x64,            /* ySuperscriptXSize */
    0x00,0x64,            /* ySuperscriptYSize */
    0x00,0x00,            /* ySuperscriptXOffset */
    0x00,0x32,            /* ySuperscriptYOffset */
    0x00,0x10,            /* yStrikeoutSize */
    0x01,0x2C,            /* yStrikeoutPosition */
    0x00,0x00,            /* sFamilyClass */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* panose */
    0x00,0x00,0x00,0x01, /* ulUnicodeRange1 */
    0x00,0x00,0x00,0x00, /* ulUnicodeRange2 */
    0x00,0x00,0x00,0x00, /* ulUnicodeRange3 */
    0x00,0x00,0x00,0x00, /* ulUnicodeRange4 */
    0x00,0x00,0x00,0x00, /* achVendID */
    0x00,0x40,            /* fsSelection */
    0x00,0x20,            /* usFirstCharIndex */
    0x00,0x20,            /* usLastCharIndex */
    0x03,0x20,            /* sTypoAscender */
    0xFE,0xC0,            /* sTypoDescender */
    0x00,0x00,            /* sTypoLineGap */
    0x04,0x00,            /* usWinAscent */
    0x01,0x40,            /* usWinDescent */
    0x00,0x00,0x00,0x01, /* ulCodePageRange1 */
    0x00,0x00,0x00,0x00, /* ulCodePageRange2 */
};

/* Table tags we can target (FourCharCode) */
#define TAG(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(d))

typedef struct {
    uint32_t tag;
    const uint8_t *data;
    uint32_t len;
} TableEntry;

static uint32_t calc_checksum(const uint8_t *data, uint32_t len) {
    uint32_t sum = 0;
    uint32_t nLongs = (len + 3) / 4;
    for (uint32_t i = 0; i < nLongs; i++) {
        uint32_t val = 0;
        for (int j = 0; j < 4; j++) {
            val <<= 8;
            size_t idx = i * 4 + j;
            if (idx < len) val |= data[idx];
        }
        sum += val;
    }
    return sum;
}

static NSData *build_font_with_table(uint32_t target_tag,
                                      const uint8_t *fuzz_data,
                                      size_t fuzz_len) {
    /* Define all tables */
    TableEntry tables[] = {
        {TAG('c','m','a','p'), g_cmap, sizeof(g_cmap)},
        {TAG('g','l','y','f'), g_glyf, sizeof(g_glyf)},
        {TAG('h','e','a','d'), g_head, sizeof(g_head)},
        {TAG('h','h','e','a'), g_hhea, sizeof(g_hhea)},
        {TAG('h','m','t','x'), g_hmtx, sizeof(g_hmtx)},
        {TAG('l','o','c','a'), g_loca, sizeof(g_loca)},
        {TAG('m','a','x','p'), g_maxp, sizeof(g_maxp)},
        {TAG('n','a','m','e'), g_name, sizeof(g_name)},
        {TAG('O','S','/','2'), g_os2,  sizeof(g_os2)},
        {TAG('p','o','s','t'), g_post, sizeof(g_post)},
    };
    int numTables = sizeof(tables) / sizeof(tables[0]);

    /* Replace target table with fuzz data */
    int hasTarget = 0;
    for (int i = 0; i < numTables; i++) {
        if (tables[i].tag == target_tag) {
            tables[i].data = fuzz_data;
            tables[i].len = (uint32_t)fuzz_len;
            hasTarget = 1;
            break;
        }
    }

    /* If target tag is not in base tables, add it */
    TableEntry extraTable;
    if (!hasTarget) {
        extraTable.tag = target_tag;
        extraTable.data = fuzz_data;
        extraTable.len = (uint32_t)fuzz_len;
        numTables++; /* We'll handle this separately */
    }

    int totalTables = numTables;

    /* Sort tables by tag for binary search */
    /* (skipping sort for fuzzing — CoreText handles unsorted) */

    /* Calculate offsets */
    uint32_t headerSize = 12 + totalTables * 16;
    uint32_t offset = headerSize;
    /* Align to 4 bytes */
    if (offset % 4) offset += 4 - (offset % 4);

    NSMutableData *font = [NSMutableData dataWithLength:offset];
    uint8_t *buf = (uint8_t *)font.mutableBytes;

    /* sfnt header */
    uint32_t scalerType = 0x00010000; /* TrueType */
    buf[0] = (scalerType >> 24); buf[1] = (scalerType >> 16);
    buf[2] = (scalerType >> 8);  buf[3] = scalerType;
    buf[4] = (totalTables >> 8); buf[5] = totalTables;

    /* searchRange, entrySelector, rangeShift */
    int entrySelector = 0;
    int searchRange = 1;
    while (searchRange * 2 <= totalTables) {
        searchRange *= 2;
        entrySelector++;
    }
    searchRange *= 16;
    int rangeShift = totalTables * 16 - searchRange;
    buf[6] = (searchRange >> 8); buf[7] = searchRange;
    buf[8] = (entrySelector >> 8); buf[9] = entrySelector;
    buf[10] = (rangeShift >> 8); buf[11] = rangeShift;

    /* Table directory */
    int dirOff = 12;
    for (int i = 0; i < (hasTarget ? numTables : numTables - 1); i++) {
        TableEntry *t = &tables[i];
        uint32_t padLen = (t->len + 3) & ~3;

        /* Tag */
        buf[dirOff] = (t->tag >> 24); buf[dirOff+1] = (t->tag >> 16);
        buf[dirOff+2] = (t->tag >> 8); buf[dirOff+3] = t->tag;
        /* Checksum */
        uint32_t cs = calc_checksum(t->data, t->len);
        buf[dirOff+4] = (cs >> 24); buf[dirOff+5] = (cs >> 16);
        buf[dirOff+6] = (cs >> 8);  buf[dirOff+7] = cs;
        /* Offset */
        buf[dirOff+8] = (offset >> 24); buf[dirOff+9] = (offset >> 16);
        buf[dirOff+10] = (offset >> 8); buf[dirOff+11] = offset;
        /* Length */
        buf[dirOff+12] = (t->len >> 24); buf[dirOff+13] = (t->len >> 16);
        buf[dirOff+14] = (t->len >> 8);  buf[dirOff+15] = t->len;

        /* Append table data */
        [font increaseLengthBy:padLen];
        buf = (uint8_t *)font.mutableBytes;
        memcpy(buf + offset, t->data, t->len);

        offset += padLen;
        dirOff += 16;
    }

    /* Extra table if needed */
    if (!hasTarget) {
        TableEntry *t = &extraTable;
        uint32_t padLen = (t->len + 3) & ~3;

        buf[dirOff] = (t->tag >> 24); buf[dirOff+1] = (t->tag >> 16);
        buf[dirOff+2] = (t->tag >> 8); buf[dirOff+3] = t->tag;
        uint32_t cs = calc_checksum(t->data, t->len);
        buf[dirOff+4] = (cs >> 24); buf[dirOff+5] = (cs >> 16);
        buf[dirOff+6] = (cs >> 8);  buf[dirOff+7] = cs;
        buf[dirOff+8] = (offset >> 24); buf[dirOff+9] = (offset >> 16);
        buf[dirOff+10] = (offset >> 8); buf[dirOff+11] = offset;
        buf[dirOff+12] = (t->len >> 24); buf[dirOff+13] = (t->len >> 16);
        buf[dirOff+14] = (t->len >> 8);  buf[dirOff+15] = t->len;

        [font increaseLengthBy:padLen];
        buf = (uint8_t *)font.mutableBytes;
        memcpy(buf + offset, t->data, t->len);
    }

    return font;
}

#pragma mark - Font Exercise Functions

/*
 * Create a CTFont from raw data and exercise CoreText parsing.
 */
static void exercise_font(NSData *fontData) {
    CGDataProviderRef provider = CGDataProviderCreateWithCFData(
        (__bridge CFDataRef)fontData);
    if (!provider) return;

    CGFontRef cgFont = CGFontCreateWithDataProvider(provider);
    CGDataProviderRelease(provider);
    if (!cgFont) return;

    /* Create CTFont from CGFont */
    CTFontRef ctFont = CTFontCreateWithGraphicsFont(cgFont, 16.0, NULL, NULL);
    if (!ctFont) {
        CGFontRelease(cgFont);
        return;
    }

    /* === Exercise font metrics === */
    (void)CTFontGetAscent(ctFont);
    (void)CTFontGetDescent(ctFont);
    (void)CTFontGetLeading(ctFont);
    (void)CTFontGetUnitsPerEm(ctFont);
    (void)CTFontGetCapHeight(ctFont);
    (void)CTFontGetXHeight(ctFont);
    (void)CTFontGetUnderlinePosition(ctFont);
    (void)CTFontGetUnderlineThickness(ctFont);
    (void)CTFontGetBoundingBox(ctFont);

    /* === Exercise glyph lookup (cmap) === */
    UniChar chars[] = {'A', 'B', 'z', ' ', '!', 0x00E9, 0x4E2D};
    CGGlyph glyphs[7];
    CTFontGetGlyphsForCharacters(ctFont, chars, glyphs, 7);

    /* === Exercise glyph metrics === */
    for (int i = 0; i < 7; i++) {
        if (glyphs[i] != 0) {
            CGSize advance;
            CTFontGetAdvancesForGlyphs(ctFont, kCTFontOrientationDefault,
                                        &glyphs[i], &advance, 1);
            CGRect bbox;
            CTFontGetBoundingRectsForGlyphs(ctFont, kCTFontOrientationDefault,
                                             &glyphs[i], &bbox, 1);
        }
    }

    /* === Exercise text layout (shaping: morx/kerx/GSUB/GPOS) === */
    NSDictionary *attrs = @{
        (__bridge NSString *)kCTFontAttributeName: (__bridge id)ctFont,
    };
    NSAttributedString *attrStr = [[NSAttributedString alloc]
        initWithString:@"ABCDefgh 12345 Test!"
        attributes:attrs];
    CTLineRef line = CTLineCreateWithAttributedString(
        (__bridge CFAttributedStringRef)attrStr);
    if (line) {
        /* Get line metrics */
        CGFloat ascent, descent, leading;
        double width = CTLineGetTypographicBounds(line, &ascent, &descent, &leading);
        (void)width;

        /* Get glyph runs */
        CFArrayRef runs = CTLineGetGlyphRuns(line);
        if (runs) {
            CFIndex runCount = CFArrayGetCount(runs);
            for (CFIndex r = 0; r < runCount && r < 10; r++) {
                CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, r);
                CFIndex glyphCount = CTRunGetGlyphCount(run);
                if (glyphCount > 0 && glyphCount < 1000) {
                    CGGlyph *runGlyphs = malloc(glyphCount * sizeof(CGGlyph));
                    CGPoint *positions = malloc(glyphCount * sizeof(CGPoint));
                    if (runGlyphs && positions) {
                        CTRunGetGlyphs(run, CFRangeMake(0, 0), runGlyphs);
                        CTRunGetPositions(run, CFRangeMake(0, 0), positions);
                    }
                    free(runGlyphs);
                    free(positions);
                }
            }
        }
        CFRelease(line);
    }

    /* === Exercise name table === */
    CFStringRef familyName = CTFontCopyFamilyName(ctFont);
    if (familyName) CFRelease(familyName);
    CFStringRef fullName = CTFontCopyFullName(ctFont);
    if (fullName) CFRelease(fullName);
    CFStringRef psName = CTFontCopyPostScriptName(ctFont);
    if (psName) CFRelease(psName);

    /* === Exercise font tables === */
    CFArrayRef tags = CTFontCopyAvailableTables(ctFont, kCTFontTableOptionNoOptions);
    if (tags) {
        CFIndex count = CFArrayGetCount(tags);
        for (CFIndex i = 0; i < count && i < 50; i++) {
            CTFontTableTag tag = (CTFontTableTag)(uintptr_t)
                CFArrayGetValueAtIndex(tags, i);
            CFDataRef tableData = CTFontCopyTable(ctFont, tag,
                kCTFontTableOptionNoOptions);
            if (tableData) {
                (void)CFDataGetLength(tableData);
                CFRelease(tableData);
            }
        }
        CFRelease(tags);
    }

    CFRelease(ctFont);
    CGFontRelease(cgFont);
}

#pragma mark - Fuzzer Entry Point

/*
 * Input structure:
 *   byte 0:       table selector (which table to fuzz)
 *   bytes 1+:     fuzz data (replaces selected table)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    @autoreleasepool {
        uint8_t tableIdx = data[0];
        const uint8_t *fuzz = data + 1;
        size_t fsize = size - 1;

        /* Select which table to replace with fuzz data */
        /* NOTE: cmap timeout bug already confirmed - skip it */
        uint32_t target_tag;
        switch (tableIdx % 13) {
            case 0:  target_tag = TAG('g','l','y','f'); break; /* Glyph outlines */
            case 1:  target_tag = TAG('l','o','c','a'); break; /* Glyph locations */
            case 2:  target_tag = TAG('h','e','a','d'); break; /* Font header */
            case 3:  target_tag = TAG('h','h','e','a'); break; /* Horizontal header */
            case 4:  target_tag = TAG('h','m','t','x'); break; /* Horizontal metrics */
            case 5:  target_tag = TAG('m','a','x','p'); break; /* Maximum profile */
            case 6:  target_tag = TAG('n','a','m','e'); break; /* Naming table */
            case 7:  target_tag = TAG('p','o','s','t'); break; /* PostScript */
            case 8:  target_tag = TAG('m','o','r','x'); break; /* Extended morph (AAT) */
            case 9:  target_tag = TAG('k','e','r','n'); break; /* Kerning */
            case 10: target_tag = TAG('k','e','r','x'); break; /* Extended kerning */
            case 11: target_tag = TAG('G','S','U','B'); break; /* Glyph substitution */
            case 12: target_tag = TAG('G','P','O','S'); break; /* Glyph positioning */
        }

        NSData *fontData = build_font_with_table(target_tag, fuzz, fsize);
        if (fontData && fontData.length > 0) {
            exercise_font(fontData);
        }
    }

    return 0;
}
