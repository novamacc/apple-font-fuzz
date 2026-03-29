/*
 * standalone_harness.c - Standalone fuzzing harness for when libFuzzer is unavailable
 *
 * Reads corpus files, applies random mutations, and calls LLVMFuzzerTestOneInput
 * in a loop. Used as a fallback on CI runners (e.g., GitHub Actions macOS)
 * where libclang_rt.fuzzer_osx.a is not shipped with Xcode.
 *
 * Build: clang -fsanitize=address,undefined standalone_harness.c fuzz_target.m -o fuzzer
 * Run:   ./fuzzer corpus/ -max_total_time=18000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

static volatile int g_running = 1;

static void alarm_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void term_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Count non-hidden files in directory */
static int count_files(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') count++;
    }
    closedir(d);
    return count;
}

/* Pick a random file from directory, return path in buf */
static int pick_random_file(const char *dirpath, char *buf, size_t bufsz) {
    DIR *d = opendir(dirpath);
    if (!d) return -1;

    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') count++;
    }
    if (count == 0) { closedir(d); return -1; }

    int target = rand() % count;
    rewinddir(d);
    int idx = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (idx == target) {
            snprintf(buf, bufsz, "%s/%s", dirpath, ent->d_name);
            closedir(d);
            return 0;
        }
        idx++;
    }
    closedir(d);
    return -1;
}

/* Read file into buffer, return size */
static size_t read_file(const char *path, unsigned char **out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);

    /* Allocate extra space for mutations */
    *out = (unsigned char *)malloc((size_t)sz + 512);
    if (!*out) { fclose(f); return 0; }
    size_t rd = fread(*out, 1, (size_t)sz, f);
    fclose(f);
    return rd;
}

/* Apply random mutations to buffer */
static size_t mutate(unsigned char *buf, size_t size, size_t capacity) {
    int num_mutations = 1 + rand() % 8;
    size_t cur_size = size;

    for (int i = 0; i < num_mutations && cur_size > 0; i++) {
        int op = rand() % 6;
        switch (op) {
            case 0: /* bit flip */
                buf[rand() % cur_size] ^= (1 << (rand() % 8));
                break;
            case 1: /* byte replace */
                buf[rand() % cur_size] = (unsigned char)(rand() % 256);
                break;
            case 2: /* byte insert */
                if (cur_size < capacity - 1) {
                    size_t pos = rand() % (cur_size + 1);
                    memmove(buf + pos + 1, buf + pos, cur_size - pos);
                    buf[pos] = (unsigned char)(rand() % 256);
                    cur_size++;
                }
                break;
            case 3: /* byte delete */
                if (cur_size > 1) {
                    size_t pos = rand() % cur_size;
                    memmove(buf + pos, buf + pos + 1, cur_size - pos - 1);
                    cur_size--;
                }
                break;
            case 4: /* overwrite chunk with interesting values */
                if (cur_size >= 4) {
                    size_t pos = rand() % (cur_size - 3);
                    uint32_t interesting[] = {0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
                    uint32_t val = interesting[rand() % 12];
                    memcpy(buf + pos, &val, 4);
                }
                break;
            case 5: /* copy chunk within buffer */
                if (cur_size >= 4) {
                    size_t src = rand() % (cur_size - 2);
                    size_t dst = rand() % (cur_size - 2);
                    size_t len = 1 + rand() % (cur_size / 4 + 1);
                    if (src + len > cur_size) len = cur_size - src;
                    if (dst + len > cur_size) len = cur_size - dst;
                    memmove(buf + dst, buf + src, len);
                }
                break;
        }
    }
    return cur_size;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s corpus_dir/ [-max_total_time=N] [-max_len=N] [-timeout=N]\n", argv[0]);
        fprintf(stderr, "Standalone fuzzing harness (libFuzzer fallback)\n");
        return 1;
    }

    const char *corpus_dir = argv[1];
    int max_time = 18000; /* 5 hours default */
    size_t max_len = 65536;

    /* Parse libFuzzer-compatible flags (ignore ones we don't support) */
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "-max_total_time=", 16) == 0)
            max_time = atoi(argv[i] + 16);
        else if (strncmp(argv[i], "-max_len=", 9) == 0)
            max_len = (size_t)atoi(argv[i] + 9);
        else if (strncmp(argv[i], "-timeout=", 9) == 0)
            ; /* per-input timeout - handled by ASAN */
        else if (strncmp(argv[i], "-rss_limit_mb=", 14) == 0)
            ; /* RSS limit - handled by ASAN */
        else if (strncmp(argv[i], "-jobs=", 6) == 0)
            ; /* parallel jobs - not supported in standalone */
        else if (strncmp(argv[i], "-workers=", 9) == 0)
            ; /* workers - not supported in standalone */
        else if (strncmp(argv[i], "-artifact_prefix=", 17) == 0)
            ; /* crash output dir - crashes go to ASAN stderr */
        else if (strncmp(argv[i], "-print_final_stats=", 19) == 0)
            ; /* stats flag */
        /* Silently ignore unknown flags for compatibility */
    }

    /* Verify corpus directory exists */
    struct stat st;
    if (stat(corpus_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a valid directory\n", corpus_dir);
        return 1;
    }

    int corpus_count = count_files(corpus_dir);
    if (corpus_count == 0) {
        fprintf(stderr, "Error: corpus directory '%s' is empty\n", corpus_dir);
        return 1;
    }

    /* Set up signal handlers */
    signal(SIGALRM, alarm_handler);
    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);
    alarm(max_time);

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    printf("=== Standalone Fuzzing Harness ===\n");
    printf("Corpus: %s (%d files)\n", corpus_dir, corpus_count);
    printf("Max time: %ds, Max len: %zu\n", max_time, max_len);
    printf("Starting fuzzing loop...\n\n");

    long iterations = 0;
    long crashes_caught = 0;
    time_t start = time(NULL);

    /* First pass: feed all corpus files unmutated */
    DIR *d = opendir(corpus_dir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL && g_running) {
            if (ent->d_name[0] == '.') continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", corpus_dir, ent->d_name);
            unsigned char *buf = NULL;
            size_t sz = read_file(path, &buf);
            if (buf && sz > 0) {
                if (sz > max_len) sz = max_len;
                LLVMFuzzerTestOneInput(buf, sz);
                iterations++;
            }
            free(buf);
        }
        closedir(d);
    }
    printf("[%lds] Corpus pass done: %ld files tested\n", time(NULL) - start, iterations);

    /* Main mutation loop */
    while (g_running) {
        char path[1024];
        if (pick_random_file(corpus_dir, path, sizeof(path)) != 0) break;

        unsigned char *buf = NULL;
        size_t sz = read_file(path, &buf);
        if (!buf || sz == 0) { free(buf); continue; }

        size_t capacity = sz + 512;
        if (capacity > max_len + 512) capacity = max_len + 512;

        /* Apply mutations */
        size_t mutated_sz = mutate(buf, sz, capacity);
        if (mutated_sz > max_len) mutated_sz = max_len;

        LLVMFuzzerTestOneInput(buf, mutated_sz);
        free(buf);
        iterations++;

        if (iterations % 10000 == 0) {
            time_t elapsed = time(NULL) - start;
            long rate = elapsed > 0 ? iterations / elapsed : iterations;
            printf("[%lds] %ld iterations (%ld/s), %d corpus files\n",
                   elapsed, iterations, rate, corpus_count);
            fflush(stdout);
        }
    }

    time_t elapsed = time(NULL) - start;
    printf("\n=== Fuzzing Complete ===\n");
    printf("Total iterations: %ld\n", iterations);
    printf("Duration: %lds\n", elapsed);
    if (elapsed > 0)
        printf("Speed: %ld iterations/sec\n", iterations / elapsed);

    return 0;
}
