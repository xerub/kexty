/*
 *  kernel symbol grabber
 *
 *  Copyright (c) 2015, 2016 xerub
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define FOR_SQLITE

#ifdef FOR_SQLITE
#include <sqlite3.h>

struct ctx {
    sqlite3_stmt *stmt;
    unsigned int hash;
};
#endif

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

static size_t align = 0xFFF;

static __inline size_t
round_page(size_t size)
{
    return (size + align) & ~align;
}

/* generic stuff *************************************************************/

#define UCHAR_MAX 255

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

/* kernel stuff **************************************************************/

uint8_t *kernel = MAP_FAILED;
size_t kernel_size = 0;
int kernel_fd = -1;

static int
init_kernel(const char *filename)
{
    kernel_fd = open(filename, O_RDONLY);
    if (kernel_fd < 0) {
        return -1;
    }

    kernel_size = lseek(kernel_fd, 0, SEEK_END);

    kernel = mmap(NULL, kernel_size, PROT_READ, MAP_PRIVATE, kernel_fd, 0);
    if (kernel == MAP_FAILED) {
        close(kernel_fd);
        kernel_fd = -1;
        return -1;
    }

    return 0;
}

static void
term_kernel(void)
{
    munmap(kernel, kernel_size);
    close(kernel_fd);
}

static int
show_syms(size_t offset, int thumbize, int (*callback)(unsigned long long value, const char *symbol, void *opaque), void *opaque)
{
    uint32_t i;
    const uint8_t *p, *q;
    const struct mach_header *hdr;
    size_t eseg, size, next;
    int is64;

again:
#ifndef FOR_SQLITE
    printf("offset = %zx\n", offset);
#endif
    if (offset >= kernel_size - 3) {
        return 0;
    }

    size = 0;
    next = 0;
    p = kernel + offset;
    hdr = (struct mach_header *)p;
    q = p + sizeof(struct mach_header);
    is64 = 0;

    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        is64 = 4;
    }

    q = p + sizeof(struct mach_header) + is64;

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                next = seg->fileoff;
            }
            if (!strcmp(seg->segname, "__PAGEZERO")) {
                goto cont;
            }
            if (seg->vmaddr == 0) {
                eseg = round_page(seg->fileoff + seg->vmsize);
                if (offset + eseg < kernel_size - 3 && *(uint32_t *)(kernel + offset + eseg) != *(uint32_t *)kernel) {
                    align = 0x3FFF; /* promote alignment and hope for the best */
                    eseg = round_page(seg->fileoff + seg->vmsize);
                }
            } else {
                eseg = seg->fileoff + round_page(seg->vmsize);
            }
            if (size < eseg) {
                size = eseg;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                next = seg->fileoff;
            }
            if (!strcmp(seg->segname, "__PAGEZERO")) {
                goto cont;
            }
            if (seg->vmaddr == 0) {
                eseg = round_page(seg->fileoff + seg->vmsize);
                if (offset + eseg < kernel_size - 3 && *(uint32_t *)(kernel + offset + eseg) != *(uint32_t *)kernel) {
                    align = 0x3FFF; /* promote alignment and hope for the best */
                    eseg = round_page(seg->fileoff + seg->vmsize);
                }
            } else {
                eseg = seg->fileoff + round_page(seg->vmsize);
            }
            if (size < eseg) {
                size = eseg;
            }
        }
        if (cmd->cmd == LC_SYMTAB) {
            const struct symtab_command *sym = (struct symtab_command *)q;
            const char *stroff = (const char *)p + sym->stroff;
            if (is64) {
                uint32_t k;
                const struct nlist_64 *s = (struct nlist_64 *)(p + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if (s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR) {
                        if (callback(s[k].n_value, stroff + s[k].n_un.n_strx, opaque)) {
                            return -1;
                        }
                    }
                }
            } else {
                uint32_t k;
                const struct nlist *s = (struct nlist *)(p + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if (s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR) {
                        int thumb = thumbize && (s[k].n_desc & N_ARM_THUMB_DEF);
                        if (callback(s[k].n_value + thumb, stroff + s[k].n_un.n_strx, opaque)) {
                            return -1;
                        }
                    }
                }
            }
        }
        cont: q = q + cmd->cmdsize;
    }

    if (next) {
        return show_syms(next, thumbize, callback, opaque);
    }
    if (size) {
        offset += size;
        goto again;
    }
    return 0;
}


static int
callback(unsigned long long value, const char *symbol, void *opaque)
{
#ifdef FOR_SQLITE
    int rv;
    unsigned int hash = ((struct ctx *)opaque)->hash;
    sqlite3_stmt *stmt = ((struct ctx *)opaque)->stmt;
    printf("INSERT INTO \"Symbols\" VALUES(%u,'%s',%llu);\n", hash, symbol, value);
    rv = sqlite3_reset(stmt);
    if (rv) {
        return -1;
    }
    rv = sqlite3_bind_text(stmt, 2, symbol, strlen(symbol), SQLITE_STATIC);
    if (rv) {
        return -1;
    }
    rv = sqlite3_bind_int64(stmt, 3, value);
    if (rv) {
        return -1;
    }
    rv = sqlite3_step(stmt);
    if (rv != SQLITE_DONE) {
        fprintf(stderr, "sqlite error: %d\n", rv);
        return -1;
    }
    return 0;
#else
    (void)opaque;
    printf("%08llx %s\n", value, symbol);
    return 0;
#endif
}

#ifdef FOR_SQLITE
static unsigned int
djb_hash(const char *key)
{
    unsigned int hash = 5381;

    for (; *key; key++) {
        hash = ((hash << 5) + hash) + (*key);
    }

    return hash;
}

static int
make_db(const char *database, const char *version, int argc, char **argv)
{
    int rv;
    int newdb = 0;
    struct stat st;
    struct ctx ctx;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    unsigned int hash;
    char *str;
    int i;

    rv = stat(database, &st);
    newdb = (rv != 0);

    rv = sqlite3_open(database, &db);
    if (rv) {
        fprintf(stderr, "[e] cannot open database\n");
        return -1;
    }

    hash = djb_hash(version);

    if (newdb) {
        printf("CREATE TABLE Symbols(Kernel int, Symbol varchar(255), Value int);\n");
        rv = sqlite3_exec(db, "CREATE TABLE Symbols(Kernel int, Symbol varchar(255), Value int);", NULL, NULL, &str);
        if (rv) {
            fprintf(stderr, "sqlite error: %s\n", str);
            sqlite3_free(str);
            sqlite3_close(db);
            return -1;
        }
    } else {
        char tmp[256];
        printf("DELETE FROM \"Symbols\" WHERE Kernel=%u;\n", hash);
        snprintf(tmp, sizeof(tmp), "DELETE FROM \"Symbols\" WHERE Kernel=%u;\n", hash);
        rv = sqlite3_exec(db, tmp, NULL, NULL, &str);
        if (rv) {
            fprintf(stderr, "sqlite error: %s\n", str);
            sqlite3_free(str);
            sqlite3_close(db);
            return -1;
        }
    }

    str = "INSERT INTO \"Symbols\" VALUES(?1,?2,?3);";
    rv = sqlite3_prepare_v2(db, str, strlen(str) + 1, &stmt, NULL);
    if (rv) {
        sqlite3_close(db);
        fprintf(stderr, "[e] cannot make statement\n");
        return -1;
    }

    rv = sqlite3_bind_int64(stmt, 1, hash);
    if (rv) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        fprintf(stderr, "[e] cannot bind statement\n");
        return -1;
    }

    rv = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    ctx.stmt = stmt;
    ctx.hash = hash;
    show_syms(0, 1, callback, &ctx);

    for (i = 3; i < argc; i++) {
        unsigned long long v;
        char *p = argv[i];
        char *q = strchr(p, '=');
        if (q) {
            char *rem;
            *q++ = '\0';
            errno = 0;
            v = strtoull(q, &rem, 0);
            if (errno == 0 && *rem == '\0') {
                callback(v, p, &ctx);
                continue;
            }
        }
        fprintf(stderr, "[w] ignoring %s\n", p);
    }

    sqlite3_finalize(stmt);

    rv = sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);
    if (rv) {
        sqlite3_close(db);
        fprintf(stderr, "[e] cannot end transaction\n");
        return -1;
    }

#if 1
    printf("DROP INDEX symbol_index;\n");
    rv = sqlite3_exec(db, "DROP INDEX symbol_index;", NULL, NULL, NULL);
    printf("CREATE INDEX symbol_index on Symbols (Kernel, Symbol);\n");
    rv = sqlite3_exec(db, "CREATE INDEX symbol_index on Symbols (Kernel, Symbol);", NULL, NULL, &str);
    if (rv) {
        fprintf(stderr, "sqlite error: %s\n", str);
        sqlite3_free(str);
    }
#endif

    sqlite3_close(db);
    return 0;
}
#endif

int
main(int argc, char **argv)
{
    int rv;
    const char *version;

    if (argc < 3) {
        fprintf(stderr, "usage: %s kernel database [sym=value...]\n", argv[0]);
        return 1;
    }

    rv = init_kernel(argv[1]);
    if (rv) {
        fprintf(stderr, "[e] cannot read kernel\n");
        return -1;
    }
    version = (char *)boyermoore_horspool_memmem(kernel, kernel_size, (uint8_t *)"Darwin Kernel Version", sizeof("Darwin Kernel Version") - 1);
    if (!version) {
        fprintf(stderr, "[e] cannot find version\n");
        term_kernel();
        return -1;
    }

#ifdef FOR_SQLITE
    make_db(argv[2], version, argc, argv);
#else
    printf("%s\n", version);
    show_syms(0, 1, callback, (void *)version);
#endif

    term_kernel();
    return 0;
}
