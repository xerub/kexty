/*
 *  kext loader
 *
 *  Copyright (c) 2015, 2016 xerub
 */

#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/fat.h>
#include "kdb.h"
#include "kdb.c"

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#include <IOKit/IOKitLib.h>
#undef round_page
#define HOST_KERNEL_PORT 4
#endif

//#define MY_LOGGER	// debugging stuff for 32bit (7.x, maybe 8.x...)
#define MY_LOGGER_SIZE	(64 * 1024)

typedef unsigned long long addr_t;

struct dependency {
    uint8_t *buf;
    size_t size;
    addr_t base;
    const char *name;
};

#define round_page(size) ((size + 0xFFF) & ~0xFFF)

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

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

static void *
mempcpy(void *dest, const void *src, size_t n)
{
    return (char *)memmove(dest, src, n) + n;
}

static char *
read_file(const char *filename, size_t *sz)
{
    int rv;
    int fd;
    char *buf;
    struct stat st;
    *sz = 0;
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    rv = fstat(fd, &st);
    if (rv) {
        close(fd);
        return NULL;
    }
    buf = malloc(st.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    *sz = read(fd, buf, st.st_size);
    close(fd);
    if (*sz != (size_t)st.st_size) {
        free(buf);
        return NULL;
    }
    buf[*sz] = '\0';
    return buf;
}

/* xml stuff *****************************************************************/

static char *
xml_newval(const char *key, const char *value, char *buf, size_t *sz, int type)
{
    char *p;
    char *ptr, *tmp;
    const char *tag, *endtag;
    size_t newsize;

    p = strstr(buf, "<dict>");	/* first <dict> tag */
    assert(p);

    switch (type) {
        case 0:
            tag = "<string>";
            endtag = "</string>";
            break;
        case 1:
            tag = "<integer>";
            endtag = "</integer>";
            break;
        case 2:
            tag = "<integer size=\"64\">";
            endtag = "</integer>";
            break;
        default:
            assert(0);
    }

    p += sizeof("<dict>") - 1;

    newsize = *sz + 15 + strlen(key) + strlen(tag) + strlen(value) + strlen(endtag);

    ptr = malloc(newsize + 1);
    assert(ptr);

    tmp = mempcpy(ptr, buf, p - buf);
    *tmp++ = '\n';
    *tmp++ = '\t';
    tmp = mempcpy(tmp, "<key>", 5);
    tmp = mempcpy(tmp, key, strlen(key));
    tmp = mempcpy(tmp, "</key>", 6);
    *tmp++ = '\n';
    *tmp++ = '\t';
    tmp = stpcpy(tmp, tag);
    tmp = stpcpy(tmp, value);
    tmp = stpcpy(tmp, endtag);
    tmp = memcpy(tmp, p, *sz - (p - buf) + 1);

    free(buf);
    buf = ptr;

    *sz = newsize;
    return buf;
}

static char *
xml_setval(const char *key, const char *value, char *buf, size_t *sz, int type)
{
    char *p, *q;
    char *ptr, *tmp;
    size_t oldlen, newlen;

    p = strstr(buf, key);	/* find key */
    if (!p) {
        return xml_newval(key, value, buf, sz, type);
    }
    p = strchr(p, '>');		/* end of key tag */
    assert(p);
    p = strchr(p + 1, '>');	/* end of value tag */
    assert(p);

    for (q = p; q > buf && isspace(q[-1]); q--) {
        continue;
    }
    if (q[-1] == '/') {
        char *tag, *endtag;
        for (tag = q; tag > buf && tag[-1] != '<'; tag--) {
            continue;
        }
        while (isspace(*tag)) {
            tag++;
        }
        endtag = tag;
        while (!isspace(*endtag) && endtag < q - 1) {
            endtag++;
        }

        q[-1] = '>';

        newlen = strlen(value);
        ptr = malloc((q - buf) + newlen + (endtag - tag) + *sz - (p - buf) + 3);
        assert(ptr);

        tmp = mempcpy(ptr, buf, q - buf);
        tmp = mempcpy(tmp, value, newlen);
        tmp = mempcpy(tmp, "</", 2);
        tmp = mempcpy(tmp, tag, endtag - tag);
        tmp = mempcpy(tmp, ">", 1);
        tmp = memcpy(tmp, p + 1, *sz - (p - buf));
        free(buf);
        *sz = (q - buf) + newlen + (endtag - tag) + *sz - (p - buf) + 2;
        return ptr;
    }

    p++;
    q = strchr(p, '<');

    oldlen = q - p;
    newlen = strlen(value);
    if (oldlen >= newlen) {
        /* can use old block */
        memcpy(p, value, newlen);
        memmove(p + newlen, q, *sz - (q - buf) + 1);
    } else {
        /* we need a new block */
        ptr = malloc(*sz - oldlen + newlen + 1);
        assert(ptr);
        memcpy(ptr, buf, p - buf);
        memcpy(ptr + (p - buf), value, newlen);
        memcpy(ptr + (p - buf) + newlen, q, *sz - (q - buf) + 1);
        free(buf);
        buf = ptr;
    }
    *sz = *sz - oldlen + newlen;
    return buf;
}

static char *
xml_sethex(const char *key, addr_t value, char *buf, size_t *sz, int type)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "0x%llx", value);
    return xml_setval(key, tmp, buf, sz, type);
}

/* generic macho *************************************************************/

static int
make_all_sections_visible(uint8_t *buf, size_t size)
{
    unsigned i, j;
    struct mach_header *hdr = (struct mach_header *)buf;
    uint8_t *q = buf + sizeof(struct mach_header);

    (void)size;

    if (!MACHO(buf)) {
        return -1;
    }
    if (IS64(buf)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            struct section *sec = (struct section *)(seg + 1);
            for (j = 0; j < seg->nsects; j++) {
                /*printf("%.16s/%.16s:%.16s\n", seg->segname, sec[j].segname, sec[j].sectname);*/
                if (sec[j].flags == S_ZEROFILL) {
                    sec[j].flags = S_REGULAR;
                    sec[j].offset = seg->fileoff + sec[j].addr - seg->vmaddr;
                }
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            for (j = 0; j < seg->nsects; j++) {
                /*printf("%.16s/%.16s:%.16s\n", seg->segname, sec[j].segname, sec[j].sectname);*/
                if (sec[j].flags == S_ZEROFILL) {
                    sec[j].flags = S_REGULAR;
                    sec[j].offset = seg->fileoff + sec[j].addr - seg->vmaddr;
                }
            }
        }
        q = q + cmd->cmdsize;
    }

    return 0;
}

static addr_t
get_base(uint8_t *buf, size_t size)
{
    unsigned i;
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q = buf + sizeof(struct mach_header);

    (void)size;

    if (!MACHO(buf)) {
        return -1;
    }
    if (IS64(buf)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, "__TEXT")) {
                return seg->vmaddr;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (!strcmp(seg->segname, "__TEXT")) {
                return seg->vmaddr;
            }
        }
        q = q + cmd->cmdsize;
    }

    return -1;
}

static addr_t
get_sect_data(const uint8_t *p, size_t size, const char *segname, const char *sectname, size_t *sz)
{
    unsigned i, j;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);

    (void)size;

    if (sz) *sz = 0;

    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, segname)) {
                const struct section *sec = (struct section *)(seg + 1);
                if (sectname == NULL) {
                    if (sz) *sz = seg->filesize;
                    return seg->fileoff;
                }
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, sectname)) {
                        if (sz) *sz = sec[j].size;
                        if (sec[j].flags == S_ZEROFILL) {
                            return seg->fileoff + sec[j].addr - seg->vmaddr;
                        }
                        return sec[j].offset;
                    }
                }
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (!strcmp(seg->segname, segname)) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                if (sectname == NULL) {
                    if (sz) *sz = seg->filesize;
                    return seg->fileoff;
                }
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, sectname)) {
                        if (sz) *sz = sec[j].size;
                        if (sec[j].flags == S_ZEROFILL) {
                            return seg->fileoff + sec[j].addr - seg->vmaddr;
                        }
                        return sec[j].offset;
                    }
                }
            }
        }
        q = q + cmd->cmdsize;
    }

    return 0;
}

static addr_t
pre_alloc_sect(uint8_t *p, size_t size, size_t need)
{
    unsigned i;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);
    unsigned hdrsize;

    (void)size;

    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        q += 4;
    }
    hdrsize = q - p + hdr->sizeofcmds;

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            struct section *sec = (struct section *)(seg + 1);
            if (seg->nsects && sec->offset - need >= hdrsize) {
                sec->offset -= need;
                sec->addr -= need;
                sec->size += need;
                return sec->offset;
            }
            break;
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            if (seg->nsects && sec->offset - need >= hdrsize) {
                sec->offset -= need;
                sec->addr -= need;
                sec->size += need;
                return sec->offset;
            }
            break;
        }
        q = q + cmd->cmdsize;
    }

    return 0;
}

static addr_t
get_vaddr(const uint8_t *p, size_t size, addr_t where)
{
    unsigned i;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);

    (void)size;

    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (where >= seg->fileoff && where < seg->fileoff + seg->filesize) {
                return seg->vmaddr + where - seg->fileoff;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (where >= seg->fileoff && where < seg->fileoff + seg->filesize) {
                return seg->vmaddr + where - seg->fileoff;
            }
        }
        q = q + cmd->cmdsize;
    }

    return 0;
}

/* assembler *****************************************************************/

static unsigned int
make_bl32(int blx, int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;

    unsigned int omask = 0xF800;
    unsigned int amask = 0x7FF;

    if (blx) { /* XXX untested */
        omask = 0xE800;
        amask = 0x7FE;
        pos &= ~3;
    }

    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);

    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

static uint32_t
make_movw(unsigned reg, unsigned imm)
{
    unsigned lo, hi;

    unsigned imm4 = (imm >> 12) & 15;
    unsigned i    = (imm >> 11) & 1;
    unsigned imm3 = (imm >> 8) & 7;
    unsigned imm8 = imm & 255;

    reg &= 15;

    lo = (0xF240 << 0) | (i << 10) | imm4;
    hi = (imm3 << 12) | (reg << 8) | imm8;

    return lo | (hi << 16);
}

static uint32_t
make_movt(unsigned reg, unsigned imm)
{
    unsigned lo, hi;

    unsigned imm4 = (imm >> 12) & 15;
    unsigned i    = (imm >> 11) & 1;
    unsigned imm3 = (imm >> 8) & 7;
    unsigned imm8 = imm & 255;

    reg &= 15;

    lo = (0xF2C0 << 0) | (i << 10) | imm4;
    hi = (imm3 << 12) | (reg << 8) | imm8;

    return lo | (hi << 16);
}

static uint64_t
make_move(unsigned reg, unsigned imm)
{
    uint32_t lo, hi;
    lo = make_movw(reg, imm);
    hi = make_movt(reg, imm >> 16);
    return ((uint64_t)hi << 32) | lo;
}

/* patchfinder ***************************************************************/

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define static /* pragma ignored "-Wunused-function" is broken on some gcc */
#define memmem(a, b, c, d) (void *)boyermoore_horspool_memmem((const uint8_t *)(a), b, (const uint8_t *)(c), d)
#include "patchfinder.c"
#undef static
#pragma GCC diagnostic pop

static addr_t
step_thumb(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += insn_is_32bit((uint16_t *)(buf + start)) ? 4 : 2;
    }
    return 0;
}

static addr_t
bof32(const uint8_t *buf, addr_t start, addr_t where)
{
    for (where &= ~1; where >= start; where -= 2) {
        uint16_t op = *(uint16_t *)(buf + where);
        if ((op & 0xFF00) == 0xB500) {
            //printf("%x: PUSH {LR}\n", where);
            return where;
        }
        if (where - 4 >= start && (buf[where - 3] & 0xF8) > 0xE0) {
            where -= 2;
        }
    }
    return 0;
}

static addr_t
calc32(const uint8_t *buf, addr_t start, addr_t end, int r)
{
    addr_t i;
    uint32_t value[16];

    memset(value, 0, sizeof(value));

    end &= ~1;
    for (i = start & ~1; i < end; ) {
        uint16_t *current_instruction = (uint16_t *)(buf + i);
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            addr_t literal_address = (i & ~3) + 4 + insn_ldr_literal_imm(current_instruction);
            value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *) (buf + literal_address);
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += i + 4;
            }
        } else if ((*current_instruction & 0xFF00) == 0x4600) {
            uint8_t regs = *current_instruction;
            int rn = (regs >> 3) & 15;
            int rd = (regs & 7) | ((regs & 0x80) >> 4);
            value[rd] = value[rn];
        }
        i += insn_is_32bit(current_instruction) ? 4 : 2;
    }
    return value[r];
}

static addr_t
xref32(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint32_t value[16];

    memset(value, 0, sizeof(value));

    end &= ~1;
    for (i = start & ~1; i < end; ) {
        uint16_t *current_instruction = (uint16_t *)(buf + i);
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            addr_t literal_address = (i & ~3) + 4 + insn_ldr_literal_imm(current_instruction);
            value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *) (buf + literal_address);
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += i + 4;
                if (value[reg] == what) {
                    return i;
                }
            }
        }
        i += insn_is_32bit(current_instruction) ? 4 : 2;
    }
    return 0;
}

static addr_t
step_64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

static addr_t
step_64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

static addr_t
bof64(const uint8_t *buf, addr_t start, addr_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("%x: ADD X29, SP, #0x%x\n", where, delta);
            if ((delta & 0xF) == 0) {
                addr_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                if ((au & 0xFFC003E0) == 0xA98003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
            }
        }
    }
    return 0;
}

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            unsigned adr = ((op & 0x60000000) >> 17) | ((op & 0xFFFFE0) << 9);
            //printf("%llx: ADRP X%d, 0x%x\n", i, reg, adr);
            value[reg] = adr + (i & ~0xFFF);
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                assert(shift == 0);
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            unsigned adr = ((op & 0x60000000) >> 29) | ((op & 0xFFFFE0) >> 3);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

static addr_t
calc64(const uint8_t *buf, addr_t start, addr_t end, int r)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            unsigned adr = ((op & 0x60000000) >> 17) | ((op & 0xFFFFE0) << 9);
            //printf("%llx: ADRP X%d, 0x%x\n", i, reg, adr);
            value[reg] = adr + (i & ~0xFFF);
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                assert(shift == 0);
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            unsigned adr = ((op & 0x60000000) >> 29) | ((op & 0xFFFFE0) >> 3);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
    }
    return value[r];
}

/* machofinder ***************************************************************/

static addr_t
find_dref(const uint8_t *buf, size_t size, addr_t data, int nth, int bof)
{
    addr_t x;
    addr_t offset, end;
    size_t sz;

    offset = get_sect_data(buf, size, "__TEXT", "__text", &sz);
    if (!offset) {
        return 0;
    }
    end = offset + sz;

    if (IS64(buf)) {
        addr_t off = offset;
        do {
            x = xref64(buf, off, end, data);
            if (!x) {
                return 0;
            }
            off = x + 4;
        } while (nth--);
        if (bof) {
            x = bof64(buf, offset, x);
        }
    } else {
        addr_t off = offset;
        do {
            x = xref32(buf, off, end, data);
            if (!x) {
                return 0;
            }
            off = x + 4;
        } while (nth--);
        if (bof) {
            x = bof32(buf, offset, x);
        }
    }
    return x;
}

static addr_t
find_sref(const uint8_t *buf, size_t size, const char *string, int bof)
{
    unsigned char *str = boyermoore_horspool_memmem(buf, size, (const void *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return find_dref(buf, size, str - buf, 0, bof);
}

static addr_t
find_metaclass32(uint8_t *buf, size_t size, addr_t base, const char *driver)
{
    unsigned i, j;
    uint8_t *str;
    addr_t call, ref = 0, bof = 0;
    addr_t ctors, sect;
    addr_t addr;
    size_t sz;

    /* find the metaclass name */
    str = boyermoore_horspool_memmem(buf, size, (uint8_t *)driver, strlen(driver) + 1);
    if (!str) {
        return 0;
    }

    /* find constructor section */
    ctors = get_sect_data(buf, size, "__DATA", "__mod_init_func", &sz);
    if (!ctors) {
        ctors = get_sect_data(buf, size, "__DATA", "__constructor", &sz);
    }
    if (!ctors || !sz) {
        return 0;
    }

    /* find __text section */
    sect = get_sect_data(buf, size, "__TEXT", "__text", NULL);
    if (!sect) {
        return 0;
    }

    /* check all references to driver name... */
    for (j = 0; !ref; j++) {
        addr_t tmp = find_dref(buf, size, str - buf, j, 0);
        if (!tmp) {
            return 0;
        }
        bof = bof32(buf, sect, tmp);
        if (!bof) {
            return 0;
        }
        /* ... and see if we landed in a constructor */
        for (i = 0; i < sz / 4; i++) {
            if (bof + base == (((uint32_t *)(buf + ctors))[i] & ~1)) {
                ref = tmp;
                break;
            }
        }
    }
    if (!ref) {
        return 0;
    }

    /* find next call */
    call = step_thumb(buf, ref, 0x20, 0xD000F000, 0xD000F800);
    if (!call) {
        return 0;
    }

    /* calculate R0 at the time of call */
    addr = calc32(buf, bof, call, 0);
    if (!addr) {
        return 0;
    }

    /* find __const section */
    sect = get_sect_data(buf, size, "__DATA", "__const", &sz);
    if (!sect) {
        return 0;
    }

    /* now get a reference to the value above */
    for (i = 0; i < sz / 4; i++) {
        if (addr + base == ((uint32_t *)(buf + sect))[i]) {
            return base + sect + i * 4;
        }
    }

    return 0;
}

static addr_t
find_metaclass64(uint8_t *buf, size_t size, addr_t base, const char *driver)
{
    unsigned i, j;
    uint8_t *str;
    addr_t call, ref = 0, bof = 0;
    addr_t ctors, sect;
    addr_t addr;
    size_t sz;

    /* find the metaclass name */
    str = boyermoore_horspool_memmem(buf, size, (uint8_t *)driver, strlen(driver) + 1);
    if (!str) {
        return 0;
    }

    /* find constructor section */
    ctors = get_sect_data(buf, size, "__DATA", "__mod_init_func", &sz);
    if (!ctors || !sz) {
        return 0;
    }

    /* find __text section */
    sect = get_sect_data(buf, size, "__TEXT", "__text", NULL);
    if (!sect) {
        return 0;
    }

    /* check all references to driver name... */
    for (j = 0; !ref; j++) {
        addr_t tmp = find_dref(buf, size, str - buf, j, 0);
        if (!tmp) {
            return 0;
        }
        bof = bof64(buf, sect, tmp);
        if (!bof) {
            return 0;
        }
        /* ... and see if we landed in a constructor */
        for (i = 0; i < sz / 8; i++) {
            if (bof + base == (((uint64_t *)(buf + ctors))[i] & ~1)) {
                ref = tmp;
                break;
            }
        }
    }
    if (!ref) {
        return 0;
    }

    /* find next call */
    call = step_64(buf, ref, 0x40, 0x94000000, 0xFC000000);
    if (!call) {
        return 0;
    }

    /* calculate X0 at the time of call */
    addr = calc64(buf, bof, call, 0);
    if (!addr) {
        return 0;
    }

    /* find __const section */
    sect = get_sect_data(buf, size, "__DATA", "__const", &sz);
    if (!sect) {
        return 0;
    }

    /* now get a reference to the value above */
    for (i = 0; i < sz / 8; i++) {
        if (addr + base == ((uint64_t *)(buf + sect))[i]) {
            return base + sect + i * 8;
        }
    }

    return 0;
}

static addr_t
find_vtable(const uint8_t *buf, size_t size, int which, unsigned *sz)
{
    unsigned i, j;
    int state = 0;
    size_t const_size;
    addr_t const_off = get_sect_data(buf, size, "__DATA", "__const", &const_size);

    if (sz) *sz = 0;

    if (!const_off) {
        return 0;
    }

    if (IS64(buf)) {
        const uint64_t *abuf = (uint64_t *)(buf + const_off);
        for (i = 0; i < const_size / sizeof(abuf[0]) - 2; i++) {
            if (abuf[i] == 0 && abuf[i + 1] == 0 && abuf[i + 2] != 0 && state++ == which) {
                for (j = i + 2; j < const_size / sizeof(abuf[0]); j++) {
                    if (abuf[j] == 0) {
                        if (sz) *sz = j - i;
                        break;
                    }
                }
                return const_off + i * sizeof(abuf[0]);
            }
        }
    } else {
        const uint32_t *abuf = (uint32_t *)(buf + const_off);
        for (i = 0; i < const_size / sizeof(abuf[0]) - 2; i++) {
            if (abuf[i] == 0 && abuf[i + 1] == 0 && abuf[i + 2] != 0 && state++ == which) {
                for (j = i + 2; j < const_size / sizeof(abuf[0]); j++) {
                    if (abuf[j] == 0) {
                        if (sz) *sz = j - i;
                        break;
                    }
                }
                return const_off + i * sizeof(abuf[0]);
            }
        }
    }

    return 0;
}

/* kernel stuff **************************************************************/

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#include <mach/mach.h>

#ifdef __LP64__
#define KDELTA 0x4000 /* XXX 7.x-8.x: 0x2000 */
#else
#define KDELTA 0x1000
#endif

kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

static vm_address_t
get_kernel_base(task_t *kernel_task)
{
    kern_return_t rv;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000; /* arm64: addr = 0xffffff8000000000 */

#ifdef HOST_KERNEL_PORT
    *kernel_task = 0;
    rv = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, HOST_KERNEL_PORT, kernel_task);
    if (rv != KERN_SUCCESS || *kernel_task == 0)
#endif
    rv = task_for_pid(mach_task_self(), 0, kernel_task);
    if (rv != KERN_SUCCESS) {
        *kernel_task = 0;
        rv = bootstrap_look_up(bootstrap_port, "com.apple.kernel_task", kernel_task);
        if (rv != KERN_SUCCESS || *kernel_task == 0)
        return -1;
    }

    while ((rv = vm_region_recurse_64(*kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count)) == KERN_SUCCESS) {
        if (size > 1024 * 1024 * 1024) {
#ifdef __LP64__
            vm_address_t where = 16 * 0x200000;
#else
            vm_address_t where = 1 * 0x200000;
#endif
            for (where += addr; where >= addr; where -= 0x200000) {
                vm_size_t sz;
                uint8_t head[2048];
                sz = sizeof(head);
                rv = vm_read_overwrite(*kernel_task, where + KDELTA, sizeof(head), (vm_address_t)head, &sz);
                if (rv == 0 && sz == sizeof(head) && (*(uint32_t *)head & ~1) == 0xfeedface
                    && boyermoore_horspool_memmem(head, sizeof(head), (const uint8_t *)"__KLD", 5)) {
                    return where + KDELTA;
                }
#ifdef __LP64__
                sz = sizeof(head);
                rv = vm_read_overwrite(*kernel_task, where + KDELTA / 2, sizeof(head), (vm_address_t)head, &sz);
                if (rv == 0 && sz == sizeof(head) && (*(uint32_t *)head & ~1) == 0xfeedface
                    && boyermoore_horspool_memmem(head, sizeof(head), (const uint8_t *)"__KLD", 5)) {
                    return where + KDELTA / 2;
                }
#endif
            }
            break;
        }
        addr += size;
    }

    return -1;
}

uint8_t *kernel = NULL;
#ifdef __LP64__
size_t kernel_size = 0x2600000;
#else
size_t kernel_size = 0x1200000;
#endif
task_t kernel_task = TASK_NULL;
uint64_t kernel_base = 0;
struct kdb *kernel_db;

static vm_size_t
kread(vm_address_t where, uint8_t *p, vm_size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = vm_read_overwrite(kernel_task, where + offset, chunk, (vm_address_t)(p + offset), &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @0x%zx\n", offset + where);
            break;
        }
        offset += sz;
    }
    return offset;
}

static vm_size_t
kwrite(vm_address_t where, const uint8_t *p, vm_size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        vm_size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = vm_write(kernel_task, where + offset, (vm_offset_t)p + offset, chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @0x%zx\n", offset + where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

static vm_size_t
kwrite_uint64(vm_address_t where, uint64_t value)
{
    return kwrite(where, (uint8_t *)&value, sizeof(value));
}

static vm_size_t
kwrite_uint32(vm_address_t where, uint32_t value)
{
    return kwrite(where, (uint8_t *)&value, sizeof(value));
}

static vm_size_t
kwrite_undo(vm_address_t where, vm_size_t size)
{
    return kwrite(where, kernel + where - kernel_base, size);
}

static vm_address_t
kalloc(vm_size_t size)
{
    int rv;
    vm_address_t addr = 0;
    rv = vm_allocate(kernel_task, &addr, round_page(size), 1);
    assert(rv == KERN_SUCCESS);
    return addr;
}

static void
kfree(vm_address_t addr, vm_size_t size)
{
    vm_deallocate(kernel_task, addr, round_page(size));
}

static int
init_kernel(const char *filename)
{
    (void)filename;

    kernel_base = get_kernel_base(&kernel_task);
    if (kernel_base == (vm_address_t)-1) {
        return -1;
    }

    kernel = malloc(kernel_size);
    if (!kernel) {
        return -1;
    }

    kernel_size = kread(kernel_base, kernel, kernel_size);
    return 0;
}

static void
term_kernel(void)
{
    free(kernel);
}

#else	/* !__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */

uint8_t *kernel = MAP_FAILED;
size_t kernel_size = 0;
int kernel_fd = -1;
uint64_t kernel_base = 0;
struct kdb *kernel_db;

static size_t
kread(addr_t where, uint8_t *p, size_t size)
{
    (void)(where && p);
    return size;
}

static size_t
kwrite(addr_t where, const uint8_t *p, size_t size)
{
    (void)(where && p);
    return size;
}

static size_t
kwrite_uint64(addr_t where, uint64_t value)
{
    return kwrite(where, (uint8_t *)&value, sizeof(value));
}

static size_t
kwrite_uint32(addr_t where, uint32_t value)
{
    return kwrite(where, (uint8_t *)&value, sizeof(value));
}

static size_t
kwrite_undo(addr_t where, size_t size)
{
    return kwrite(where, kernel + where - kernel_base, size);
}

static uintptr_t
kalloc(size_t size)
{
    return (uintptr_t)malloc(size);
}

static void
kfree(uintptr_t addr, size_t size)
{
    (void)size;
    free((void *)addr);
}

static int
init_kernel(const char *filename)
{
    kernel_fd = open(filename, O_RDONLY);
    if (kernel_fd < 0) {
        return -1;
    }

    kernel_size = lseek(kernel_fd, 0, SEEK_END);

    kernel = mmap(NULL, kernel_size, PROT_READ, MAP_PRIVATE, kernel_fd, 0);
    if (kernel != MAP_FAILED) {
        if ((*(uint32_t *)kernel & ~1) == 0xfeedface) {
            kernel_base = get_base(kernel, kernel_size);
            return 0;
        }
        munmap(kernel, kernel_size);
        kernel = MAP_FAILED;
    }

    close(kernel_fd);
    kernel_fd = -1;
    return -1;
}

static void
term_kernel(void)
{
    munmap(kernel, kernel_size);
    close(kernel_fd);
}
#endif	/* !__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */

/* kernel kext ***************************************************************/

static addr_t
off_PRELINK_TEXT(void)
{
    unsigned i;
    const uint8_t *p = kernel;
    addr_t offset = 0;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);

    if (kernel_size < 0x1000) {
        return 0;
    }

    if (IS64(p)) {
        q += 4;
    }

    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                offset = seg->fileoff;
                break;
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                offset = seg->fileoff;
                break;
            }
        }
        q = q + cmd->cmdsize;
    }

    return offset;
}

static addr_t
find_kext(const char *kextid, addr_t *next)
{
    addr_t koff, kbase, ksize;
    addr_t offset = off_PRELINK_TEXT();
    size_t len = strlen(kextid) + 1; /* XXX with zero, too */
    const uint8_t *p;

    *next = 0;

    if (offset == 0) {
        return 0;
    }

    while (1) {
        p = boyermoore_horspool_memmem(kernel + offset + 1, kernel_size - offset - 1, (const void *)kextid, len);
        if (!p) {
            return 0;
        }
        offset = p - kernel;

        if (((int *)p)[-1] == 0 || !isdigit(p[64])) {
            continue;
        }

        if (IS64(kernel)) {
            kbase = *(uint64_t *)(p - 0x10 + 0x9c);
            ksize = *(uint64_t *)(p - 0x10 + 0xa4);
        } else {
            kbase = *(uint32_t *)(p - 0xc + 0x94);
            ksize = *(uint32_t *)(p - 0xc + 0x98);
        }
        if (((kbase | ksize) & 0xFFF) || kbase < kernel_base || ksize > 0x1000000) {
            continue;
        }

        for (koff = offset & ~0xFFF; koff && offset - koff < 0x100000; koff -= 0x1000) {
            if (*(uint32_t *)(kernel + koff) == *(uint32_t *)kernel) {
                addr_t other = (offset & ~0xFFF) + 0x1000;
                while (other < kernel_size && other < offset + 0x100000) {
                    uint32_t magic = *(uint32_t *)(kernel + other);
                    if (magic == *(uint32_t *)kernel || magic == 0x6369643C) {
                        *next = other;
                        return koff;
                    }
                    other += 0x1000;
                }
                break;
            }
        }
    }

    return 0;
}

static int
load_dep(const char *kextid, struct dependency *dep)
{
    uint8_t *buf;
    size_t size;
    addr_t kext, next;

    kext = find_kext(kextid, &next);
    if (!kext) {
        return -1;
    }
    size = next - kext;

    printf("%s: 0x%llx -> 0x%llx\n", kextid, kext, next);

    buf = malloc(size);
    if (!buf) {
        return -1;
    }

    memcpy(buf, kernel + kext, size);

    dep->buf = buf;
    dep->size = size;
    dep->base = get_base(buf, size);
    dep->name = kextid;
    return 0;
}

static void
free_dep(struct dependency *dep)
{
    free(dep->buf);
}

/* fat ***********************************************************************/

struct macho {
    int fd;
    size_t off, end;
};

static int
mclose(struct macho *macho)
{
    int rv = -1;
    if (macho) {
        rv = close(macho->fd);
        free(macho);
    }
    return rv;
}

static ssize_t
mread(struct macho *macho, void *buf, size_t count, off_t offset)
{
    size_t len;
    size_t off;
    if (!macho) {
        return -1;
    }
    off = offset + macho->off;
    if (off < macho->off) {
        return -1;
    }
    if (off >= macho->end) {
        return 0;
    }
    len = macho->end - off;
    if (len > count) {
        len = count;
    }
    return pread(macho->fd, buf, len, off);
}

static struct macho *
mopen(const char *filename, int mode, const struct mach_header *target)
{
    int rv;
    int fd;
    size_t size;
    unsigned i, n;
    struct stat st;
    struct fat_header fat_buf;
    struct mach_header hdr;
    struct macho *macho;

    macho = malloc(sizeof(struct macho));
    if (macho == NULL) {
        return NULL;
    }

    fd = open(filename, mode);
    if (fd < 0) {
        free(macho);
        return NULL;
    }
    macho->fd = fd;

    rv = fstat(fd, &st);
    if (rv) {
        mclose(macho);
        return NULL;
    }

    size = read(fd, &fat_buf, sizeof(fat_buf));
    if (size != sizeof(fat_buf)) {
        mclose(macho);
        return NULL;
    }

    if (fat_buf.magic != FAT_CIGAM) {
        if (fat_buf.magic == target->magic && (cpu_type_t)fat_buf.nfat_arch == target->cputype) {
            size = read(fd, &n, sizeof(n));
            if (size == sizeof(n) && (cpu_subtype_t)n <= target->cpusubtype) {
                macho->off = 0;
                macho->end = st.st_size;
                return macho;
            }
        }
        mclose(macho);
        return NULL;
    }

    n = __builtin_bswap32(fat_buf.nfat_arch);
    for (i = 0; i < n; i++) {
        size_t off, end;
        struct fat_arch arch_buf;
        size = pread(fd, &arch_buf, sizeof(arch_buf), sizeof(fat_buf) + i * sizeof(arch_buf));
        if (size != sizeof(arch_buf)) {
            break;
        }
        off = __builtin_bswap32(arch_buf.offset);
        end = off + __builtin_bswap32(arch_buf.size);
        if (end < off || (off_t)end > st.st_size) {
            break;
        }
        macho->off = off;
        macho->end = end;
        size = mread(macho, &hdr, sizeof(hdr), 0);
        if (size != sizeof(hdr)) {
            break;
        }
        if (hdr.magic == target->magic && hdr.cputype == target->cputype && hdr.cpusubtype <= target->cpusubtype) {
            return macho;
        }
    }

    mclose(macho);
    return NULL;
}

/* the real mccoy ************************************************************/

static addr_t solver_code(uint8_t *p, size_t size, addr_t base, const char *symbol);
static addr_t solver_kern(addr_t vm_kernel_slide, const char *symbol);
static addr_t solver_deps(uint8_t *p, size_t size, addr_t base, addr_t vm_kernel_slide, const char *symbol, struct dependency *deps, int ndep);

static addr_t
solver(uint8_t *p, size_t size, addr_t base, addr_t vm_kernel_slide, const char *symbol, struct dependency *deps, int ndep)
{
    addr_t val;

    if (p) {
        val = solver_code(p, size, base, symbol);
        if (val) {
            return val;
        }
    }

    if (deps && ndep > 0) {
        val = solver_deps(p, size, base, vm_kernel_slide, symbol, deps, ndep);
        if (val) {
            return val;
        }
    }

    val = solver_kern(vm_kernel_slide, symbol);
    if (val) {
        return val;
    }

    val = kdb_find(kernel_db, symbol);
    if (!val) {
        printf("UNDEFINED: %s\n", symbol);
    }
    assert(val);
    return val + vm_kernel_slide;
}

static uint8_t *
load_kext(const char *filename, addr_t vm_kernel_slide, addr_t *dest, size_t *sz, struct dependency *deps, int ndep)
{
    int rv;
    struct macho *macho;
    uint8_t *buf;
    uint8_t p[0x1000];
    size_t size, offset;
    struct symtab_command *ksym = NULL;
    struct dysymtab_command *kdys = NULL;
    size_t linkdelta = 0;
    int is64 = 0;
    unsigned i, j, k;
    const struct mach_header *hdr;
    const uint8_t *q;
    size_t hdrsz;

    *sz = 0;
    *dest = 0;

    /* since I'm not going to rewrite a full dyld-like code, I'm gonna make some assumptions:
     * segments (including LINKEDIT) come in order
     * sections are nicely laid down inside segments
     * after segments come the other commands: SYMTAB, DYSYMTAB
     * symbols, relocations are inside LINKEDIT
     */

    macho = mopen(filename, O_RDONLY, (struct mach_header *)kernel);
    assert(macho);

    size = mread(macho, p, sizeof(p), 0);
    assert(size == sizeof(p));

    /* parse header, calculate total in-memory size */

    hdr = (struct mach_header *)p;
    q = p + sizeof(struct mach_header);

    if (IS64(p)) {
        is64 = 4;
    }
    q += is64;

    hdrsz = q - p + hdr->sizeofcmds;
    assert(hdrsz <= sizeof(p));

    size = 0;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            seg->vmsize = round_page(seg->vmsize);
            size += seg->vmsize;
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            seg->vmsize = round_page(seg->vmsize);
            size += seg->vmsize;
        }
        q = q + cmd->cmdsize;
    }

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    *dest = kalloc(size);
#endif
    rv = posix_memalign((void **)&buf, 0x1000, size);
    assert(rv == 0);
    memset(buf, 0, size); /* XXX take care of S_ZEROFILL */
#ifndef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    if (is64) {
        *dest = 0xdead000000000000;
    } else {
        *dest = 0xdead0000;
    }
#endif

    /* read segments in, calculate linkedit delta */

    q = p + sizeof(struct mach_header) + is64;

    offset = 0;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            struct section *sec = (struct section *)(seg + 1);
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                linkdelta = offset - seg->fileoff;
            }
            if (seg->filesize > seg->vmsize) {
                seg->filesize = seg->vmsize;
            }
            seg->fileoff = offset;
            seg->vmaddr += *dest - vm_kernel_slide;
            for (j = 0; j < seg->nsects; j++) {
                sec[j].addr += *dest - vm_kernel_slide;
                assert(sec->reloff == 0 && sec->nreloc == 0);
            }
            size = mread(macho, buf + offset, seg->filesize, seg->fileoff);
            assert(size == seg->filesize);
            offset += seg->vmsize;
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                linkdelta = offset - seg->fileoff;
            }
            if (seg->filesize > seg->vmsize) {
                seg->filesize = seg->vmsize;
            }
            seg->fileoff = offset;
            seg->vmaddr += *dest - vm_kernel_slide;
            for (j = 0; j < seg->nsects; j++) {
                sec[j].addr += *dest - vm_kernel_slide;
                assert(sec->reloff == 0 && sec->nreloc == 0);
            }
            size = mread(macho, buf + offset, seg->filesize, seg->fileoff);
            assert(size == seg->filesize);
            offset += seg->vmsize;
        }
        q = q + cmd->cmdsize;
    }

    mclose(macho);

    /* fix header */

    memcpy(buf, p, hdrsz);

    /* solve imports, spot relocs */

    q = buf + sizeof(struct mach_header) + is64;

#define SLIDE(x) do { if (x) x += linkdelta; } while (0)
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SYMTAB) {
            struct symtab_command *sym = (struct symtab_command *)q;
            ksym = sym;
            SLIDE(sym->symoff);
            SLIDE(sym->stroff);
            if (is64) {
                struct nlist_64 *s = (struct nlist_64 *)(buf + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if ((s[k].n_type & N_EXT) && GET_LIBRARY_ORDINAL(s[k].n_desc) == DYNAMIC_LOOKUP_ORDINAL && s[k].n_value == 0) {
                        s[k].n_value = solver(buf, offset, *dest, vm_kernel_slide, (char *)buf + sym->stroff + s[k].n_un.n_strx, deps, ndep);
                        continue;
                    }
                    s[k].n_value += *dest - vm_kernel_slide;
                }
            } else {
                struct nlist *s = (struct nlist *)(buf + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if ((s[k].n_type & N_EXT) && GET_LIBRARY_ORDINAL(s[k].n_desc) == DYNAMIC_LOOKUP_ORDINAL && s[k].n_value == 0) {
                        s[k].n_value = solver(buf, offset, *dest, vm_kernel_slide, (char *)buf + sym->stroff + s[k].n_un.n_strx, deps, ndep);
                        continue;
                    }
                    s[k].n_value += *dest - vm_kernel_slide;
                }
            }
        }
        if (cmd->cmd == LC_DYSYMTAB) {
            struct dysymtab_command *dys = (struct dysymtab_command *)q;
            kdys = dys;
            SLIDE(dys->tocoff);
            SLIDE(dys->modtaboff);
            SLIDE(dys->extrefsymoff);
            SLIDE(dys->indirectsymoff);
            SLIDE(dys->extreloff);
            SLIDE(dys->locreloff);
        }
        q = q + cmd->cmdsize;
    }
#undef SLIDE

    /* apply relocs */

    if (kdys && kdys->locreloff) {
        const struct relocation_info *r = (struct relocation_info *)(buf + kdys->locreloff);
        if (is64) {
            for (k = 0; k < kdys->nlocrel; k++, r++) {
                if (
#if 1 /* XXX horrible hack to reduce size */
                    (((uint32_t *)r)[1] >> 24) != 6
#else
                    r->r_pcrel || r->r_length != 3 || r->r_extern || r->r_type > GENERIC_RELOC_VANILLA
#endif
                   ) {
                    assert(0);
                }
                if (r->r_address & R_SCATTERED) {
                    assert(0);
                }
                *(uint64_t *)(buf + r->r_address) += *dest;
            }
        } else {
            for (k = 0; k < kdys->nlocrel; k++, r++) {
                if (
#if 1 /* XXX horrible hack to reduce size */
                    (((uint32_t *)r)[1] >> 24) != 4
#else
                    r->r_pcrel || r->r_length != 2 || r->r_extern || r->r_type > GENERIC_RELOC_VANILLA
#endif
                   ) {
                    assert(0);
                }
                if (r->r_address & R_SCATTERED) {
                    assert(0);
                }
                *(uint32_t *)(buf + r->r_address) += *dest;
            }
        }
    }

    /* apply externs */

    if (kdys && kdys->extreloff && ksym->symoff) {
        const struct relocation_info *r = (struct relocation_info *)(buf + kdys->extreloff);
        if (is64) {
            const struct nlist_64 *s = (struct nlist_64 *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextrel; k++, r++) {
                assert(!r->r_pcrel && r->r_length == 3 && r->r_extern && r->r_type == GENERIC_RELOC_VANILLA);
                *(uint64_t *)(buf + r->r_address) = s[r->r_symbolnum].n_value;
            }
        } else {
            const struct nlist *s = (struct nlist *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextrel; k++, r++) {
                assert(!r->r_pcrel && r->r_length == 2 && r->r_extern && r->r_type == GENERIC_RELOC_VANILLA);
                *(uint32_t *)(buf + r->r_address) = s[r->r_symbolnum].n_value;
            }
        }
    }

    if (kdys) {
        kdys->nlocrel = 0; /* XXX nuke relocs */
        kdys->nextrel = 0; /* XXX nuke exts */
    }

    *sz = offset;
    return buf;
}

static char *
populate_xml(char *xml, size_t *sz, addr_t obase, size_t osize, addr_t kmod_info, char *id)
{
    char *p = strchr(id, '.');
    if (p) {
        p++;
    } else {
        p = id;
    }

    xml = xml_setval("CFBundleIdentifier", id, xml, sz, 0);
    assert(xml);
    xml = xml_sethex("_PrelinkExecutableSize", osize, xml, sz, 2);
    assert(xml);
    xml = xml_sethex("_PrelinkExecutableLoadAddr", obase, xml, sz, 2);
    assert(xml);
    xml = xml_sethex("_PrelinkExecutableSourceAddr", obase, xml, sz, 2);
    assert(xml);
    xml = xml_sethex("_PrelinkKmodInfo", obase + kmod_info, xml, sz, 2);
    assert(xml);
    if (!strstr(xml, "_PrelinkBundlePath")) {
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "/System/Library/Extensions/%s.kext", p);
        xml = xml_setval("_PrelinkBundlePath", tmp, xml, sz, 0);
        assert(xml);
    }
    if (!strstr(xml, "_PrelinkExecutableRelativePath")) {
        xml = xml_setval("_PrelinkExecutableRelativePath", p, xml, sz, 0);
        assert(xml);
    }
    return xml;
}

static void
dump_file(const char *filename, int n, void *buf, size_t size)
{
    FILE *f;
    char tmp[256];
    if (n >= 0) {
        snprintf(tmp, sizeof(tmp), "%s%d", filename, n);
        filename = tmp;
    }
    f = fopen(filename, "wb");
    fwrite(buf, 1, size, f);
    fclose(f);
}

static const uint8_t ret0_arm32[] = {
    0x00, 0x20, 0x70, 0x47
};

static const uint8_t ret0_arm64[] = {
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6
};

static const uint8_t bcopy_armv7[] = {
    0x4F, 0xF0, 0x01, 0x09, 0x81, 0x42, 0x88, 0xBF, 0x4F, 0xF0, 0xFF, 0x39, 0x00, 0x2A, 0x08, 0xBF,
    0x70, 0x47, 0x4F, 0xF0, 0x00, 0x0C, 0x81, 0x42, 0x88, 0xBF, 0xA2, 0xF1, 0x01, 0x0C, 0x10, 0xF8,
    0x0C, 0x30, 0x01, 0x3A, 0x01, 0xF8, 0x0C, 0x30, 0xCC, 0x44, 0xF8, 0xD1, 0x70, 0x47
};

static const uint8_t bcopy_arm64[] = {
    0xE9, 0x03, 0x40, 0xB2, 0x3F, 0x00, 0x00, 0xEB, 0xE8, 0x7F, 0x60, 0xB2, 0x08, 0x81, 0x02, 0x8B,
    0x08, 0xFD, 0x60, 0x93, 0x0A, 0x00, 0x80, 0x92, 0xE8, 0x93, 0x88, 0x9A, 0x29, 0x91, 0x8A, 0x9A,
    0xC2, 0x00, 0x00, 0xB4, 0x42, 0x04, 0x00, 0xD1, 0x0A, 0x68, 0x68, 0x38, 0x2A, 0x68, 0x28, 0x38,
    0x08, 0x01, 0x09, 0x8B, 0x82, 0xFF, 0xFF, 0xB5, 0xC0, 0x03, 0x5F, 0xD6
};

// XXX I should call OSSafeRelease(infoDict) aka infoDict->release()
//#define ALL_MATCH 1 /* start matching for all kexts, not just this one */
//#define MATCH_NOW 1 /* if ALL_MATCH, start matching NOW */
static uint8_t stuff32[] = {
    0xbc, 0xb5, /* push {r2-r5, r7, lr} */
    0x04, 0xaf, /* add  r7, sp, #16 */
    0x0c, 0x4d, /* ldr  r5, [pc, #48]   ; rv */
    0x0d, 0x48, /* ldr  r0, [pc, #52]   ; xml */
    0x00, 0x21, /* movs r1, #0 */
    0x0d, 0x4c, /* ldr  r4, [pc, #52]   ; OSUnserializeXML */
    0xa0, 0x47, /* blx  r4 */
    0x88, 0xb1, /* cbz  r0, .Ldone */
    0x0c, 0x4c, /* ldr  r4, [pc, #48]   ; OSKext::withPrelinkedInfoDict */
    0xa0, 0x47, /* blx  r4 */
    0x01, 0x35, /* adds r5, #1 */
    0x68, 0xb1, /* cbz  r0, .Ldone */
    0x0b, 0x48, /* ldr  r0, [pc, #44]   ; ident */
    0x00, 0x21, /* movs r1, #0 */
    0x00, 0x22, /* movs r2, #0 */
#ifdef ALL_MATCH
    0x02, 0x23, /* movs r3, #2 */
#else
    0x00, 0x23, /* movs r3, #0 */
#endif
    0x00, 0x93, /* str  r3, [sp, #0] */
    0x01, 0x91, /* str  r1, [sp, #4] */
    0x00, 0x23, /* movs r3, #0 */
    0x09, 0x4c, /* ldr  r4, [pc, #36]   ; OSKext::loadKextWithIdentifier */
    0xa0, 0x47, /* blx  r4 */
    0x05, 0x46, /* mov  r5, r0 */
    0x10, 0xb9, /* cbnz r0, .Ldone */
#ifdef MATCH_NOW
    0x01, 0x20, /* movs r0, #1 */
#else
    0x00, 0x20, /* movs r0, #0 */
#endif
    0x07, 0x4c, /* ldr  r4, [pc, #28]   ; OSKext::sendAllKextPersonalitiesToCatalog */
#ifdef ALL_MATCH
    0xa0, 0x47, /* blx  r4 */
#else
    0x00, 0xbf, /* nop */
#endif
    0x28, 0x46, /* mov  r0, r5 */
    0xbc, 0xbd, /* pop  {r2-r5, r7, pc} */
/* 0x38 */
    1, 1, 1, 1, /* rv */
    2, 2, 2, 2, /* xml */
    3, 3, 3, 3, /* OSUnserializeXML */
    4, 4, 4, 4, /* OSKext::withPrelinkedInfoDict */
    5, 5, 5, 5, /* ident */
    6, 6, 6, 6, /* OSKext::loadKextWithIdentifier */
    7, 7, 7, 7, /* OSKext::sendAllKextPersonalitiesToCatalog */
};

static uint32_t stuff64[] = {
    0xa9bf7bfd, /* stp  x29, x30, [sp,#-16]! */
    0x910003fd, /* mov  x29, sp */
    0xa9bf4ff4, /* stp  x20, x19, [sp,#-16]! */
    0x58000374, /* ldr  x20, 78 <rv> */
    0x58000380, /* ldr  x0, 80 <xml> */
    0xd2800001, /* mov  x1, #0x0 */
    0x58000388, /* ldr  x8, 88 <OSUnserializeXML> */
    0xd63f0100, /* blr  x8 */
    0xb4000240, /* cbz  x0, .Ldone */
    0x58000368, /* ldr  x8, 90 <OSKext_withPrelinkedInfoDict> */
    0xd63f0100, /* blr  x8 */
    0x91000694, /* add  x20, x20, #0x1 */
    0xb40001c0, /* cbz  x0, .Ldone */
    0x58000320, /* ldr  x0, 98 <ident> */
    0xd2800001, /* mov  x1, #0x0 */
    0xd2800002, /* mov  x2, #0x0 */
    0xd2800003, /* mov  x3, #0x0 */
#ifdef ALL_MATCH
    0xd2800044, /* mov  x4, #0x2 */
#else
    0xd2800004, /* mov  x4, #0x0 */
#endif
    0xd2800005, /* mov  x5, #0x0 */
    0x580002a8, /* ldr  x8, a0 <OSKext_loadKextWithIdentifier> */
    0xd63f0100, /* blr  x8 */
    0xaa0003f4, /* mov  x20, x0 */
    0xb5000080, /* cbnz x0, .Ldone */
#ifdef MATCH_NOW
    0xd2800020, /* mov  x0, #0x1 */
#else
    0xd2800000, /* mov  x0, #0x0 */
#endif
    0x58000248, /* ldr  x8, a8 <OSKext_sendAllKextPersonalitiesToCatalog> */
#ifdef ALL_MATCH
    0xd63f0100, /* blr  x8 */
#else
    0xd503201f, /* nop */
#endif
    0xaa1403e0, /* mov  x0, x20 */
    0xa8c14ff4, /* ldp  x20, x19, [sp],#16 */
    0xa8c17bfd, /* ldp  x29, x30, [sp],#16 */
    0xd65f03c0, /* ret */
/* 0x78 */
    1, 1, /* rv */
    2, 2, /* xml */
    3, 3, /* OSUnserializeXML */
    4, 4, /* OSKext_withPrelinkedInfoDict */
    5, 5, /* ident */
    6, 6, /* OSKext_loadKextWithIdentifier */
    7, 7, /* OSKext_sendAllKextPersonalitiesToCatalog */
};

#ifdef MY_LOGGER
static uint8_t logger32[] = {
/*00000000 <_hook1>*/
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0x00, 0xb5, /* push {lr} */
    0x00, 0xf0, /* bl         */
    0x0c, 0xf8, /*      _putc */
    0xe6, 0x46, /* mov  lr, r12 */
    0x00, 0xbd, /* pop  {pc} */
/*00000016 <_hook2>*/
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0xc0, 0x46, /* nop */
    0x01, 0xb5, /* push {r0, lr} */
    0x30, 0x46, /* mov  r0, r6 */
    0x00, 0xf0, /* bl         */
    0x01, 0xf8, /*      _putc */
    0x01, 0xbd, /* pop  {r0, pc} */
/*0000002a <_putc>*/
    0x0e, 0xb5, /* push {r1-r3, lr} */
    0x04, 0x49, /* ldr  r1, [pc, #16]   ; block */
    0x0a, 0x68, /* ldr  r2, [r1, #0] */
    0x04, 0x32, /* adds r2, #4 */
    0x04, 0x4b, /* ldr  r3, [pc, #16]   ; limit */
    0x9a, 0x42, /* cmp  r2, r3 */
    0x02, 0xd2, /* bcs  .Ldone */
    0x88, 0x54, /* strb r0, [r1, r2] */
    0x03, 0x3a, /* subs r2, #3 */
    0x0a, 0x60, /* str  r2, [r1, #0] */
    0x0e, 0xbd, /* pop  {r1-r3, pc} */
    1, 1, 1, 1, /* block */
    2, 2, 2, 2, /* limit */
};

// XXX 32bit only here
static uint32_t
find_callee_with_str(const uint8_t *buf, size_t size, const char *str)
{
    uint32_t callee = 0;
    addr_t ref = find_sref(buf, size, str, 0);
    if (ref) {
        addr_t site = step_thumb(buf, ref, 0x10, 0xD000F000, 0xD000F800);
        if (site) {
            callee = site + insn_bl_imm32((uint16_t *)(buf + site)) + 4;
        }
    }
    return callee;
}

static uint32_t
find_logger_hook1(void)
{
    // _iolog_logputc+0x12 (IOLog)
    addr_t IOLog = find_callee_with_str(kernel, kernel_size, "iokit terminate done");
    /*printf("IOLog = 0x%x\n", IOLog);*/
    if (IOLog) {
        addr_t a = step_thumb(kernel, IOLog, 0x100, 0x447A, 0xFFFF);
        if (a) {
            addr_t b = calc32(kernel, IOLog, a + 2, 2);
            if (b) {
                a = step_thumb(kernel, b & ~1, 0x40, 0x4478, 0xFF78);
                if (a) {
                    return a + 2;
                }
            }
        }
    }
    return 0;
}

static uint32_t
find_logger_hook2(void)
{
    // conslog_putc#tail+0x32 (printf)
    addr_t printf_ = find_callee_with_str(kernel, kernel_size, "iBoot version: %s\n");
    /*printf("printf_ = 0x%x\n", printf_);*/
    if (printf_) {
        addr_t a = step_thumb(kernel, printf_, 0x100, 0xD000F000, 0xD000F800);
        if (a) {
            uint32_t b = calc32(kernel, printf_, a, 3);
            if (b) {
                a = step_thumb(kernel, b & ~1, 0x100, 0x9000F000, 0xD000F800);
                if (a) {
                    b = a + insn_bl_imm32((uint16_t *)(kernel + a)) + 4;
                    if (b) {
                        a = step_thumb(kernel, b, 0x40, 0x4478, 0xFF78);
                        if (a) {
                            a = step_thumb(kernel, a + 2, 0x40, 0x4478, 0xFF78);
                            if (a) {
                                return a + 2;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
// XXX no 32bit only here
#endif	/* MY_LOGGER */

static int
call_kernel(addr_t TRAMPOLINE_ADDR)
{
    int ret = -1;
    struct dependency dep;

    size_t rv;
    size_t size;
    addr_t i, sect;
    addr_t val, site = 0;

    rv = load_dep("com.apple.iokit.IOCryptoAcceleratorFamily", &dep);
    assert(rv == 0);

    val = find_sref(dep.buf, dep.size, "_internalTest", 1);
    assert(val);

    val += dep.base;
    printf("IOAESAcceleratorUserClient::_internalTest: 0x%llx\n", val);

    sect = get_sect_data(dep.buf, dep.size, "__DATA", "__const", &size);
    assert(sect);
    if (IS64(kernel)) {
        const uint64_t *ptr = (uint64_t *)(dep.buf + sect);
        for (i = 0; i < size / 8; i++) {
            if (ptr[i] == val) {
                site = i * 8;
                break;
            }
        }
    } else {
        const uint32_t *ptr = (uint32_t *)(dep.buf + sect);
        for (i = 0; i < size / 4; i++) {
            if (ptr[i] == val + 1) {
                site = i * 4;
                break;
            }
        }
    }
    assert(site);
    val = site + sect + dep.base;

    free_dep(&dep);

    printf("_internalTest: 0x%llx\n", val);

    if (IS64(kernel)) {
        rv = kwrite_uint64(val, TRAMPOLINE_ADDR);
        assert(rv == sizeof(uint64_t));
    } else {
        rv = kwrite_uint32(val, TRAMPOLINE_ADDR + 1);
        assert(rv == sizeof(uint32_t));
    }

    fflush(stdout);
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    sync();
    sleep(1);
    sync();
    sleep(1);
    sync();
    sleep(1);

    io_connect_t conn = 0;
    io_service_t dev = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOAESAccelerator"));
    if (dev) {
        ret = IOServiceOpen(dev, mach_task_self(), 0, &conn);
        if (ret == kIOReturnSuccess) {
            ret = IOConnectCallStructMethod(conn, 2/*kIOAESAcceleratorTest*/, NULL, 0, NULL, 0);
            IOServiceClose(conn);
        }
        IOObjectRelease(dev);
    }
#else
    ret = 0;
#endif

    if (IS64(kernel)) {
        rv = kwrite_undo(val, sizeof(uint64_t));
        assert(rv == sizeof(uint64_t));
    } else {
        rv = kwrite_undo(val, sizeof(uint32_t));
        assert(rv == sizeof(uint32_t));
    }

    return ret;
}

int
main(int argc, char **argv)
{
    int rc;
    size_t rv;
    uint8_t *obuf;
    size_t osize;
    addr_t obase;
    addr_t kmod_info;
    char *kernel_ver;
    addr_t vm_kernel_slide;
    char *xml;
    size_t xml_size;
    struct dependency *deps = NULL;
    int i, ndep;
    char *kextid;
    addr_t TRAMPOLINE_ADDR;
    uint8_t *stuff;
    size_t sizeof_stuff;
    addr_t xbase = 0;

    if (argc < 3) {
        printf("usage: %s kext plist [deps...]\n", argv[0]);
        return 1;
    }
#ifndef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    /* gross hack ahead */
    if (!strcmp(argv[1], "-solve")) {
        rv = init_kernel(argv[2]);
        if (rv) {
            fprintf(stderr, "[e] cannot read kernel\n");
            return -1;
        }
        for (i = 3; i < argc; i++) {
            printf("%s=0x%llx\n", argv[i], solver(NULL, 0, 0, 0, argv[i], NULL, 0));
        }
        return 0;
    }
#endif
    ndep = argc - 3;

    /* read in kernel, solve some shit, etc. */

    rv = init_kernel("krnl");
    if (rv) {
        fprintf(stderr, "[e] cannot read kernel\n");
        return -1;
    }
    dump_file("_krnl", -1, kernel, kernel_size);

    kernel_ver = (char *)boyermoore_horspool_memmem(kernel, kernel_size, (unsigned char *)"Darwin Kernel Version", sizeof("Darwin Kernel Version") - 1);
    kernel_db = kdb_init("kernel.db", kernel_ver);

    /* read our kext, xml, etc. */

    if (ndep > 0) {
        deps = malloc(ndep * sizeof(struct dependency));
        assert(deps);
        for (i = 0; i < ndep; i++) {
            rv = load_dep(argv[i + 3], deps + i);
            assert(rv == 0);
            make_all_sections_visible(deps[i].buf, deps[i].size);
            dump_file("_dep", i + 1, deps[i].buf, deps[i].size);
        }
    }

    if (IS64(kernel)) {
        unsigned v = 0;
        if (kernel_ver) {
            kernel_ver = strstr(kernel_ver, "root:xnu-");
            if (kernel_ver) {
                v = atoi(kernel_ver + 9);
            }
        }
        assert(v);
        if (v < 2783) {
            vm_kernel_slide = kernel_base - 0xFFFFFF8000202000; // 7.x
        } else if (v >= 3248) {
            vm_kernel_slide = kernel_base - 0xFFFFFF8004004000; // 9.x
        } else {
            vm_kernel_slide = kernel_base - 0xFFFFFF8002002000; // 8.x
        }
        stuff = (uint8_t *)stuff64;
        sizeof_stuff = sizeof(stuff64);
    } else {
        vm_kernel_slide = kernel_base - 0x80001000;
        stuff = stuff32;
        sizeof_stuff = sizeof(stuff32);
    }
    printf("vm_kernel_slide = 0x%llx\n", vm_kernel_slide);
    obuf = load_kext(argv[1], vm_kernel_slide, &obase, &osize, deps, ndep);
    xml = read_file(argv[2], &xml_size);
    assert(obuf && xml);

    printf("obase = 0x%llx\n", obase);

    kmod_info = get_sect_data(obuf, osize, "__DATA", "__data", &rv);
    assert(kmod_info);
    printf("kmod_info: 0x%llx\n", kmod_info + obase);

    if (IS64(kernel)) {
        *(uint64_t *)(obuf + kmod_info + 0x9c) = obase - vm_kernel_slide;
        *(uint64_t *)(obuf + kmod_info + 0xa4) = osize;
        kextid = (char *)obuf + kmod_info + 0x10;
    } else {
        *(uint32_t *)(obuf + kmod_info + 0x94) = obase - vm_kernel_slide;
        *(uint32_t *)(obuf + kmod_info + 0x98) = osize;
        kextid = (char *)obuf + kmod_info + 0xC;
    }

    xml = populate_xml(xml, &xml_size, obase - vm_kernel_slide, osize, kmod_info, kextid);

    dump_file("_xml", -1, xml, xml_size);
    dump_file("_kext", -1, obuf, osize);

    if (ndep > 0) {
        for (i = 0; i < ndep; i++) {
            free_dep(deps + i);
        }
        free(deps);
    }

    /* upload and execute */

    rv = kwrite(obase, obuf, osize);
    assert(rv == osize);

    xbase = kalloc(xml_size + 1);
    printf("xml addr = 0x%llx\n", xbase);
    rv = kwrite(xbase, (uint8_t *)xml, xml_size);
    assert(rv == xml_size);

    TRAMPOLINE_ADDR = kalloc(sizeof_stuff);
    printf("trampoline: 0x%llx\n", TRAMPOLINE_ADDR);

    addr_t OSUnserializeXML = solver(NULL, 0, 0, vm_kernel_slide, "__Z16OSUnserializeXMLPKcPP8OSString", NULL, 0);
    addr_t OSKext_withPrelinkedInfoDict = solver(NULL, 0, 0, vm_kernel_slide, "__ZN6OSKext21withPrelinkedInfoDictEP12OSDictionary", NULL, 0);
    addr_t OSKext_loadKextWithIdentifier = solver(NULL, 0, 0, vm_kernel_slide, "__ZN6OSKext22loadKextWithIdentifierEPKcbbhhP7OSArray", NULL, 0);
    addr_t OSKext_sendAllKextPersonalitiesToCatalog = solver(NULL, 0, 0, vm_kernel_slide, "__ZN6OSKext33sendAllKextPersonalitiesToCatalogEb", NULL, 0);

    printf("OSUnserializeXML = 0x%llx\n", OSUnserializeXML);
    printf("OSKext::withPrelinkedInfoDict = 0x%llx\n", OSKext_withPrelinkedInfoDict);
    printf("OSKext::loadKextWithIdentifier = 0x%llx\n", OSKext_loadKextWithIdentifier);
    printf("OSKext::sendAllKextPersonalitiesToCatalog = 0x%llx\n", OSKext_sendAllKextPersonalitiesToCatalog);

    if (IS64(kernel)) {
        ((uint64_t *)stuff64)[15] = 0xDC0080F0;
        ((uint64_t *)stuff64)[16] = xbase;
        ((uint64_t *)stuff64)[17] = OSUnserializeXML;
        ((uint64_t *)stuff64)[18] = OSKext_withPrelinkedInfoDict;
        ((uint64_t *)stuff64)[19] = kmod_info + obase + 0x10; /* identifier */
        ((uint64_t *)stuff64)[20] = OSKext_loadKextWithIdentifier;
        ((uint64_t *)stuff64)[21] = OSKext_sendAllKextPersonalitiesToCatalog;
    } else {
        ((uint32_t *)stuff32)[14] = 0xDC0080F0;
        ((uint32_t *)stuff32)[15] = xbase;
        ((uint32_t *)stuff32)[16] = OSUnserializeXML;
        ((uint32_t *)stuff32)[17] = OSKext_withPrelinkedInfoDict;
        ((uint32_t *)stuff32)[18] = kmod_info + obase + 0xC; /* identifier */
        ((uint32_t *)stuff32)[19] = OSKext_loadKextWithIdentifier;
        ((uint32_t *)stuff32)[20] = OSKext_sendAllKextPersonalitiesToCatalog;
    }
    dump_file("_tramp", -1, stuff, sizeof_stuff);

    rv = kwrite(TRAMPOLINE_ADDR, stuff, sizeof_stuff);
    assert(rv == sizeof_stuff);

#ifdef MY_LOGGER
// XXX 32bit only here
    assert(!IS64(kernel));
    uint8_t relog[] = {
        0x10, 0x46, /* mov r0, r2 */
        0x19, 0x46, /* mov r1, r3 */
        0, 0, 0, 0, /* bl  ... */
        0x0F, 0xBC, /* pop {r0-r3} */
        0x0F, 0x46, /* mov r7, r1 */
        0x10, 0x47  /* bx  r2 */
    };
    addr_t OSKextLog = find_callee_with_str(kernel, kernel_size, "Jettisoning kext bootstrap segments.");
    printf("OSKextLog = 0x%llx\n", OSKextLog);
    addr_t logger_hook1 = find_logger_hook1();
    printf("logger_hook1 = 0x%llx\n", logger_hook1);
    addr_t logger_hook2 = find_logger_hook2();
    printf("logger_hook2 = 0x%llx\n", logger_hook2);
    if (OSKextLog) {
        addr_t y = 0;
        OSKextLog += kernel_base;
        if (logger_hook1) {
            // we found _iolog_logputc, it's best to reroute OSKextLog to IOLogv
            y = solver(NULL, 0, 0, vm_kernel_slide, "_IOLogv", NULL, 0);
            if (y) {
                printf("OSKextLog -> IOLog\n");
                ((uint32_t *)relog)[1] = make_bl32(0, OSKextLog + 16 + 4, y & ~1);
            }
        } else if (logger_hook2) {
            // we found conslog_putc#tail, it's best to reroute OSKextLog to vprintf
            y = solver(NULL, 0, 0, vm_kernel_slide, "_vprintf", NULL, 0);
            if (y) {
                printf("OSKextLog -> vprintf\n");
                ((uint32_t *)relog)[1] = make_bl32(0, OSKextLog + 16 + 4, y & ~1);
            }
        }
        if (y == 0) { // we could still reroute to either IOLogv or vprintf, but we did't hook any putc, anyway
            OSKextLog = 0;
        }
    }

    addr_t LOGGER_ADDR = (TRAMPOLINE_ADDR + sizeof(stuff32) + 3) & ~3;
    addr_t logger_block = 0;

    if (OSKextLog) {
        rv = kwrite(OSKextLog + 16, relog, sizeof(relog));
        assert(rv == sizeof(relog));
    }
    if (logger_hook1 || logger_hook2) {
        logger_block = kalloc(MY_LOGGER_SIZE);

        void *heck = calloc(1, MY_LOGGER_SIZE);
        rv = kwrite(logger_block, heck, MY_LOGGER_SIZE);
        assert(rv == MY_LOGGER_SIZE);
        free(heck);

        printf("logger block: 0x%llx\n", logger_block);

        ((uint32_t *)logger32)[16] = logger_block;
        ((uint32_t *)logger32)[17] = MY_LOGGER_SIZE;

        if (logger_hook1) {
            memcpy(logger32 + 0x00, kernel + logger_hook1, 12);
            logger_hook1 += kernel_base;
        }
        if (logger_hook2) {
            memcpy(logger32 + 0x16, kernel + logger_hook2, 10);
            logger_hook2 += kernel_base;
        }

        rv = kwrite(LOGGER_ADDR, logger32, sizeof(logger32));
        assert(rv == sizeof(logger32));

        if (logger_hook1) {
            uint8_t hook[] = {
                0xf4, 0x46, /* mov r12, lr */
                0, 0, 0, 0,
                0, 0, 0, 0,
                0x88, 0x47, /* blx r1 */
            };
            *(uint64_t *)(hook + 2) = make_move(1, LOGGER_ADDR + 0x00 + 1);
            rv = kwrite(logger_hook1, hook + 0, 12);
            assert(rv == 12);
        }
        if (logger_hook2) {
            uint8_t hook[] = {
                0xf0, 0xde, /* unused */
                0, 0, 0, 0,
                0, 0, 0, 0,
                0xa0, 0x47, /* blx r4 */
            };
            *(uint64_t *)(hook + 2) = make_move(4, LOGGER_ADDR + 0x16 + 1);
            rv = kwrite(logger_hook2, hook + 2, 10);
            assert(rv == 10);
        }

        dump_file("_logr", -1, logger32, sizeof(logger32));
    }
// XXX no 32bit only here
#endif	/* MY_LOGGER */

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    vm_prot_t prot = VM_PROT_READ | VM_PROT_EXECUTE;
    rv = vm_protect(kernel_task, TRAMPOLINE_ADDR, round_page(sizeof_stuff), 1, prot);
    assert(rv == KERN_SUCCESS);
    rv = vm_protect(kernel_task, TRAMPOLINE_ADDR, round_page(sizeof_stuff), 0, prot);
    assert(rv == KERN_SUCCESS);
#endif	/* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */

    rc = call_kernel(TRAMPOLINE_ADDR);

    kfree(xbase, xml_size + 1);

    printf("OSKext -> 0x%x\n", rc);
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    if (rc == 0) {
        // XXX seems redundant
        rv = IOCatalogueModuleLoaded(kIOMasterPortDefault, kextid);
        printf("IOKit -> 0x%zx\n", rv);
    }
#endif

    rv = kread(obase, obuf, osize);
    dump_file("_kext", 2, obuf, rv);

#ifdef MY_LOGGER
// XXX 32bit only here
    if (logger_hook1 || logger_hook2) {
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        for (rv = 0; rv < 10; rv++) {
            sleep(1);
            printf(".");
            fflush(stdout);
        }
        printf("\n");
#endif

        uint32_t *heck = calloc(1, MY_LOGGER_SIZE);
        assert(heck);
        rv = kread(logger_block, (void *)heck, MY_LOGGER_SIZE);
        dump_file("_log", -1, heck + 1, *heck);
        free(heck);

        // undo logger hooks
        if (logger_hook1) {
            rv = kwrite_undo(logger_hook1, 12);
            assert(rv == 12);
        }
        if (logger_hook2) {
            rv = kwrite_undo(logger_hook2, 10);
            assert(rv == 10);
        }

        kfree(logger_block, MY_LOGGER_SIZE);
    }
    if (OSKextLog) {
        rv = kwrite_undo(OSKextLog + 16, sizeof(relog));
        assert(rv == sizeof(relog));
    }
// XXX no 32bit only here
#endif	/* MY_LOGGER */

    kfree(TRAMPOLINE_ADDR, sizeof_stuff);

    // XXX let's see what changed
    rv = kread(kernel_base, kernel, kernel_size);
    assert(rv == kernel_size);
    dump_file("_krnl", 2, kernel, kernel_size);

    printf("done\n");

    free(xml);
    free(obuf);
    kdb_term(kernel_db);
    term_kernel();
    return rc;
}

/*
 * there are 3 solvers below:
 * solver_code: create small missing functions (nullsubs)
 * solver_kern: use patchfinder to find missing symbols
 * solver_deps: do nasty stuff to satisfy kext dependencies
 */

static addr_t
solver_code(uint8_t *p, size_t size, addr_t base, const char *symbol)
{
    if (!strcmp(symbol, "_bcopy")) {
        static addr_t val = 0;
        if (val) {
            return val;
        }
        if (IS64(p)) {
            val = pre_alloc_sect(p, size, (sizeof(bcopy_arm64) + 3) & ~3);
            if (!val) {
                return 0;
            }
            memcpy(p + val, bcopy_arm64, sizeof(bcopy_arm64));
        } else {
            val = pre_alloc_sect(p, size, (sizeof(bcopy_armv7) + 3) & ~3);
            if (!val) {
                return 0;
            }
            memcpy(p + val, bcopy_armv7, sizeof(bcopy_armv7));
            val++;
        }
        val += base;
        return val;
    }
    if (
#if 0
        !strcmp(symbol, "_current_task") ||
#endif
        !strcmp(symbol, "__ZN12IOUserClient18clientHasPrivilegeEPvPKc") ||
        0) {
        static addr_t val = 0;
        if (val) {
            return val;
        }
        if (IS64(p)) {
            val = pre_alloc_sect(p, size, (sizeof(ret0_arm64) + 3) & ~3);
            if (!val) {
                return 0;
            }
            memcpy(p + val, ret0_arm64, sizeof(ret0_arm64));
        } else {
            val = pre_alloc_sect(p, size, (sizeof(ret0_arm32) + 3) & ~3);
            if (!val) {
                return 0;
            }
            memcpy(p + val, ret0_arm32, sizeof(ret0_arm32));
            val++;
        }
        val += base;
        return val;
    }
    return 0;
}

static addr_t
solver_kern(addr_t vm_kernel_slide, const char *symbol)
{
    addr_t val;
    if (!strcmp(symbol, "_kernel_base")) {
        return kernel_base;
    }
    if (!strcmp(symbol, "_get_task_ipcspace")) {
        val = solver(NULL, 0, 0, vm_kernel_slide, "_ipc_port_copyout_send", NULL, 0);
        if (val) {
            /* look in pthread_callbacks, _get_task_ipcspace is right above _ipc_port_copyout_send */
            size_t size;
            addr_t i, data = get_sect_data(kernel, kernel_size, "__DATA", "__data", &size);
            if (IS64(kernel)) {
                const uint64_t *kptr = (uint64_t *)(kernel + data);
                for (i = 0; i < size / 8; i++) {
                    if (kptr[i] == val) {
                        return kptr[i - 1];
                    }
                }
            } else {
                const uint32_t *kptr = (uint32_t *)(kernel + data);
                for (i = 0; i < size / 4; i++) {
                    if (kptr[i] == val) {
                        return kptr[i - 1];
                    }
                }
            }
        }
    }
    if (!strcmp(symbol, "_ipc_port_copyout_send")) {
        size_t size;
        addr_t x, z, end;
        /* find fileport_alloc() */
        x = find_sref(kernel, kernel_size, "\"Couldn't allocate send right for fileport!\\n\"", 0);
        if (!x) {
            return 0;
        }
        if (IS64(kernel)) {
            uint64_t y;
            long long w;
            /* find panic() call */
            x = step_64(kernel, x, 0x10, 0x94000000, 0xFC000000);
            if (!x) {
                return 0;
            }
            /* next call should be to ipc_port_copyout_send() if fileport_alloc() was inline */
            z = step_64(kernel, x + 4, 0x10, 0x94000000, 0xFC000000);
            if (z) {
                /* follow the call and return that */
                w = *(uint32_t *)(kernel + z) & 0x3FFFFFF;
                w <<= 64 - 26;
                w >>= 64 - 26 - 2;
                return z + w + kernel_base;
            }
            /* no next call, fileport_alloc() was probably not inline, find ret nearby */
            x = step_64(kernel, x, 0x18, 0xd65f03c0, 0xFFFFFFFF);
            if (!x) {
                return 0;
            }
            /* found ret, now go to bof... */
            z = get_sect_data(kernel, kernel_size, "__TEXT", "__text", &size);
            y = bof64(kernel, z, x);
            if (!y) {
                return 0;
            }
            /* ... and find an xref call to it */
            for (end = z + size; z < end; z += 4) {
                z = step_64(kernel, z, end - z, 0x94000000, 0xFC000000);
                if (!z) {
                    break;
                }
                w = *(uint32_t *)(kernel + z) & 0x3FFFFFF;
                w <<= 64 - 26;
                w >>= 64 - 26 - 2;
                x = z + w;
                if (x == y) {
                    /* ok got the caller of fileport_alloc(), now find next call */
                    z = step_64(kernel, z + 4, 0x20, 0x94000000, 0xFC000000);
                    if (z) {
                        w = *(uint32_t *)(kernel + z) & 0x3FFFFFF;
                        w <<= 64 - 26;
                        w >>= 64 - 26 - 2;
                        return z + w + kernel_base;
                    }
                    break;
                }
            }
        } else {
            uint32_t y, w;
            /* find panic() call */
            x = step_thumb(kernel, x, 0x10, 0xD000F000, 0xD000F800);
            if (!x) {
                return 0;
            }
            /* next call should be to ipc_port_copyout_send() if fileport_alloc() was inline */
            z = step_thumb(kernel, x + 4, 0x10, 0xD000F000, 0xD000F800);
            if (z) {
                /* follow the call and return that */
                y = z + insn_bl_imm32((uint16_t *)(kernel + z)) + 4;
                return y + kernel_base + 1;
            }
            /* no next call, fileport_alloc() was probably not inline, find ret nearby */
            x = step_thumb(kernel, x, 0x10, 0xBD00, 0xFF00);
            if (!x) {
                return 0;
            }
            /* found ret, now go to bof... */
            z = get_sect_data(kernel, kernel_size, "__TEXT", "__text", &size);
            y = bof32(kernel, z, x);
            if (!y) {
                return 0;
            }
            /* ... and find an xref call to it */
            for (end = z + size; z < end; z += 4) {
                z = step_thumb(kernel, z, end - z, 0xD000F000, 0xD000F800);
                if (!z) {
                    break;
                }
                w = z + insn_bl_imm32((uint16_t *)(kernel + z)) + 4;
                if (w == y) {
                    /* ok got the caller of fileport_alloc(), now find next call */
                    z = step_thumb(kernel, z + 4, 0x20, 0xD000F000, 0xD000F800);
                    if (z) {
                        y = z + insn_bl_imm32((uint16_t *)(kernel + z)) + 4;
                        return y + kernel_base + 1;
                    }
                    break;
                }
            }
        }
    }
    if (!strcmp(symbol, "_kernel_pmap")) {
        if (IS64(kernel)) {
            addr_t bof;
            addr_t ret;
            addr_t call;
            size_t size;
            addr_t sect;
            // find beginning of function containing this string
            bof = find_sref(kernel, kernel_size, "\"pmap_map_bd\"", 1);
            if (!bof) {
                return 0;
            }
            // get text section info
            sect = get_sect_data(kernel, kernel_size, "__TEXT", "__text", &size);
            if (!sect) {
                return 0;
            }
            // find ret
            ret = step_64(kernel, bof, 0x1000, 0xD65F03C0, 0xFFFFFFFF);
            if (!ret) {
                return 0;
            }
            // find last call before ret
            call = step_64_back(kernel, ret, 0x40, 0x94000000, 0xFC000000);
            if (!call) {
                return 0;
            }
            // calculate x2 ref at the time of call
            val = calc64(kernel, bof, call, 2);
        } else {
            val = find_pmap_location(kernel_base, kernel, kernel_size);
        }
        if (val) {
            return kernel_base + val;
        }
    }
    if (!strcmp(symbol, "gPhysAddr64")) {
        if (IS64(kernel)) {
            addr_t bof;
            addr_t sub;
            addr_t site;
            unsigned insn;
            // find function containing this string
            site = find_sref(kernel, kernel_size, "\"mdevadd: attempt to add overlapping memory device at %016llX-%016llX\\n\"", 0);
            if (!site) {
                return 0;
            }
            // find beginning of this function
            bof = bof64(kernel, 0, site);
            if (!bof) {
                return 0;
            }
            // find sub reg, reg
            sub = step_64_back(kernel, site, 0x40, 0x4B000000, 0x7FC0FC00);
            if (!sub) {
                return 0;
            }
            // find subtracted register address
            insn = *(uint32_t *)(kernel + sub);
            val = calc64(kernel, bof, sub, (insn >> 16) & 0x1F);
            if (val) {
                return kernel_base + val;
            }
        }
    }
    if (!strcmp(symbol, "__Z16OSUnserializeXMLPKcPP8OSString")) {
        // find bof of sref to "OSUnserializeXML: %s near line %d\n"
        // WARNING: but that may be __Z21OSUnserializeXMLparsePv
    }
    if (!strcmp(symbol, "__ZN6OSKext21withPrelinkedInfoDictEP12OSDictionary")) {
        // find sref to "OSBundleRamDiskOnly" in "__KLD"
        // from there, find first BEQ/BNE and follow it
        // from there, find first BL call and follow it
        // WARNING: doesn't work online on a running kernel, because __KLD segment is gone
        // WARNING: doesn't work offline on a dumped kernel, because addresses mismatch
        // (works offline on a decrypted kernel)
#ifndef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        addr_t x;
        uint8_t *str;
        size_t size;
        addr_t sect;

        str = boyermoore_horspool_memmem(kernel, kernel_size, (uint8_t *)"OSBundleRamDiskOnly", sizeof("OSBundleRamDiskOnly"));
        if (!str) {
            return 0;
        }
        sect = get_sect_data(kernel, kernel_size, "__KLD", "__text", &size);
        if (!sect) {
            return 0;
        }
        if (IS64(kernel)) {
            uint64_t y;
            x = xref64(kernel, sect, sect + size, str - kernel);
            if (!x) {
                return 0;
            }
            x = step_64(kernel, x, 0x100, 0x36000000,  0x7E000000);
            if (!x) {
                return 0;
            }
            x += (*(uint32_t *)(kernel + x) & 0xFFFE0) >> 3;
            x = step_64(kernel, x, 0x10, 0x94000000, 0xFC000000);
            if (!x) {
                return 0;
            }
            y = get_vaddr(kernel, kernel_size, x);
            if (!y) {
                return 0;
            }
            return y + ((*(int *)(kernel + x) << 6) >> 4);
        } else {
            uint32_t y;
            x = xref32(kernel, sect, sect + size, str - kernel);
            if (!x) {
                return 0;
            }
            x = step_thumb(kernel, x, 0x100, 0xD000, 0xFE00);
            if (!x) {
                return 0;
            }
            x += kernel[x] * 2 + 4;
            x = step_thumb(kernel, x, 0x10, 0xD000F000, 0xD000F800);
            if (!x) {
                return 0;
            }
            y = get_vaddr(kernel, kernel_size, x);
            if (!y) {
                return 0;
            }
            return y + insn_bl_imm32((uint16_t *)(kernel + x)) + 4 + 1;
        }
#endif	/* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */
    }
    if (!strcmp(symbol, "__ZN6OSKext22loadKextWithIdentifierEPKcbbhhP7OSArray")) {
        val = find_sref(kernel, kernel_size, "Can't load kext %s - not found.", 1);
        if (val) {
            if (IS64(kernel)) {
                return val + kernel_base;
            } else {
                return val + kernel_base + 1;
            }
        }
    }
    if (!strcmp(symbol, "__ZN6OSKext33sendAllKextPersonalitiesToCatalogEb")) {
        val = find_sref(kernel, kernel_size, "but not starting matching", 1);
        if (val) {
            if (IS64(kernel)) {
                return val + kernel_base;
            } else {
                return val + kernel_base + 1;
            }
        }
    }
    if (!strcmp(symbol, "_IOSimpleLockLock")) {
        return solver(NULL, 0, 0, vm_kernel_slide, "_lck_spin_lock", NULL, 0);
    }
    if (!strcmp(symbol, "_IOSimpleLockUnlock")) {
        return solver(NULL, 0, 0, vm_kernel_slide, "_lck_spin_unlock", NULL, 0);
    }
    return 0;
}

static addr_t
solver_deps(uint8_t *p, size_t size, addr_t base, addr_t vm_kernel_slide, const char *symbol, struct dependency *deps, int ndep)
{
    addr_t val;

    while (ndep > 0) {
        if (!strcmp(deps->name, "com.apple.driver.AppleARMPlatform")) {
            if (!strcmp(symbol, "__ZN22AppleARMNORFlashDevice9metaClassE")) {
                if (IS64(kernel)) {
                    return find_metaclass64(deps->buf, deps->size, deps->base, "AppleARMNORFlashDevice");
                } else {
                    return find_metaclass32(deps->buf, deps->size, deps->base, "AppleARMNORFlashDevice");
                }
            }
        }
        ndep--;
        deps++;
    }
    return 0;
}
