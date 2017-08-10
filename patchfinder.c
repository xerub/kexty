/* --- planetbeing patchfinder --- */

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if (bit_range(imm12, 11, 10) == 0) {
        switch (bit_range(imm12, 9, 8)) {
        case 0:
            return bit_range(imm12, 7, 0);
        case 1:
            return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
        case 2:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
        case 3:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
        default:
            return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t * i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t * i)
{
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t * i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t * i)
{
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t * i)
{
    if ((*i & 0xF800) == 0xE000)
        return 1;
    else if ((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t * i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t * i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i & 0xFF) << 2;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings
static int insn_is_ldr_imm(uint16_t * i)
{
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);

    return opA == 6 && (opB & 4) == 4;
}

static int insn_ldr_imm_rt(uint16_t * i)
{
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t * i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t * i)
{
    return ((*i >> 6) & 0x1F);
}

// TODO: More encodings
static int insn_is_ldrb_imm(uint16_t * i)
{
    return (*i & 0xF800) == 0x7800;
}

static int insn_ldrb_imm_rt(uint16_t * i)
{
    return (*i & 7);
}

static int insn_ldrb_imm_rn(uint16_t * i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldrb_imm_imm(uint16_t * i)
{
    return ((*i >> 6) & 0x1F);
}

static int insn_is_ldr_reg(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return 1;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return 1;
    else
        return 0;
}

static int insn_ldr_reg_rn(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return (*i >> 3) & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*i & 0xF);
    else
        return 0;
}

int insn_ldr_reg_rt(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_ldr_reg_lsl(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return 0;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 4) & 0x3;
    else
        return 0;
}

static int insn_is_add_reg(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return 1;
    else if ((*i & 0xFF00) == 0x4400)
        return 1;
    else if ((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if ((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if ((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t * i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t * i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t * i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return 1;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return *i & 0xFF;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_is_cmp_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return 1;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return 1;
    else
        return 0;
}

static int insn_cmp_imm_rn(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return *i & 0xF;
    else
        return 0;
}

static int insn_cmp_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return *i & 0xFF;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else
        return 0;
}

static int insn_is_and_imm(uint16_t * i)
{
    return (*i & 0xFBE0) == 0xF000 && (*(i + 1) & 0x8000) == 0;
}

static int insn_and_imm_rn(uint16_t * i)
{
    return *i & 0xF;
}

static int insn_and_imm_rd(uint16_t * i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_and_imm_imm(uint16_t * i)
{
    return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
}

static int insn_is_push(uint16_t * i)
{
    if ((*i & 0xFE00) == 0xB400)
        return 1;
    else if (*i == 0xE92D)
        return 1;
    else if (*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

static int insn_push_registers(uint16_t * i)
{
    if ((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if (*i == 0xE92D)
        return *(i + 1);
    else if (*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

static int insn_is_preamble_push(uint16_t * i)
{
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

static int insn_is_str_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 1;
    else if ((*i & 0xF800) == 0x9000)
        return 1;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return 1;
    else
        return 0;
}

static int insn_str_imm_postindexed(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 1;
    else if ((*i & 0xF800) == 0x9000)
        return 1;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 10) & 1;
    else
        return 0;
}

static int insn_str_imm_wback(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 0;
    else if ((*i & 0xF800) == 0x9000)
        return 0;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 0;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 8) & 1;
    else
        return 0;
}

static int insn_str_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if ((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_str_imm_rt(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if ((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_str_imm_rn(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if ((*i & 0xF800) == 0x9000)
        return 13;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t *find_last_insn_matching(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * current_instruction, int (*match_func) (uint16_t *))
{
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (match_func(current_instruction)) {
            return current_instruction;
        }
    }

    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t *current_instruction = insn;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            found = 1;
            break;
        }

        if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while ((uintptr_t) current_instruction < (uintptr_t) insn) {
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t *) (kdata + (((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if (insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if (insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t *find_literal_ref(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * insn, uint32_t address)
{
    uint16_t *current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));

    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address = (uintptr_t) kdata + ((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if (literal_address >= (uintptr_t) kdata && (literal_address + 4) <= ((uintptr_t) kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *) (literal_address);
            }
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
                if (value[reg] == address) {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t * kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t *pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd)
        return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *) kdata, (uintptr_t) pmap_map_bd - (uintptr_t) kdata);
    if (!ptr)
        return 0;

    // Find the beginning of it (we may have a version that throws panic after the function end).
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata)
            return 0;
        ptr--;
    }

    // Find the end of it.
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = memmem(ptr, ksize - ((uintptr_t) ptr - (uintptr_t) kdata), search_function_end, sizeof(search_function_end));
    if (!ptr)
        return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl)
        return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;
            break;
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {
            break;
        }
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if (ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t) bl - (uintptr_t) kdata) + 4 + imm32;
    if (target > ksize)
        return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;

    int rd;
    current_instruction = (uint16_t *) (kdata + target);
    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if (!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall0(uint32_t region, uint8_t * kdata, size_t ksize)
{
    // Search for the preamble to syscall 1
    const uint8_t syscall1_search[] = { 0x90, 0xB5, 0x01, 0xAF, 0x82, 0xB0, 0x09, 0x68, 0x01, 0x24, 0x00, 0x23 };
    void *ptr = memmem(kdata, ksize, syscall1_search, sizeof(syscall1_search));
    if (!ptr)
        return 0;

    // Search for a pointer to syscall 1
    uint32_t ptr_address = (uintptr_t) ptr - (uintptr_t) kdata + region;
    uint32_t function = ptr_address | 1;
    void *syscall1_entry = memmem(kdata, ksize, &function, sizeof(function));
    if (!syscall1_entry)
        return 0;

    // Calculate the address of syscall 0 from the address of the syscall 1 entry
    return (uintptr_t) syscall1_entry - (uintptr_t) kdata - 0x18; // XXX 9.x should use - 0x10
}

/* --- planetbeing patchfinder --- */
