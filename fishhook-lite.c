// fishhook-lite.c —— 精简 classic-bind 符号重绑定（MIT）
// 仅处理 LC_DYLD_INFO(_ONLY) 的 bind + lazy_bind 区（配合 -Wl,-no_fixup_chains）。
// 本 image 定位用 dlsym 保存的原始 _dyld_* 函数指针，避免与自身 hook 互相干扰。
#include "fishhook-lite.h"
#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>

// ---- ULEB128 读取 ----
static uint64_t read_uleb(const uint8_t **pp, const uint8_t *end) {
    uint64_t result = 0;
    int shift = 0;
    const uint8_t *p = *pp;
    while (p < end) {
        uint8_t byte = *p++;
        result |= (uint64_t)(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    *pp = p;
    return result;
}

// ---- bind opcode 常量（SDK mach-o/bind.h 已有大部分，做缺省防护）----
#ifndef BIND_OPCODE_MASK
#define BIND_OPCODE_MASK                         0xF0
#endif
#ifndef BIND_IMMEDIATE_MASK
#define BIND_IMMEDIATE_MASK                      0x0F
#endif
#ifndef BIND_OPCODE_DONE
#define BIND_OPCODE_DONE                         0x00
#endif
#ifndef BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM        0x10
#endif
#ifndef BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB       0x20
#endif
#ifndef BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM        0x30
#endif
#ifndef BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
#endif
#ifndef BIND_OPCODE_SET_TYPE_IMM
#define BIND_OPCODE_SET_TYPE_IMM                 0x50
#endif
#ifndef BIND_OPCODE_SET_ADDEND_SLEB
#define BIND_OPCODE_SET_ADDEND_SLEB              0x60
#endif
#ifndef BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB  0x70
#endif
#ifndef BIND_OPCODE_ADD_ADDR_ULEB
#define BIND_OPCODE_ADD_ADDR_ULEB                0x80
#endif
#ifndef BIND_OPCODE_DO_BIND
#define BIND_OPCODE_DO_BIND                      0x90
#endif
#ifndef BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xA0
#endif
#ifndef BIND_OPCODE_THREADED
#define BIND_OPCODE_THREADED                     0xB0
#endif
#ifndef BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB
#define BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB 0x00
#endif
#ifndef BIND_SUBOPCODE_THREADED_APPLY
#define BIND_SUBOPCODE_THREADED_APPLY            0x01
#endif

static int g_done = 0;

static int process_image(const struct mach_header *mh, intptr_t slide,
                         struct rebind_entry *entries, size_t count) {
    const uint8_t *base = (const uint8_t *)mh;
    const struct segment_command_64 *linkedit = NULL;
    const struct dyld_info_command *dyld_info = NULL;
    const struct segment_command_64 *segs[64];
    int nsegs = 0;

    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) return 0;
    if (mh->filetype != MH_DYLIB && mh->filetype != MH_EXECUTE && mh->filetype != MH_BUNDLE) return 0;

    const struct load_command *lc = (const struct load_command *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (nsegs < 64) segs[nsegs++] = seg;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit = seg;
        } else if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
            dyld_info = (const struct dyld_info_command *)lc;
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (!linkedit || !dyld_info) return 0;

    intptr_t linkedit_base = (intptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    const uint8_t *linkedgedata = (const uint8_t *)linkedit_base;

    int rebound = 0;

    // 精确处理：两区各扫一遍，用 segment vmaddr+slide 定位槽
    {
        struct { const uint8_t *p; const uint8_t *end; } passes[2] = {
            { linkedgedata + dyld_info->bind_off,      linkedgedata + dyld_info->bind_off + dyld_info->bind_size },
            { linkedgedata + dyld_info->lazy_bind_off, linkedgedata + dyld_info->lazy_bind_off + dyld_info->lazy_bind_size },
        };
        for (int pass = 0; pass < 2; pass++) {
            const uint8_t *p = passes[pass].p;
            const uint8_t *end = passes[pass].end;
            uintptr_t seg_off = 0;
            int seg_idx = 0;
            const char *sym = NULL;
            while (p < end) {
                uint8_t op = *p++;
                uint8_t imm = op & BIND_IMMEDIATE_MASK;
                switch (op & BIND_OPCODE_MASK) {
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                        seg_idx = imm;
                        seg_off = (uintptr_t)read_uleb(&p, end);
                        break;
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        sym = (const char *)p;
                        while (*p++ != '\0') {}
                        break;
                    case BIND_OPCODE_ADD_ADDR_ULEB:
                        seg_off += (uintptr_t)read_uleb(&p, end);
                        break;
                    case BIND_OPCODE_DO_BIND: {
                        if (sym && seg_idx < nsegs) {
                            void **slot = (void **)(segs[seg_idx]->vmaddr + slide + seg_off);
                            for (size_t k = 0; k < count; k++) {
                                if (strcmp(entries[k].name, sym) == 0) {
                                    if (entries[k].replaced && !*entries[k].replaced)
                                        *entries[k].replaced = *slot;
                                    if (*slot != entries[k].replacement) {
                                        *slot = entries[k].replacement;
                                        rebound++;
                                    }
                                }
                            }
                        }
                        seg_off += sizeof(void *);
                        break;
                    }
                    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                        uint64_t times = read_uleb(&p, end);
                        read_uleb(&p, end); // skip
                        if (sym && seg_idx < nsegs) {
                            for (uint64_t t = 0; t < times; t++) {
                                void **slot = (void **)(segs[seg_idx]->vmaddr + slide + seg_off);
                                for (size_t k = 0; k < count; k++) {
                                    if (strcmp(entries[k].name, sym) == 0) {
                                        if (entries[k].replaced && !*entries[k].replaced)
                                            *entries[k].replaced = *slot;
                                        if (*slot != entries[k].replacement) {
                                            *slot = entries[k].replacement;
                                            rebound++;
                                        }
                                    }
                                }
                                seg_off += sizeof(void *);
                            }
                        } else {
                            seg_off += times * sizeof(void *);
                        }
                        break;
                    }
                    case BIND_OPCODE_DONE:
                        if (pass == 1) { /* lazy 区多符号连续 */ }
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        read_uleb(&p, end);
                        break;
                    case BIND_OPCODE_SET_ADDEND_SLEB:
                        read_uleb(&p, end);
                        break;
                    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                    case BIND_OPCODE_SET_TYPE_IMM:
                    default:
                        break;
                }
            }
        }
    }
    return rebound;
}

int rebind_local(struct rebind_entry *entries, size_t count) {
    if (g_done) return 0;
    g_done = 1;

    // 用 dlsym 直取原始 dyld 函数（若 AntiDetect 自身被 rebind 也不受影响——首次执行时还没 rebind）
    uint32_t (*f_count)(void) = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
    const char *(*f_name)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    const struct mach_header *(*f_header)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!f_count || !f_name || !f_header) return 0;

    int total = 0;
    uint32_t n = f_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *mh = f_header(i);
        const char *nm = f_name(i);
        if (!mh || !nm) continue;
        // 只处理自己这个 image（install_name 含 AntiDetect）
        const char *base = strrchr(nm, '/');
        base = base ? base + 1 : nm;
        if (strstr(base, "AntiDetect") == NULL) continue;

        intptr_t slide = (intptr_t)mh; // 对 dylib：slide = load_addr - preferred; 用 vmaddr 差值
        // 精确 slide：__TEXT vmaddr 与实际地址之差
        const struct load_command *lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64 &&
                strcmp(((const struct segment_command_64 *)lc)->segname, "__TEXT") == 0) {
                slide = (intptr_t)mh - (intptr_t)((const struct segment_command_64 *)lc)->vmaddr;
                break;
            }
            lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
        }
        total += process_image(mh, slide, entries, count);
        break; // 只处理自己
    }
    return total;
}
