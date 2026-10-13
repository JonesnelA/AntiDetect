// UnlockHelper.m —— v5：GOT 槽重定向 + 伪造授权 payload
//
// 模型（v114 测试修正）：JnZ1Hub 的授权状态由心跳持续管理，本地写标志/喂命令会被
// 服务器心跳重置。必须拦截「解密服务器响应」这一层，把服务器的任何响应都替换成
// 解锁命令流——这样无论服务器发什么（包括拒绝），JnZ1Hub 收到的都是授权。
//
// 实现方式（零 inline patch，作用域天然限定 JnZ1Hub）：
//   1. dlsym 拿 CCCryptorGCMOneshotDecrypt 真地址
//   2. 遍历 JnZ1Hub 的 __DATA_CONST.__got，找到值==真地址的槽（即它的解密绑定槽）
//   3. mach_vm_protect 改 RW → 槽值替换为 my_gcm_decrypt
//   → 只有 JnZ1Hub 的 GCM 解密调用经过我们；数美/游戏走自己的槽不受影响
//
// my_gcm_decrypt 逻辑：
//   调真函数（GCM tag 由真解密验证，无破绽）→ 检查明文是否命令流特征
//   （长度 8~1024 且首字节 ∈ {2,3,6}，与随机数据/JSON 可区分）→ 命中且未替换过
//   → 输出覆写为解锁命令流 [0x02,0x03]（apply + 解锁标志，走 JnZ1Hub 完整逻辑）

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <dlfcn.h>
#import <string.h>

// ---- CCCryptorGCMOneshotDecrypt 真实签名（CommonCrypto）----
// CCCryptorStatus CCCryptorGCMOneshotDecrypt(
//     CCAlgorithm alg, CCOptions options,
//     const void *key, size_t keyLength,
//     const void *iv, size_t ivLen,
//     const void *cipherIn, size_t cipherInLen,
//     const void *aData, size_t aDataLen,
//     void *plainOut,
//     const void *tagData, size_t tagLength);
typedef int (*gcm_decrypt_fn)(unsigned int, unsigned int,
                              const void *, size_t,
                              const void *, size_t,
                              const void *, size_t,
                              const void *, size_t,
                              void *,
                              const void *, size_t);

static gcm_decrypt_fn orig_gcm_decrypt;
static int g_replaced;               // 只替换一次
static int64_t g_jzBase;

static int my_gcm_decrypt(unsigned int alg, unsigned int options,
                          const void *key, size_t keyLen,
                          const void *iv, size_t ivLen,
                          const void *cipherIn, size_t cipherInLen,
                          const void *aData, size_t aDataLen,
                          void *plainOut,
                          const void *tagData, size_t tagLen) {
    int ret = orig_gcm_decrypt(alg, options, key, keyLen, iv, ivLen,
                               cipherIn, cipherInLen, aData, aDataLen,
                               plainOut, tagData, tagLen);
    if (ret != 0 || g_replaced || !plainOut || cipherInLen < 8 || cipherInLen > 4096)
        return ret;

    uint8_t *plain = (uint8_t *)plainOut;
    uint8_t b0 = plain[0];
    // 命令流特征：首字节为合法命令字，且全段无大段 ASCII 文本（JSON/日志可区分）
    if ((b0 == 0x02 || b0 == 0x03 || b0 == 0x06) && cipherInLen >= 8) {
        int asciiish = 0;
        for (size_t k = 0; k < cipherInLen; k++)
            if (plain[k] >= 0x20 && plain[k] < 0x7f) asciiish++;
        if (asciiish > (int64_t)(cipherInLen * 0.7)) return ret; // 文本，非命令流

        // 命中：覆写为解锁命令流 [0x02, 0x03]（apply + 解锁标志）
        plain[0] = 0x02;
        plain[1] = 0x03;
        for (size_t k = 2; k < cipherInLen; k++) plain[k] = 0xff; // NOOP 填充
        g_replaced = 1;
        NSLog(@"[UnlockHelper] GCM payload replaced (len=%zu)", cipherInLen);
    }
    return ret;
}

static int64_t JnZ1HubLoadAddr(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "JnZ1Hub.dylib") != NULL)
            return (int64_t)_dyld_get_image_header(i);
    }
    return 0;
}

// 扫 JnZ1Hub 的 __got/__la_symbol_ptr 段，找值==真地址的槽并重定向
static int RedirectGot(int64_t base, void *realFn, void *myFn) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    const struct load_command *lc = (const struct load_command *)p;
    int redirected = 0;

    for (uint32_t c = 0; c < mh->ncmds; c++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            BOOL isGot = (strcmp(seg->segname, "__DATA_CONST") == 0);
            const struct section_64 *sec = (const struct section_64 *)((uint8_t *)lc + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if (isGot && (strcmp(sec->sectname, "__got") == 0 ||
                              strcmp(sec->sectname, "__auth_got") == 0)) {
                    void **slot = (void **)(base + sec->addr);
                    for (uint64_t k = 0; k < sec->size / 8; k++) {
                        if (slot[k] == realFn) {
                            mach_vm_address_t pageAddr = ((mach_vm_address_t)(slot + k)) & ~0xFFFULL;
                            mach_vm_size_t pageSize = 0x1000;
                            if (mach_vm_protect(mach_task_self(), pageAddr, pageSize, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
                                slot[k] = myFn;
                                redirected++;
                                NSLog(@"[UnlockHelper] GOT slot redirected @ page %llx", (unsigned long long)pageAddr);
                            } else {
                                NSLog(@"[UnlockHelper] vm_protect failed @ %llx", (unsigned long long)pageAddr);
                            }
                        }
                    }
                }
                sec++;
            }
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return redirected;
}

__attribute__((constructor))
static void UnlockHelperInit(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            int64_t base = JnZ1HubLoadAddr();
            if (!base) { NSLog(@"[UnlockHelper] JnZ1Hub not found"); return; }

            void *real = dlsym(RTLD_DEFAULT, "CCCryptorGCMOneshotDecrypt");
            if (!real) { NSLog(@"[UnlockHelper] dlsym GCM decrypt failed"); return; }
            orig_gcm_decrypt = (gcm_decrypt_fn)real;

            int n = RedirectGot(base, real, (void *)my_gcm_decrypt);
            NSLog(@"[UnlockHelper] redirected %d GOT slot(s)", n);
        });
    }
}
