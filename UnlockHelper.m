// UnlockHelper.m —— v2：直接写 JnZ1Hub 的解锁标志（bss）
//
// 逆向依据（0x1b8aec handler 成功分支）：
//   func.001bbf84 之后：stlr w8=1 → [JnZ1Hub+0x13e9080]（解锁标志，__common）
//   以及 [JnZ1Hub+0x13e9084] = 1（配套标志）
//   授权轮询（AuthTickTime）可能周期性清零 → 持续线程每秒重写。
// 无 hook、无对抗痕迹；反作弊仍由 JnZ1Hub 本体承担。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>

static const uint64_t kFlagUnlock  = 0x13e9080;   // stlr w8=1（验证成功标志）
static const uint64_t kFlagUnlock2 = 0x13e9084;   // 配套标志
static const uint64_t kMenuExpire  = 0x13e9038;   // 0x13e9000 区状态块

static int64_t JnZ1HubLoadAddr(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "JnZ1Hub.dylib") != NULL) {
            return (int64_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

static void WriteFlags(void) {
    int64_t base = JnZ1HubLoadAddr();
    if (!base) return;
    volatile int *f1 = (volatile int *)(base + kFlagUnlock);
    volatile int *f2 = (volatile int *)(base + kFlagUnlock2);
    *f1 = 1;
    *f2 = 1;
}

__attribute__((constructor))
static void UnlockHelperInit(void) {
    @autoreleasepool {
        WriteFlags();
        // JnZ1Hub 的授权轮询（AuthTickTime）可能清零标志 → 常驻线程每秒重写
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            for (;;) {
                [NSThread sleepForTimeInterval:1.0];
                WriteFlags();
            }
        });
    }
}
