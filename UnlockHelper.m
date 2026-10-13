// UnlockHelper.m —— v4：运行时调用 JnZ1Hub 的 payload 解析函数喂伪造命令流
//
// 逆向依据（func.0016f2b8 @JnZ1Hub，服务器 payload = 二进制命令流，非 JSON）：
//   命令字节流逐字节分发：
//     0x02 → func.001bbf84（apply 授权数据，有前置条件检查）
//     0x03 → 解锁标志（stlr 1 → 0x13e9080/0x13e9084）+ 状态指针（0x25f0ce8）
//     0x06 <len> <data> / 0x00 / 0x01 / 0x04 / 0x05 / 0xff → 其它控制
//   服务器解密后的明文即此命令流。我们直接构造 [0x03] 调用 func.0016f2b8(data,len)，
//   走 JnZ1Hub 自己的完整解锁逻辑（含 v108 裸写内存漏掉的状态指针设置）。
//   零 hook、零对抗痕迹；反作弊仍由 JnZ1Hub 本体承担。

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>

// JnZ1Hub 内偏移（静态分析定值，v19.7.3 宿主 dylib）
static const uint64_t kOffParse = 0x16f2b8;  // func.0016f2b8(data,len) 命令流解析

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

static void FeedUnlockStream(void) {
    int64_t base = JnZ1HubLoadAddr();
    if (!base) return;

    // 伪造命令流：0x03 = 解锁标志 + 状态指针（JnZ1Hub 完整逻辑）
    uint8_t stream[] = { 0x03 };
    int (*parse)(uint8_t *, int) = (int (*)(uint8_t *, int))(base + kOffParse);
    int ret = parse(stream, (int)sizeof(stream));

    static int logged = 0;
    if (!logged) {
        NSLog(@"[UnlockHelper] parse(0x03) ret=%d", ret);
        logged = 1;
    }
}

__attribute__((constructor))
static void UnlockHelperInit(void) {
    @autoreleasepool {
        // 等宿主完全初始化（其构造函数链先跑完），再喂命令
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            FeedUnlockStream();
            // 周期重喂（防授权轮询清零标志）
            for (int i = 0; i < 60; i++) {
                [NSThread sleepForTimeInterval:5.0];
                FeedUnlockStream();
            }
        });
    }
}
