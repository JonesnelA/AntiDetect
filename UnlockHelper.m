// UnlockHelper.m —— JnZ1Hub 离线解锁器（不 hook 任何东西，零对抗痕迹）
//
// 职责唯一：向 NSUserDefaults 写入 JnZ1Hub 的离线解锁键（交接文档记录的绕过法），
// 配合 JnZ1Hub 自身的授权轮询时序（AuthTickTime / JH.MenuUnlock.v1）延迟+周期重写。
// 反作弊对抗完全由 JnZ1Hub 宿主承担（v95 实测 locked 可过）。
//
// 键（来自 JnZ1Hub.dylib __cstring 0x2217dc 区）：
//   JH.shop.mode  = "0"
//   JH.shop.md5   = "d41d8cd98f00b204e9800998ecf8427e"（空文件 md5）
//   JH.shop.size  = "0"
//   MenuUnlockExpireTS = 当前时间 + 10 年（菜单解锁）

#import <Foundation/Foundation.h>

static void WriteUnlockKeys(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:@"0" forKey:@"JH.shop.mode"];
    [ud setObject:@"d41d8cd98f00b204e9800998ecf8427e" forKey:@"JH.shop.md5"];
    [ud setObject:@"0" forKey:@"JH.shop.size"];
    [ud setDouble:[[NSDate date] timeIntervalSince1970] + 315360000.0
           forKey:@"MenuUnlockExpireTS"];
    [ud synchronize];
}

__attribute__((constructor))
static void UnlockHelperInit(void) {
    @autoreleasepool {
        WriteUnlockKeys();
        // JnZ1Hub 的授权轮询是异步的（AuthTickTime），延迟+周期重写保证它读到
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            for (int i = 0; i < 12; i++) {
                [NSThread sleepForTimeInterval:10.0];
                WriteUnlockKeys();
            }
        });
    }
}
