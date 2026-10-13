// UnlockHelper.m —— v3：先写解锁键，再 dlopen JnZ1Hub（交接文档 v47 验证过的时序）
//
// 关键（交接文档 §四.1，JUZ1Hub(49) 时代验证成功）：
//   1. 本 dylib 是唯一的 LC 注入项（zsign -l）
//   2. constructor 先写 NSUserDefaults 解锁键
//   3. 再 dlopen("@executable_path/JnZ1Hub.dylib") —— 宿主构造函数读到的键已就位
//   4. 宿主文件放在 app bundle 内但不进 LC（打包时直接放文件）
// 注意：键写入必须在宿主加载前，时序不能反（v107 zsign 双注入失败的根因）。

#import <Foundation/Foundation.h>
#import <dlfcn.h>

static void WriteUnlockKeys(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:@"0" forKey:@"JH.shop.mode"];
    [ud setObject:@"d41d8cd98f00b204e9800998ecf8427e" forKey:@"JH.shop.md5"];
    [ud setObject:@"0" forKey:@"JH.shop.size"];
    [ud synchronize];
}

__attribute__((constructor))
static void UnlockHelperInit(void) {
    @autoreleasepool {
        // 1. 先写解锁键（宿主还没加载）
        WriteUnlockKeys();

        // 2. 再动态加载宿主（此时它构造函数里读到的键已就位）
        void *h = dlopen("@executable_path/JnZ1Hub.dylib", RTLD_NOW);
        if (!h) {
            // 兜底：不带 @executable_path 直接试文件名
            h = dlopen("JnZ1Hub.dylib", RTLD_NOW);
        }

        // 3. 宿主加载后再补写一次（覆盖宿主初始化期间可能的写回）
        WriteUnlockKeys();
    }
}
