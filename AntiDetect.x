// AntiDetect.x —— 纯过检测层（不含任何游戏功能，与 JnZ1Hub 无关）
//
// 手段均来自 JnZ1Hub.dylib 逆向还原的原理复写（jnz1_report/JnZ1Hub逆向分析报告.md §6.5）：
//   A. 注入痕迹隐藏   —— dyld 镜像列表过滤（游戏读自身镜像时看不到注入 dylib）
//   B. 越狱痕迹抹除   —— stat/lstat/access/fopen 路径黑名单返回 ENOENT
//   C. 反调试         —— ptrace(PT_DENY_ATTACH) 拦截 + sysctl P_TRACED 标志清除
//   D. 网络状态伪造   —— Reachability 全家恒可达（防误判掉线/重连）
//   E. 检测请求假响应 —— NSData/NSURLSession 按 URL 规则返回静态 JSON，其余放行
//   F. 弹窗压制       —— profile/UDID/描述文件相关 present 与 openURL 吞掉
//
// 架构约束（必须遵守，来自逆向结论）：
//   - 零 inline 修改：本 dylib 不写任何游戏代码段，全部走运行时 hook；
//   - 数据段写/断点类功能属于功能层（QiQiuTweak），不在本层实现。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/proc.h>
#import <sys/errno.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <objc/message.h>

// Apple SDK 无 sys/ptrace.h，手动声明
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

// ============================================================
// 配置区
// ============================================================

// 需要从 dyld 镜像列表里隐藏的 dylib 名（含后缀即可，子串匹配）
static NSArray<NSString *> *HiddenDylibNames(void) {
    static NSArray *arr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[@"AntiDetect.dylib", @"QiQiuTweak.dylib", @"JnZ1Hub.dylib"];
    });
    return arr;
}

// 越狱痕迹路径黑名单（返回 ENOENT）
static const char * const kJBPaths[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    "/private/var/tmp/cydia.log",
    "/var/jb",
    "/var/lib/apt",
    "/var/lib/dpkg",
    "/var/lib/undecimus",
    "/private/var/lib/undecimus",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/var/binpack",
    "/etc/apt",
    "/private/etc/apt",
    "/bin/sh",          // 未越狱设备 /bin/sh 不存在（iOS 无 shell），越狱后存在
};
static const int kJBPathCount = sizeof(kJBPaths) / sizeof(kJBPaths[0]);

static BOOL IsJBPath(const char *path) {
    if (!path) return NO;
    for (int i = 0; i < kJBPathCount; i++) {
        if (strcmp(path, kJBPaths[i]) == 0) return YES;
    }
    return NO;
}

// 假响应 URL 规则：命中的 URL 返回静态 JSON，不发给服务器。
// 默认含两类：
//   1) 应用内描述文件/证书校验域（ESign 场景的对外查询，避免暴露证书状态）
//   2) 预留游戏检测上报规则位 —— 真机抓到游戏的检测 URL 后往这里加
static BOOL IsFakeResponseURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    // 证书/签名工具类查询域（与 A神无关，通用规则，按需增删）
    if ([host hasSuffix:@".iosastool.online"] || [host isEqualToString:@"iosastool.online"]) return YES;
    if ([host hasSuffix:@".udid.one"] || [host isEqualToString:@"udid.one"]) return YES;
    // TODO: 真机日志确认游戏检测上报 URL 后在此追加，例如：
    // if ([host hasSuffix:@"game-antifraud.example.com"]) return YES;
    return NO;
}

static NSData *FakeJSONPayload(void) {
    // 与目标接口语义匹配的空数据成功响应（字段族来自逆向还原：data/status/msg/code）
    static NSData *payload;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        payload = [@"{\"data\":[],\"status\":\"ok\",\"msg\":\"\",\"code\":0}"
                   dataUsingEncoding:NSUTF8StringEncoding];
    });
    return payload;
}

// 弹窗关键词（标题/正文任一命中即压制）
static NSArray<NSString *> *SuppressKeywords(void) {
    static NSArray *arr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[@"描述文件", @"描述檔", @"Profile", @"profile", @"UDID", @"udid",
                @"企业证书", @"企业级", @"Enterprise", @"未受信任", @"Untrusted"];
    });
    return arr;
}

static BOOL ShouldSuppressText(NSString *text) {
    if (text.length == 0) return NO;
    for (NSString *kw in SuppressKeywords()) {
        if ([text rangeOfString:kw].location != NSNotFound) return YES;
    }
    return NO;
}

// ============================================================
// A. 注入痕迹隐藏：dyld 镜像列表过滤
// ============================================================
// 原理：统计需要隐藏的镜像下标，count 减去隐藏数；
//       get_image_name/header 返回时做下标重映射。
// 限制：只对"末尾加载"的注入 dylib 生效场景足够（zsign 注入的 dylib 在列表尾部）。

static int gHiddenCount = 0;   // 需要隐藏的镜像数
static NSMutableArray<NSNumber *> *gHiddenIdx; // 隐藏镜像的原始下标

// 真函数指针（dlsym 直取，绕开自身 hook，避免递归/计数错位）
static uint32_t (*real_image_count)(void);
static const char *(*real_image_name)(uint32_t);
static const struct mach_header *(*real_image_header)(uint32_t);

static void ResolveRealDyldFns(void) {
    static dispatch_once_t ronce;
    dispatch_once(&ronce, ^{
        real_image_count  = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
        real_image_name   = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        real_image_header = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    });
}

static void ScanHiddenImages(void) {
    ResolveRealDyldFns();
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gHiddenIdx = [NSMutableArray array];
        if (!real_image_count || !real_image_name) return;
        uint32_t n = real_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *name = real_image_name(i);
            if (!name) continue;
            NSString *ns = [@(name) lastPathComponent];
            for (NSString *h in HiddenDylibNames()) {
                if ([ns isEqualToString:h]) {
                    [gHiddenIdx addObject:@(i)];
                    break;
                }
            }
        }
        gHiddenCount = (int)gHiddenIdx.count;
    });
}

static BOOL IsHiddenIndex(uint32_t idx) {
    for (NSNumber *v in gHiddenIdx) if ((uint32_t)v.intValue == idx) return YES;
    return NO;
}

// 原始下标 -> 过滤后下标（返回 -1 表示该下标被隐藏）
static long MapVisibleIndex(uint32_t idx) {
    long visible = -1;
    for (uint32_t i = 0; i <= idx; i++) {
        if (IsHiddenIndex(i)) continue;
        visible++;
    }
    return visible;
}

// 可见下标 -> 原始下标
static long MapRealIndex(long visibleIdx) {
    ResolveRealDyldFns();
    if (!real_image_count) return -1;
    long seen = -1;
    uint32_t n = real_image_count();
    for (uint32_t i = 0; i < n; i++) {
        if (IsHiddenIndex(i)) continue;
        seen++;
        if (seen == visibleIdx) return (long)i;
    }
    return -1;
}

// ============================================================
// A/B/C 全部用 Logos %hookf（自动管理 orig，避免递归）
// ============================================================

%hookf(uint32_t, _dyld_image_count) {
    ScanHiddenImages();
    uint32_t n = %orig;
    return (uint32_t)(n - gHiddenCount);
}

%hookf(const char *, _dyld_get_image_name, uint32_t idx) {
    ScanHiddenImages();
    long real = MapRealIndex(idx);
    if (real < 0) return NULL;
    return %orig((uint32_t)real);
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t idx) {
    ScanHiddenImages();
    long real = MapRealIndex(idx);
    if (real < 0) return NULL;
    return %orig((uint32_t)real);
}

%hookf(int, stat, const char *restrict path, struct stat *restrict buf) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, lstat, const char *restrict path, struct stat *restrict buf) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (IsJBPath(path)) { errno = ENOENT; return NULL; }
    return %orig;
}

%hookf(int, ptrace, int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31 /* PT_DENY_ATTACH */) return 0; // 吞掉游戏侧反调试
    return %orig;
}

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = %orig;
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        // 清除 P_TRACED 标志（kinfo_proc.kp_proc.p_flag）
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// ============================================================
// E. 网络层假响应（URL 规则见 IsFakeResponseURL）
// ============================================================

%hook NSData
+ (NSData *)dataWithContentsOfURL:(NSURL *)url {
    if (IsFakeResponseURL(url)) {
        return FakeJSONPayload();
    }
    return %orig;
}
+ (NSData *)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError **)errorPtr {
    if (IsFakeResponseURL(url)) {
        if (errorPtr) *errorPtr = nil;
        return FakeJSONPayload();
    }
    return %orig;
}
%end

// ============================================================
// D. Reachability 恒可达（游戏内自带 Reachability 类，运行时解析）
// ============================================================

%hook Reachability
- (BOOL)isReachable        { return YES; }
- (BOOL)isReachableViaWiFi { return YES; }
- (BOOL)isReachableViaWWAN { return YES; }
- (BOOL)isConnectionRequired          { return NO; }
- (BOOL)connectionRequired            { return NO; }
- (BOOL)isConnectionOnDemand          { return NO; }
- (BOOL)isInterventionRequired        { return NO; }
- (void)startNotifier { /* 吞掉，配合恒可达 */ }
%end

// ============================================================
// F. 弹窗压制（profile/UDID/描述文件）
// ============================================================

%hook UIViewController
- (void)presentViewController:(UIViewController *)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)(void))completion {
    @try {
        if ([viewControllerToPresent isKindOfClass:%c(UIAlertController)]) {
            UIAlertController *ac = (UIAlertController *)viewControllerToPresent;
            if (ShouldSuppressText(ac.title) || ShouldSuppressText(ac.message)) {
                if (completion) completion();
                return; // 吞掉
            }
        }
    } @catch (NSException *e) { }
    %orig;
}
%end

%hook UIApplication
- (BOOL)openURL:(NSURL *)url {
    NSString *scheme = url.scheme.lowercaseString ?: @"";
    if ([scheme isEqualToString:@"managedconfiguration"] ||
        [scheme isEqualToString:@"prefs"] ||
        [scheme isEqualToString:@"app-prefs"]) {
        // 打开系统设置（描述文件页）一律吞掉
        return NO;
    }
    return %orig;
}
- (void)openURL:(NSURL *)url options:(NSDictionary *)options
      completionHandler:(void (^)(BOOL success))completion {
    NSString *scheme = url.scheme.lowercaseString ?: @"";
    if ([scheme isEqualToString:@"managedconfiguration"] ||
        [scheme isEqualToString:@"prefs"] ||
        [scheme isEqualToString:@"app-prefs"]) {
        if (completion) completion(NO);
        return;
    }
    %orig;
}
%end

// ============================================================
// Constructor：镜像隐藏初始化（%hookf 的 hook 由 Logos 自动安装）
// ============================================================

%ctor {
    @autoreleasepool {
        ResolveRealDyldFns();
        ScanHiddenImages();
    }
}
