// AntiDetect.m —— 纯过检测层 v2（零外部依赖：无 Logos / 无 CydiaSubstrate）
//
// hook 实现方式（对齐 JnZ1Hub 的非越狱可用架构）：
//   ObjC 层：method_exchangeImplementations（runtime API，零依赖）
//   C 层   ：fishhook-lite 符号重绑定（只改自身 __DATA 绑定指针，不 patch 代码段）
//
// 层次：
//   A. 注入痕迹隐藏   —— dyld 镜像列表过滤
//   B. 越狱痕迹抹除   —— stat/lstat/access/fopen 路径黑名单
//   C. 反调试         —— ptrace(PT_DENY_ATTACH) 拦截 + sysctl P_TRACED 清除
//   D. 网络状态伪造   —— Reachability 恒可达
//   E. 检测请求假响应 —— NSData dataWithContentsOfURL 按 URL 规则
//   F. 弹窗压制       —— profile/UDID present 与 openURL 吞掉

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/proc.h>
#import <sys/errno.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

#include "fishhook-lite.h"

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

#pragma mark - 配置

static NSArray<NSString *> *HiddenDylibNames(void) {
    static NSArray *arr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[@"AntiDetect.dylib", @"QiQiuTweak.dylib", @"JnZ1Hub.dylib"];
    });
    return arr;
}

static const char * const kJBPaths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app",
    "/Applications/Zebra.app", "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/stash",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    "/private/var/tmp/cydia.log",
    "/var/jb", "/var/lib/apt", "/var/lib/dpkg", "/var/lib/undecimus",
    "/private/var/lib/undecimus",
    "/usr/sbin/sshd", "/usr/bin/sshd",
    "/var/binpack", "/etc/apt", "/private/etc/apt",
    "/bin/sh",
};
static const int kJBPathCount = (int)(sizeof(kJBPaths) / sizeof(kJBPaths[0]));

static BOOL IsJBPath(const char *path) {
    if (!path) return NO;
    for (int i = 0; i < kJBPathCount; i++)
        if (strcmp(path, kJBPaths[i]) == 0) return YES;
    return NO;
}

static BOOL IsFakeResponseURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    // 证书/签名工具类查询域（与 A神无关的通用规则，按需增删）
    if ([host hasSuffix:@".iosastool.online"] || [host isEqualToString:@"iosastool.online"]) return YES;
    if ([host hasSuffix:@".udid.one"] || [host isEqualToString:@"udid.one"]) return YES;
    // TODO: 真机确认游戏检测上报 URL 后追加
    return NO;
}

static NSData *FakeJSONPayload(void) {
    static NSData *payload;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        payload = [@"{\"data\":[],\"status\":\"ok\",\"msg\":\"\",\"code\":0}"
                   dataUsingEncoding:NSUTF8StringEncoding];
    });
    return payload;
}

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
    for (NSString *kw in SuppressKeywords())
        if ([text rangeOfString:kw].location != NSNotFound) return YES;
    return NO;
}

#pragma mark - A. dyld 镜像隐藏（C 层，fishhook 重绑定）

static uint32_t (*real_image_count)(void);
static const char *(*real_image_name)(uint32_t);
static const struct mach_header *(*real_image_header)(uint32_t);

static int gHiddenCount = 0;
static uint32_t gHiddenIdx[16]; // 隐藏镜像的原始下标（纯 C 数组，hook 内零 ObjC 分配）

static void ScanHiddenImages(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!real_image_count || !real_image_name) return;
        uint32_t n = real_image_count();
        int c = 0;
        for (uint32_t i = 0; i < n; i++) {
            const char *name = real_image_name(i);
            if (!name) continue;
            const char *base = strrchr(name, '/');
            base = base ? base + 1 : name;
            for (NSString *h in HiddenDylibNames()) {
                if (strcmp(base, h.UTF8String) == 0) {
                    if (c < 16) gHiddenIdx[c++] = i;
                    break;
                }
            }
        }
        gHiddenCount = c;
    });
}

static BOOL IsHiddenIndex(uint32_t idx) {
    for (int i = 0; i < gHiddenCount; i++)
        if (gHiddenIdx[i] == idx) return YES;
    return NO;
}

static long MapRealIndex(long visibleIdx) {
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

static uint32_t my_dyld_image_count(void) {
    ScanHiddenImages();
    uint32_t n = real_image_count ? real_image_count() : _dyld_image_count();
    return (uint32_t)(n - gHiddenCount);
}

static const char *my_dyld_get_image_name(uint32_t idx) {
    ScanHiddenImages();
    long real = MapRealIndex(idx);
    if (real < 0) return NULL;
    return real_image_name ? real_image_name((uint32_t)real) : _dyld_get_image_name((uint32_t)real);
}

static const struct mach_header *my_dyld_get_image_header(uint32_t idx) {
    ScanHiddenImages();
    long real = MapRealIndex(idx);
    if (real < 0) return NULL;
    return real_image_header ? real_image_header((uint32_t)real) : _dyld_get_image_header((uint32_t)real);
}

#pragma mark - B/C. C 层 hook 实现（经 fishhook 重绑定）

static int (*orig_stat)(const char *, struct stat *);
static int (*orig_lstat)(const char *, struct stat *);
static int (*orig_access)(const char *, int);
static FILE *(*orig_fopen)(const char *, const char *);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static uint32_t (*orig_image_count)(void);
static const char *(*orig_image_name)(uint32_t);
static const struct mach_header *(*orig_image_header)(uint32_t);

static int my_stat(const char *restrict path, struct stat *restrict buf) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return orig_stat ? orig_stat(path, buf) : stat(path, buf);
}
static int my_lstat(const char *restrict path, struct stat *restrict buf) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
}
static int my_access(const char *path, int mode) {
    if (IsJBPath(path)) { errno = ENOENT; return -1; }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}
static FILE *my_fopen(const char *path, const char *mode) {
    if (IsJBPath(path)) { errno = ENOENT; return NULL; }
    return orig_fopen ? orig_fopen(path, mode) : fopen(path, mode);
}
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                     void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
                          : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

#pragma mark - E/F. ObjC 层 hook（method swizzle，零依赖）

// ---- NSData +dataWithContentsOfURL: 假响应 ----
static NSData *(*orig_dataWithContentsOfURL)(id, SEL, NSURL *);
static NSData *new_dataWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
    if (IsFakeResponseURL(url)) return FakeJSONPayload();
    return orig_dataWithContentsOfURL(self, _cmd, url);
}

static NSData *(*orig_dataWithContentsOfURL_opt)(id, SEL, NSURL *, NSDataReadingOptions, NSError **);
static NSData *new_dataWithContentsOfURL_opt(id self, SEL _cmd, NSURL *url,
                                             NSDataReadingOptions opts, NSError **err) {
    if (IsFakeResponseURL(url)) { if (err) *err = nil; return FakeJSONPayload(); }
    return orig_dataWithContentsOfURL_opt(self, _cmd, url, opts, err);
}

// ---- UIViewController present 压制 ----
static void (*orig_presentVC)(id, SEL, UIViewController *, BOOL, void (^)(void));
static void new_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL flag, void (^completion)(void)) {
    @try {
        if (vc && [vc isKindOfClass:[UIAlertController class]]) {
            UIAlertController *ac = (UIAlertController *)vc;
            if (ShouldSuppressText(ac.title) || ShouldSuppressText(ac.message)) {
                if (completion) completion();
                return;
            }
        }
    } @catch (NSException *e) { }
    orig_presentVC(self, _cmd, vc, flag, completion);
}

// ---- UIApplication openURL 压制（prefs/managedconfiguration scheme）----
static BOOL IsSystemSettingsURL(NSURL *url) {
    NSString *scheme = url.scheme.lowercaseString ?: @"";
    return [scheme isEqualToString:@"managedconfiguration"] ||
           [scheme isEqualToString:@"prefs"] ||
           [scheme isEqualToString:@"app-prefs"];
}

static BOOL (*orig_openURL)(id, SEL, NSURL *);
static BOOL new_openURL(id self, SEL _cmd, NSURL *url) {
    if (IsSystemSettingsURL(url)) return NO;
    return orig_openURL(self, _cmd, url);
}

static void (*orig_openURL_opt)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL));
static void new_openURL_opt(id self, SEL _cmd, NSURL *url, NSDictionary *options,
                            void (^completion)(BOOL)) {
    if (IsSystemSettingsURL(url)) { if (completion) completion(NO); return; }
    orig_openURL_opt(self, _cmd, url, options, completion);
}

// ---- Reachability 恒可达（类存在才 swizzle）----
static void SwizzleInstance(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static BOOL (*orig_isReachable)(id, SEL);
static BOOL new_isReachable(id self, SEL _cmd) { return YES; }
static BOOL (*orig_isReachableWiFi)(id, SEL);
static BOOL new_isReachableWiFi(id self, SEL _cmd) { return YES; }
static BOOL (*orig_isReachableWWAN)(id, SEL);
static BOOL new_isReachableWWAN(id self, SEL _cmd) { return YES; }
static BOOL (*orig_connRequired)(id, SEL);
static BOOL new_connRequired(id self, SEL _cmd) { return NO; }
static void (*orig_startNotifier)(id, SEL);
static void new_startNotifier(id self, SEL _cmd) { /* 吞掉 */ }

#pragma mark - 安装

static void SwizzleClass(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c) return;
    Method m = class_getClassMethod(c, sel);
    if (!m) return;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

__attribute__((constructor))
static void AntiDetectInit(void) {
    @autoreleasepool {
        // ---- C 层：fishhook 重绑定（先保存原函数指针供 dyld 隐藏用）----
        real_image_count  = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
        real_image_name   = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        real_image_header = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");

        struct rebind_entry entries[] = {
            { "stat",                (void *)my_stat,                (void **)&orig_stat },
            { "lstat",               (void *)my_lstat,               (void **)&orig_lstat },
            { "access",              (void *)my_access,              (void **)&orig_access },
            { "fopen",               (void *)my_fopen,               (void **)&orig_fopen },
            { "ptrace",              (void *)my_ptrace,              (void **)&orig_ptrace },
            { "sysctl",              (void *)my_sysctl,              (void **)&orig_sysctl },
            { "_dyld_image_count",   (void *)my_dyld_image_count,    (void **)&orig_image_count },
            { "_dyld_get_image_name",(void *)my_dyld_get_image_name, (void **)&orig_image_name },
            { "_dyld_get_image_header",(void *)my_dyld_get_image_header,(void **)&orig_image_header },
        };
        // rebind 前先把真函数指针交给 my_* 兜底（orig_* 此时尚未填充）
        real_image_count  = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
        real_image_name   = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        real_image_header = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
        ScanHiddenImages();

        rebind_local(entries, sizeof(entries) / sizeof(entries[0]));

        // ---- ObjC 层：method swizzle ----
        Class dataCls = [NSData class];
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:),
                     (IMP)new_dataWithContentsOfURL, (IMP *)&orig_dataWithContentsOfURL);
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:options:error:),
                     (IMP)new_dataWithContentsOfURL_opt, (IMP *)&orig_dataWithContentsOfURL_opt);

        SwizzleInstance([UIViewController class], @selector(presentViewController:animated:completion:),
                        (IMP)new_presentVC, (IMP *)&orig_presentVC);

        Class appCls = objc_getClass("UIApplication");
        SwizzleInstance(appCls, @selector(openURL:),
                        (IMP)new_openURL, (IMP *)&orig_openURL);
        SwizzleInstance(appCls, @selector(openURL:options:completionHandler:),
                        (IMP)new_openURL_opt, (IMP *)&orig_openURL_opt);

        Class reachCls = objc_getClass("Reachability");
        if (reachCls) {
            SwizzleInstance(reachCls, @selector(isReachable),
                            (IMP)new_isReachable, (IMP *)&orig_isReachable);
            SwizzleInstance(reachCls, @selector(isReachableViaWiFi),
                            (IMP)new_isReachableWiFi, (IMP *)&orig_isReachableWiFi);
            SwizzleInstance(reachCls, @selector(isReachableViaWWAN),
                            (IMP)new_isReachableWWAN, (IMP *)&orig_isReachableWWAN);
            SwizzleInstance(reachCls, @selector(isConnectionRequired),
                            (IMP)new_connRequired, (IMP *)&orig_connRequired);
            SwizzleInstance(reachCls, @selector(startNotifier),
                            (IMP)new_startNotifier, (IMP *)&orig_startNotifier);
        }
    }
}
