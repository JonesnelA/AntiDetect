// AntiDetect.m —— 纯过检测层 v3（最小化，仅 ObjC swizzle，零 C 层 rebind）
//
// v3 依据（2026-10-13 真机定界）：
//   v95（JnZ1Hub locked mode）在 19.7.3 不被反作弊踢 → 注入本身 + ObjC swizzle 可存活；
//   v97（v2）被踢 → 触发点在 AntiDetect 独有行为：dyld 镜像隐藏（指纹交叉验证不一致）、
//   stat/ptrace/sysctl 等 fishhook 重绑定（GOT 审计检出）。v3 全部撤掉，只保留
//   JnZ1Hub 已验证能过的行为超集的最小化：
//   E. 检测请求假响应（NSData swizzle）
//   F. 弹窗压制（UIViewController/UIApplication swizzle）
//   D. Reachability 恒可达（类存在才装）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 规则配置

static BOOL IsFakeResponseURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    // 证书/签名工具类查询域（通用规则，按需增删）
    if ([host hasSuffix:@".iosastool.online"] || [host isEqualToString:@"iosastool.online"]) return YES;
    if ([host hasSuffix:@".udid.one"] || [host isEqualToString:@"udid.one"]) return YES;
    // TODO: 真机抓到游戏检测上报 URL 后在此追加
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

static BOOL IsSystemSettingsURL(NSURL *url) {
    NSString *scheme = url.scheme.lowercaseString ?: @"";
    return [scheme isEqualToString:@"managedconfiguration"] ||
           [scheme isEqualToString:@"prefs"] ||
           [scheme isEqualToString:@"app-prefs"];
}

#pragma mark - E. NSData 假响应

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

#pragma mark - F. 弹窗压制

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

#pragma mark - D. Reachability 恒可达

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

static void SwizzleInstance(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

__attribute__((constructor))
static void AntiDetectInit(void) {
    @autoreleasepool {
        Class dataCls = [NSData class];
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:),
                     (IMP)new_dataWithContentsOfURL, (IMP *)&orig_dataWithContentsOfURL);
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:options:error:),
                     (IMP)new_dataWithContentsOfURL_opt, (IMP *)&orig_dataWithContentsOfURL_opt);

        SwizzleInstance([UIViewController class],
                        @selector(presentViewController:animated:completion:),
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
