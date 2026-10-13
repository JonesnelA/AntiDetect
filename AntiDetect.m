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

// flags 来源（按优先级）：
//   1. Documents/antidetect_flags.txt（文件 App 直接可见/可编辑，已开文件共享）
//   2. 剪贴板内容以 "antidetect:" 开头，如 antidetect:data,present
// token：data / present / openurl。两者皆无 = 全关（空壳，纯注入验证）
static void InstallHooks(NSSet<NSString *> *flags);

static void LogFlags(NSSet<NSString *> *flags) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)
                      firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"antidetect.log"];
    NSString *log = [NSString stringWithFormat:@"AntiDetect init flags=%@\n",
                     flags.allObjects ?: @"(none)"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (!fh) { [log writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:NULL]; }
    else { [fh seekToEndOfFile]; [fh writeData:[log dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
}

static NSSet<NSString *> *ParseTokens(NSString *text) {
    NSMutableSet *flags = [NSMutableSet set];
    if (!text) return flags;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:
         [NSCharacterSet newlineCharacterSet]]) {
        NSString *t = [line stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceCharacterSet]];
        if (t.length && ![t hasPrefix:@"#"]) [flags addObject:t];
    }
    return flags;
}

static NSSet<NSString *> *LoadFlags(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)
                      firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"antidetect_flags.txt"];
    NSString *text = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    NSSet *flags = ParseTokens(text);
    if (flags.count == 0) {
        // 剪贴板通道：antidetect:data,present
        NSString *clip = [UIPasteboard generalPasteboard].string ?: @"";
        if ([clip hasPrefix:@"antidetect:"]) {
            flags = ParseTokens([clip substringFromIndex:@"antidetect:".length]);
        }
    }
    LogFlags(flags);
    return flags;
}

__attribute__((constructor))
static void AntiDetectInit(void) {
    @autoreleasepool {
        InstallHooks(LoadFlags());
    }
}

static void InstallHooks(NSSet<NSString *> *flags) {
    if ([flags containsObject:@"data"]) {
        Class dataCls = [NSData class];
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:),
                     (IMP)new_dataWithContentsOfURL, (IMP *)&orig_dataWithContentsOfURL);
        SwizzleClass(dataCls, @selector(dataWithContentsOfURL:options:error:),
                     (IMP)new_dataWithContentsOfURL_opt, (IMP *)&orig_dataWithContentsOfURL_opt);
    }

    if ([flags containsObject:@"present"]) {
        SwizzleInstance([UIViewController class],
                        @selector(presentViewController:animated:completion:),
                        (IMP)new_presentVC, (IMP *)&orig_presentVC);
    }

    if ([flags containsObject:@"openurl"]) {
        Class appCls = objc_getClass("UIApplication");
        SwizzleInstance(appCls, @selector(openURL:),
                        (IMP)new_openURL, (IMP *)&orig_openURL);
        SwizzleInstance(appCls, @selector(openURL:options:completionHandler:),
                        (IMP)new_openURL_opt, (IMP *)&orig_openURL_opt);
    }
}