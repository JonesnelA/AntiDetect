// AntiDetect.m —— v7：JnZ1Hub 隐身三件套精确复刻
//
// 依据（2026-10-13 二分实测 + 逆向）：
//   v102 改名空壳仍被踢 → "未隐身的注入 dylib 存在"即死；
//   v95（JnZ1Hub locked）能过 → 它 locked 下就生效的隐身三件套是存活充要条件：
//     fishhook rebind 恰好 3 个函数：lstat / _dyld_image_count / _dyld_get_image_name
//     （逆向自 0x15ece4 rebind 表构造 / 0x15efc8 / 0x15f08c / 0x15f610 刷新），
//     多 rebind 一个都撞 GOT 审计（v97 教训），ObjC swizzle 陪葬（v99 教训）。
//   本文件 = 三件套 + 隐藏自身 + 中性命名，其余一律不做。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/stat.h>
#import <sys/errno.h>
#import <pthread.h>

#include "fishhook-lite.h"

#pragma mark - 隐藏规则（子串匹配 basename）

// 匹配这些子串的镜像会被隐藏（与 JnZ1Hub hide_substrs/artifacts 机制对齐）
static const char *kHideSubstrs[] = {
    "UIKitSupport",
};
static const int kHideSubstrCount = (int)(sizeof(kHideSubstrs) / sizeof(kHideSubstrs[0]));

// 越狱痕迹路径黑名单（lstat 拦截，复刻 JnZ1Hub 0x2205xx 表）
static const char * const kJBPaths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app",
    "/Applications/Zebra.app", "/Applications/Installer.app",
    "/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/stash",
    "/var/jb", "/var/lib/apt", "/var/lib/dpkg", "/var/lib/undecimus",
    "/private/var/lib/undecimus", "/usr/sbin/sshd", "/var/binpack",
    "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
};
static const int kJBPathCount = (int)(sizeof(kJBPaths) / sizeof(kJBPaths[0]));

#pragma mark - 状态（bss，对齐 JnZ1Hub 0x13d4bfc/0x13d4c00/0x13d4c60 布局）

static uint32_t g_realCount;      // 真实镜像数缓存（0 = 未扫描）
static uint32_t g_hiddenIdx[8];   // 隐藏镜像的原始下标（上限 8，同 JnZ1Hub）
static uint32_t g_hiddenCount;
static const char *(*orig_image_name)(uint32_t);
static int (*orig_lstat)(const char *, struct stat *);

static _Thread_local int t_in_hook;   // 重入保护（JnZ1Hub 用 TLV，等价实现）

#pragma mark - 刷新：扫描镜像，登记匹配隐藏规则的原始下标

static void RefreshHidden(void) {
    // 用 dlsym 直取真函数，绕开自身可能的 rebind
    uint32_t (*f_count)(void) = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
    const char *(*f_name)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    if (!f_count || !f_name) return;

    g_realCount = f_count();
    g_hiddenCount = 0;
    for (uint32_t i = 0; i < g_realCount; i++) {
        const char *name = f_name(i);
        if (!name) continue;
        const char *base = strrchr(name, '/');
        base = base ? base + 1 : name;
        for (int k = 0; k < kHideSubstrCount; k++) {
            if (strstr(base, kHideSubstrs[k]) != NULL) {
                if (g_hiddenCount < 8) g_hiddenIdx[g_hiddenCount++] = i;
                break;
            }
        }
    }
}

static BOOL IsHiddenIndex(uint32_t idx) {
    for (uint32_t k = 0; k < g_hiddenCount; k++)
        if (g_hiddenIdx[k] == idx) return YES;
    return NO;
}

// 可见下标 -> 原始下标（跳过被隐藏项；找不到返回 -1）
static long MapRealIndex(long visibleIdx) {
    long seen = -1;
    for (uint32_t i = 0; i < g_realCount; i++) {
        if (IsHiddenIndex(i)) continue;
        seen++;
        if (seen == visibleIdx) return (long)i;
    }
    return -1;
}

#pragma mark - replacement 实现（对齐 0x15efc8 / 0x15f08c / 0x15ee40）

static uint32_t my_dyld_image_count(void) {
    if (t_in_hook) return g_realCount - g_hiddenCount;
    t_in_hook = 1;
    if (g_realCount == 0) RefreshHidden();
    uint32_t n = g_realCount;
    t_in_hook = 0;
    return n - g_hiddenCount;
}

static const char *my_dyld_get_image_name(uint32_t idx) {
    if (t_in_hook) {
        return orig_image_name ? orig_image_name(idx) : _dyld_get_image_name(idx);
    }
    t_in_hook = 1;
    if (g_realCount == 0) RefreshHidden();
    // JnZ1Hub 0x15f0f8 语义：idx >= hidden 的每个隐藏项使 idx 后移一位
    uint32_t adj = idx;
    for (uint32_t k = 0; k < g_hiddenCount; k++) {
        if (idx >= g_hiddenIdx[k]) adj++;
    }
    t_in_hook = 0;
    if (adj >= g_realCount) return NULL;
    return orig_image_name ? orig_image_name(adj) : _dyld_get_image_name(adj);
}

static const struct mach_header *my_dyld_get_image_header(uint32_t idx) {
    if (t_in_hook) return _dyld_get_image_header(idx);
    t_in_hook = 1;
    if (g_realCount == 0) RefreshHidden();
    uint32_t adj = idx;
    for (uint32_t k = 0; k < g_hiddenCount; k++) {
        if (idx >= g_hiddenIdx[k]) adj++;
    }
    t_in_hook = 0;
    if (adj >= g_realCount) return NULL;
    return _dyld_get_image_header(adj);
}

static int my_lstat(const char *restrict path, struct stat *restrict buf) {
    if (path) {
        for (int i = 0; i < kJBPathCount; i++) {
            if (strcmp(path, kJBPaths[i]) == 0) { errno = ENOENT; return -1; }
        }
    }
    return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
}

#pragma mark - 安装

__attribute__((constructor))
static void AntiDetectInit(void) {
    // 真函数指针（dlsym 直取，rebind 前保存）
    orig_image_name = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");

    // 首扫
    RefreshHidden();

    // 精确三件套 rebind（JnZ1Hub 0x15ece4 同款，一步不多）
    struct rebind_entry entries[] = {
        { "lstat",                 (void *)my_lstat,                 (void **)&orig_lstat },
        { "_dyld_image_count",     (void *)my_dyld_image_count,      NULL },
        { "_dyld_get_image_name",  (void *)my_dyld_get_image_name,   (void **)&orig_image_name },
    };
    rebind_local(entries, sizeof(entries) / sizeof(entries[0]));
}
