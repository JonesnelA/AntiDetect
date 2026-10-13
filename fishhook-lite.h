// fishhook-lite: 精简版符号重绑定（MIT, 基于 facebook/fishhook 原理重写）
// 只修改本 image __DATA 中的绑定指针（non-lazy + lazy），不 patch 任何代码段。
// 注意：编译需 -Wl,-no_fixup_chains 以保证 classic bind opcode 可解析。
#ifndef FISHHOOK_LITE_H
#define FISHHOOK_LITE_H
#include <stddef.h>

struct rebind_entry {
    const char *name;       // 目标符号名（不带下划线前缀）
    void *replacement;      // 新函数指针
    void **replaced;        // [out] 保存原函数指针
};

// 对本 image 内所有匹配符号执行重绑定；返回重绑定条数。
int rebind_local(struct rebind_entry *entries, size_t count);

#endif
