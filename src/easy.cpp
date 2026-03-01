#include "safetyhook/easy.hpp"

namespace safetyhook {
InlineHook create_inline(void* target, void* destination, InlineHook::Flags flags, OnThunkGeneratedCallback on_thunk_generated) {
    if (auto hook = InlineHook::create(target, destination, flags, std::move(on_thunk_generated))) {
        return std::move(*hook);
    } else {
        return {};
    }
}

MidHook create_mid(void* target, MidHookFn destination, MidHook::Flags flags) {
    if (auto hook = MidHook::create(target, destination, flags)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

VmtHook create_vmt(void* object) {
    if (auto hook = VmtHook::create(object)) {
        return std::move(*hook);
    } else {
        return {};
    }
}
} // namespace safetyhook