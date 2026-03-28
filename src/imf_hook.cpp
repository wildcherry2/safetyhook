#include "safetyhook/imf_hook.hpp"

std::expected<safetyhook::InlineToMemberFunctionHook, safetyhook::InlineToMemberFunctionHook::IMFHError>
safetyhook::InlineToMemberFunctionHook::create(void* target, void* instance, void* static_invoker,
    const BindingThunk::ABISignature& target_signature, const Flags flags) {

    InlineToMemberFunctionHook hook{};
    if (const auto setup_result = hook.setup(target, instance, static_invoker, target_signature, flags))
        return std::unexpected(*setup_result);
    return hook;
}
std::expected<void, safetyhook::InlineHook::Error> safetyhook::InlineToMemberFunctionHook::enable() {
    return m_hook.enable();
}
std::expected<void, safetyhook::InlineHook::Error> safetyhook::InlineToMemberFunctionHook::disable() {
    return m_hook.disable();
}
bool safetyhook::InlineToMemberFunctionHook::enabled() const {
    return m_hook.enabled();
}

std::optional<safetyhook::InlineToMemberFunctionHook::IMFHError> safetyhook::InlineToMemberFunctionHook::setup(
    void* target, void* instance, void* static_invoker, const BindingThunk::ABISignature& signature,
    const Flags flags) {

    BindingThunk::EBindingThunkType thunk_flags = flags & PackArgs ? BindingThunk::EBindingThunkType::Argument : BindingThunk::EBindingThunkType::Default;
    if (flags & SaveContext) thunk_flags |= BindingThunk::EBindingThunkType::Register;
    BindingThunk::FThunkResult binding_thunk = BindingThunk::GenerateBindingThunk(static_invoker, instance, signature, thunk_flags);
    if (!binding_thunk) return binding_thunk.error();
    m_binder = std::move(*binding_thunk);

    auto hook_result = InlineHook::create(target, binding_thunk->get(), InlineHook::StartDisabled);
    if (!hook_result) return hook_result.error();
    m_hook = std::move(*hook_result);

    if (flags & PackArgs || flags & SaveContext) {
        BindingThunk::FThunkResult restore_thunk = BindingThunk::GenerateRestoreThunk(m_hook.original<void*>(), signature, thunk_flags);
        if (!restore_thunk) return restore_thunk.error();\
        m_restorer = std::move(*restore_thunk);
    }

    if (flags & StartDisabled) return std::nullopt;
    if (auto enable_result = m_hook.enable(); !enable_result)
        return enable_result.error();
    return std::nullopt;
}