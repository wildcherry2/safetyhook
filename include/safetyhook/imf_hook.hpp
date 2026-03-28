#pragma once
#include "BindingThunk/BindingThunk.hpp"
#include "BindingThunk/RestoreThunk.hpp"
#include "safetyhook/inline_hook.hpp"

#include <variant>

namespace safetyhook {
/** @brief An inline hook whose destination is a member function with a specific instance.
 * @note The instance must outlive the hook.
 * @attention Detouring functions that return by value but are implicitly references at the ABI level will not work
 * with the templated @ref InlineToMemberFunctionHook::create functions.
 * @attention The templated helpers are Windows only. Trying to use them outside of Windows will throw a compile error
 * in BindingThunk.
 */
class SAFETYHOOK_API InlineToMemberFunctionHook final {
public:
    enum Flags : int {
        Default = 0,            ///< Default flags.
        StartDisabled = 1 << 0, ///< Start the hook disabled.
        SaveContext = 1 << 1, ///< Save and restore non-argument register context before calling the original function.
        PackArgs = 1 << 2,    ///< Pack arguments into an ArgumentContext& during binding.
    };

    enum CreateError : int { IncorrectUsageOfArgumentContext = 0 };

    /**@brief Error types that can be returned by this hook. */
    using IMFHError = std::variant<InlineHook::Error, BindingThunk::FThunkError, CreateError>;

    /**
     * @brief Creates a new @c InlineToMemberFunctionHook, which packs arguments and return values into an @c
     * BindingThunk::ArgumentContext .
     * @tparam Destination The member function to detour to. The member function must take in a single argument, @c
     * BindingThunk::ArgumentContext&, and be void-returning, otherwise, it will fail at compile-time. It can be
     * virtual.
     * @tparam Flag Bitwise combination of flags. If @enum Flags::PackArgs is not set, it will automatically be set.
     * @tparam TargetReturnType The return type of the target function.
     * @tparam TargetArgs The arguments of the target function.
     * @param instance The instance to bind to. You may need to cast it to match the type expected by the @p Destination
     * member function.
     * @param target The target function to detour. Its signature must be TargetReturnType(*)(TargetArgs...)
     * @return The @c InlineToMemberFunctionHook, or an error variant.
     */
    template <auto Destination, Flags Flag, typename TargetReturnType, typename... TargetArgs>
        requires(BindingThunk::MemberFunctionValue<Destination> && static_cast<bool>(Flag & PackArgs))
    static std::expected<InlineToMemberFunctionHook, IMFHError> create(
        BindingThunk::MemberFunctionHelper<decltype(Destination)>::ClassType* instance,
        TargetReturnType (*target)(TargetArgs...)) {
        using Helper = BindingThunk::MemberFunctionHelper<decltype(Destination)>;
        static_assert(Helper::IsArgumentContextCallback,
            "To use the PackArgs flag, you must have a valid ArgumentContext-signature member function "
            "(void(Class::*)(ArgumentContext&))!");
        constexpr BindingThunk::EBindingThunkType thunk_flags =
            BindingThunk::EBindingThunkType::Argument |
            (Flag & SaveContext ? BindingThunk::EBindingThunkType::Register
                                : static_cast<BindingThunk::EBindingThunkType>(0));
        BindingThunk::FThunkResult bind_result =
            BindingThunk::GenerateBindingThunk<Destination, thunk_flags, TargetReturnType, TargetArgs...>(instance);
        if (!bind_result)
            return std::unexpected(bind_result.error());

        InlineToMemberFunctionHook hook{};

        hook.m_binder = std::move(*bind_result);
        auto hook_result = InlineHook::create(target, hook.m_binder.get(), InlineHook::StartDisabled);
        if (!hook_result) return std::unexpected(hook_result.error());
        hook.m_hook = std::move(*hook_result);

        typename Helper::FreeFunctionType real_target = hook.m_hook.original<typename Helper::FreeFunctionType>();
        BindingThunk::FThunkResult restore_result = BindingThunk::GenerateRestoreThunk(real_target, thunk_flags);
        if (!restore_result)
            return std::unexpected(bind_result.error());
        hook.m_restorer = std::move(*restore_result);

        if constexpr(Flag & StartDisabled) return hook;
        if (auto enable_result = hook.enable(); !enable_result)
            return std::unexpected(enable_result.error());

        return hook;
    }

    /**
     * @brief Creates a new @c InlineToMemberFunctionHook, which forwards arguments to a member function.
     * @tparam Destination The member function to detour to. It must have the same arguments and return type
     * as the target function, and never include an ArgumentContext with this overload.
     * @tparam Flag Bitwise combination of flags. It is an error for PackArgs to be set with this overload.
     * @param instance The instance to bind to. You may need to cast it to match the type expected by the @p Destination
     * member function.
     * @param target The target function to detour. It must have the same arguments and return type as the member
     * function (excluding the @c this pointer)
     * @return The @c InlineToMemberFunctionHook, or an error variant.
     */
    template <auto Destination, Flags Flag>
        requires(BindingThunk::MemberFunctionValue<Destination> && !static_cast<bool>(Flag & PackArgs))
    static std::expected<InlineToMemberFunctionHook, IMFHError> create(
        typename BindingThunk::MemberFunctionHelper<decltype(Destination)>::ClassType* instance,
        typename BindingThunk::MemberFunctionHelper<decltype(Destination)>::FreeFunctionType target) {
        using Helper = BindingThunk::MemberFunctionHelper<decltype(Destination)>;
        static_assert(
            !Helper::ContainsArgumentContext, "ArgumentContext is not allowed without the PackArgs flag set!");

        constexpr BindingThunk::EBindingThunkType thunk_flags =
            Flag & SaveContext ? BindingThunk::EBindingThunkType::Register : BindingThunk::EBindingThunkType::Default;
        BindingThunk::FThunkResult bind_result = BindingThunk::GenerateBindingThunk<Destination, thunk_flags>(instance);
        if (!bind_result)
            return std::unexpected(bind_result.error());

        InlineToMemberFunctionHook hook{};

        hook.m_binder = std::move(*bind_result);
        auto hook_result = InlineHook::create(target, hook.m_binder.get(), InlineHook::StartDisabled);
        if (!hook_result) return std::unexpected(hook_result.error());
        hook.m_hook = std::move(*hook_result);

        if constexpr (thunk_flags == BindingThunk::EBindingThunkType::Register) {
            typename Helper::FreeFunctionType real_target = hook.m_hook.original<typename Helper::FreeFunctionType>();
            BindingThunk::FThunkResult restore_result = BindingThunk::GenerateRestoreThunk(real_target, thunk_flags);
            if (!restore_result)
                return std::unexpected(bind_result.error());
            hook.m_restorer = std::move(*restore_result);
        }

        if constexpr(Flag & StartDisabled) return hook;
        if (auto enable_result = hook.enable(); !enable_result)
            return std::unexpected(enable_result.error());

        return hook;
    }

    /**
     * @brief Creates a new @c InlineToMemberFunctionHook, with a raw ABISignature to guide binding rather than templates.
     * Note that there's not much error checking here (since the params are untyped), so messing up can easily lead to undefined behavior.
     * @param target The target function to detour.
     * @param instance The instance to bind to.
     * @param static_invoker A pointer to a static function that takes the @c this pointer with the arguments from the target,
     * invokes the member function with the provided instance, and returns the result. It's better use a free-function
     * invoker with member functions because casting pointer-to-member-functions is non-standard, especially if virtuals
     * are involved.
     * @param target_signature The @c BindingThunk::ABISignature of the target. This used to guide thunk generation, which
     * binds the 'this' pointer to the incoming arguments. You can default-construct and use the member functions to set arguments,
     * or setup using the @c BuildABISignature static helper function (Windows only).
     * @param flags Bitwise combination of flags. There's no checking to see if the flags line up with what the static invoker
     * expects (which could be the forwarded arguments or an ArgumentContext&), so it must be setup correctly.
     * @return
     */
    static std::expected<InlineToMemberFunctionHook, IMFHError> create(void* target, void* instance, void* static_invoker,
        const BindingThunk::ABISignature& target_signature, Flags flags = Default);

    InlineToMemberFunctionHook(InlineToMemberFunctionHook&& Other) noexcept = default;
    InlineToMemberFunctionHook& operator=(InlineToMemberFunctionHook&& Other) noexcept = default;
    InlineToMemberFunctionHook(const InlineToMemberFunctionHook& Other) = delete;
    InlineToMemberFunctionHook& operator=(const InlineToMemberFunctionHook& Other) = delete;

    /// @brief Enable the hook.
    [[nodiscard]] std::expected<void, InlineHook::Error> enable();

    /// @brief Disable the hook.
    [[nodiscard]] std::expected<void, InlineHook::Error> disable();

    /// @brief Check if the hook is enabled.
    [[nodiscard]] bool enabled() const;

    /// @brief Call the restore thunk, if it exists, which then forwards to the original function, otherwise call the original function.
    template <typename RetT = void, typename... Args> RetT unsafe_call(Args... args) {
        return m_restorer ? static_cast<RetT (*)(Args...)>(m_restorer.get())(args...) : m_hook.unsafe_call<RetT, Args...>(args...);
    }

    /// @brief Call the original function, ignoring the restore thunk.
    template <typename RetT = void, typename... Args> RetT unsafe_call_original(Args...args) {
        return m_hook.unsafe_call<RetT, Args...>(args...);
    }

    /// @brief Call the restore thunk.
    template <typename RetT = void, typename... Args> RetT unsafe_call_restore(Args... args) {
        return static_cast<RetT (*)(Args...)>(m_restorer.get())(args...);
    }

private:
    InlineToMemberFunctionHook() = default;

    std::optional<IMFHError> setup(void* target, void* instance, void* static_invoker,
        const BindingThunk::ABISignature& signature, Flags flags = Default);

    InlineHook m_hook{};
    BindingThunk::FThunkPtr m_binder{};
    BindingThunk::FThunkPtr m_restorer{};
};
} // namespace safetyhook