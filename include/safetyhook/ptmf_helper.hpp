#pragma once
#include "BindingThunk.hpp"
#include <concepts>
#include <type_traits>
namespace safetyhook {

template <auto T>
concept PointerToMemberFunction = std::is_member_function_pointer_v<decltype(T)>;

template <typename T> struct PTMFHelper;

template <typename R, typename C, typename... As> struct PTMFHelper<R (C::*)(As...)> {
    using ReturnType = R;
    using ClassType = C;
    using MFType = R (C::*)(As...);

    template <auto MF>
        requires PointerToMemberFunction<MF> && std::same_as<MFType, decltype(MF)>
    inline static ReturnType StaticInvoker(ClassType* this_, As... args) {
        return (this_->*MF)(args...);
    }

    inline static std::expected<BindingThunk::ABISignature, BindingThunk::FThunkError> GetSignature() {
        return BindingThunk::ABISignature::BuildABISignature<ReturnType, ClassType*, As...>().value();
    }
};
} // namespace safetyhook