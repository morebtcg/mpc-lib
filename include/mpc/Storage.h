#pragma once

#include <utility>
namespace ppc::mpc::storage {

constexpr inline struct Read {
    template <class T>
    auto operator()(auto& storage, auto&& key) const {
        return tag_invoke<T>(*this, storage, std::forward<decltype(key)>(key));
    }
} read{};

constexpr inline struct Write {
    void operator()(auto& storage, auto&& key, auto&& value) const {
        tag_invoke(*this, storage, std::forward<decltype(key)>(key), std::forward<decltype(value)>(value));
    }
} write{};

constexpr inline struct Remove {
    void operator()(auto& storage, auto&& key) const { tag_invoke(*this, storage, std::forward<decltype(key)>(key)); }
} remove{};

}  // namespace ppc::mpc::storage