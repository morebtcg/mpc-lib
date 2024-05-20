#pragma once
#include "Concepts.h"

namespace ppc::mpc::network {
constexpr inline struct SendAll {
    auto operator()(auto& network, BytesConstView buffer, auto&&... args) const -> int {
        return tag_invoke(*this, network, buffer, std::forward<decltype(args)>(args)...);
    }
} sendAll;

constexpr inline struct ReceiveAll {
    auto operator()(auto& network, BytesConstView buffer, auto&&... args) const -> int {
        return tag_invoke(*this, network, buffer, std::forward<decltype(args)>(args)...);
    }
} receiveAll;
}  // namespace ppc::mpc::network