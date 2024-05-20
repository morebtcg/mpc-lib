#pragma once
#include "Concepts.h"

namespace ppc::mpc::network {
constexpr inline struct SendMessage {
    void operator()(auto& network, PlayerID playerID, BytesConstView buffer, auto&&... args) const {
        return tag_invoke(*this, network, playerID, buffer, std::forward<decltype(args)>(args)...);
    }
} sendMessage{};

constexpr inline struct ReceiveMessage {
    auto operator()(auto& network, PlayerID playerID, auto&&... args) const {
        return tag_invoke(*this, network, playerID, std::forward<decltype(args)>(args)...);
    }
} receiveMessage{};
}  // namespace ppc::mpc::network