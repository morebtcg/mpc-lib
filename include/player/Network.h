#pragma once
#include "Concepts.h"

namespace ppc::mpc::network {
constexpr inline struct SendMessage {
    void operator()(auto& network, PlayerID playerID, BytesConstView buffer, auto&&... args) const {
        return tag_invoke(*this, network, playerID, buffer, std::forward<decltype(args)>(args)...);
    }
} sendMessage{};

constexpr inline struct ReceiveMessage {
    auto operator()(auto& network, PlayerID playerID, std::output_iterator<std::byte> auto&& outputIterator, auto&&... args) const {
        return tag_invoke(*this, network, playerID, std::forward<decltype(outputIterator)>(outputIterator), std::forward<decltype(args)>(args)...);
    }
} receiveMessage{};

template <class NetworkType>
concept Network = requires(NetworkType& network) {
    { SendMessage(network, 0, BytesConstView{}) } -> std::same_as<void>;
    { ReceiveMessage(network, 0) } -> std::same_as<void>;
};
}  // namespace ppc::mpc::network