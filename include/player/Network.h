#pragma once
#include "Concepts.h"
#include <iterator>
#include <vector>

namespace ppc::mpc::network {
constexpr inline struct SendMessage {
    void operator()(auto& network, PlayerID playerID, std::ranges::input_range auto&& buffer, auto&&... args) const {
        return tag_invoke(*this, network, playerID, std::forward<decltype(buffer)>(buffer), std::forward<decltype(args)>(args)...);
    }
} sendMessage{};

constexpr inline struct ReceiveMessage {
    auto operator()(auto& network, PlayerID playerID, auto&& outputIterator, auto&&... args) const {
        return tag_invoke(*this, network, playerID, std::forward<decltype(outputIterator)>(outputIterator), std::forward<decltype(args)>(args)...);
    }
} receiveMessage{};

template <class NetworkType>
concept Network = requires(NetworkType& network, std::vector<std::byte> buffer) {
    { sendMessage(network, 0, BytesConstView{}) } -> std::same_as<void>;
    // { receiveMessage(network, 0, std::back_inserter(buffer)) } -> std::same_as<void>;
};
}  // namespace ppc::mpc::network