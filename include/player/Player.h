#pragma once
#include "Concepts.h"
#include "Network.h"
#include <tuple>
#include <utility>

namespace ppc::mpc::player {

constexpr inline struct ID {
    int operator()(auto& player, auto&&... args) const { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} id{};

constexpr inline struct Players {
    int operator()(auto& player, auto&&... args) const { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} players{};

constexpr inline struct Algorithm {
    AlgorithmType operator()(auto& player, auto&&... args) const { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} algorithm{};

constexpr inline struct CreateSecret {
    std::tuple<PrivateKeySlice, PublicKey> operator()(auto& player, network::Network auto& network, BytesConstView keyID, auto&&... args) const {
        return tag_invoke(*this, player, network, keyID, std::forward<decltype(args)>(args)...);
    }
} createSecret{};

constexpr inline struct Sign {
    auto operator()(auto& player, network::Network auto& network, BytesConstView keyID, auto&&... args) const -> int {
        return tag_invoke(*this, player, network, keyID, std::forward<decltype(args)>(args)...);
    }
} sign{};

}  // namespace ppc::mpc::player