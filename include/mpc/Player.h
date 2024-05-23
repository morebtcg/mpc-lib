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
    std::tuple<PrivateKeySlice, PublicKey> operator()(
        auto& player, auto& storage, network::Network auto& network, const KeyID& keyID, auto&&... args) const {
        return tag_invoke(*this, player, storage, network, keyID, std::forward<decltype(args)>(args)...);
    }
} createSecret{};

constexpr inline struct Sign {
    Signature operator()(auto& player, auto& storage, network::Network auto& network, const KeyID& keyID, BytesConstView signData,
        const RequestID& requestID, const PrivateKeySlice& privateKeySlice, auto&&... args) const {
        return tag_invoke(*this, player, storage, network, keyID, signData, requestID, privateKeySlice, std::forward<decltype(args)>(args)...);
    }
} sign{};

template <class PlayerType>
concept Player = requires(PlayerType& player) {
    { id(player, std::string{}) } -> std::same_as<int>;
    { players(player, std::string{}) } -> std::same_as<int>;
    { algorithm(player, std::string{}) } -> std::same_as<AlgorithmType>;
};

}  // namespace ppc::mpc::player