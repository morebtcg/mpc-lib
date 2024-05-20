#pragma once
#include "Concepts.h"
#include <utility>

namespace ppc::mpc::player {

constexpr inline struct ID {
    auto operator()(auto& player, auto&&... args) const -> int { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} id{};

constexpr inline struct TotalPlayers {
    auto operator()(auto& player, auto&&... args) const -> int { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} totalPlayers{};

constexpr inline struct CreateSecret {
    auto operator()(auto& player, AlgorithmType algorithmType, int players, auto&&... args) const -> int {
        return tag_invoke(*this, player, algorithmType, players, std::forward<decltype(args)>(args)...);
    }
} createSecret{};

}  // namespace ppc::mpc::player