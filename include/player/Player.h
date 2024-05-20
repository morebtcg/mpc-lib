#pragma once
#include <utility>

namespace ppc::mpc::player {

constexpr inline struct ID {
    auto operator()(auto& player, auto&&... args) const -> int { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} id;

constexpr inline struct TotalPlayers {
    auto operator()(auto& player, auto&&... args) const -> int { return tag_invoke(*this, player, std::forward<decltype(args)>(args)...); }
} totalPlayers;

}  // namespace ppc::mpc::player