#pragma once
#include "cosigner/cmp_setup_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "player/Concepts.h"
#include "player/Player.h"

namespace ppc::mpc::player {

class PlayerImpl {
private:
    int m_id;
    int m_players;
    AlgorithmType m_algorithm;
    platform platform_service;
    fireblocks::common::cosigner::cmp_setup_service setup_service;

public:
    friend int tag_invoke(tag_t<id> /*unused*/, PlayerImpl& player) { return player.m_id; }
    friend int tag_invoke(tag_t<players> /*unused*/, PlayerImpl& player) { return player.m_players; }
    friend int tag_invoke(tag_t<algorithm> /*unused*/, PlayerImpl& player) { return player.m_algorithm; }
};

}  // namespace ppc::mpc::player