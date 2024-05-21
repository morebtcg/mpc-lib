#pragma once
#include "cosigner/cmp_setup_service.h"
#include "player/Concepts.h"
#include "player/Player.h"

namespace ppc::mpc::player {

class PlayerImpl {
private:
    int m_id;
    AlgorithmType m_algorithm;
    int m_players;

    friend int tag_invoke(tag_t<id> /*unused*/, PlayerImpl& player) { return player.m_id; }
    friend int tag_invoke(tag_t<players> /*unused*/, PlayerImpl& player) { return player.m_players; }
    friend int tag_invoke(tag_t<algorithm> /*unused*/, PlayerImpl& player) { return player.m_algorithm; }

public:
    PlayerImpl(int id, AlgorithmType algorithm, int players) : m_id(id), m_algorithm(algorithm), m_players(players) {}
};

}  // namespace ppc::mpc::player