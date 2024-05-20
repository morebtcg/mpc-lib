#pragma once
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "player/Concepts.h"
#include "player/Player.h"
#include <memory>
#include <vector>

namespace ppc::mpc::player {

elliptic_curve256_algebra_ctx_t* toEllipticCurveAlgebra(AlgorithmType type) {
    switch (type) {
    case ECDSA_SECP256K1:
        return elliptic_curve256_new_secp256k1_algebra();
    default:
        break;
    }
    return elliptic_curve256_new_secp256k1_algebra();
}

class PlayerImpl {
private:
    int m_id;
    int m_players;
    AlgorithmType m_algorithm;

public:
    friend int tag_invoke(tag_t<id> /*unused*/, PlayerImpl& player) { return player.m_id; }
    friend int tag_invoke(tag_t<players> /*unused*/, PlayerImpl& player) { return player.m_players; }
    friend int tag_invoke(tag_t<algorithm> /*unused*/, PlayerImpl& player) { return player.m_algorithm; }

    friend std::tuple<PrivateKeySlice, PublicKey> tag_invoke(
        tag_t<createSecret> /*unused*/, PlayerImpl& player, network::Network auto& network, BytesConstView keyID, auto&&... args) {
        std::tuple<PrivateKeySlice, PublicKey> result;

        std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> algebra(
            toEllipticCurveAlgebra(algorithm(player)), elliptic_curve256_algebra_ctx_free);

        std::vector<uint64_t> playersIDs;
    }
};

}  // namespace ppc::mpc::player