#pragma once

#include "PlayerImpl.h"
#include "player/Concepts.h"
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

struct EllipticCurveAlgebraContext {
    EllipticCurveAlgebraContext(const EllipticCurveAlgebraContext&) = delete;
    EllipticCurveAlgebraContext(EllipticCurveAlgebraContext&&) = delete;
    EllipticCurveAlgebraContext& operator=(const EllipticCurveAlgebraContext&) = delete;
    EllipticCurveAlgebraContext& operator=(EllipticCurveAlgebraContext&&) = delete;
    EllipticCurveAlgebraContext(AlgorithmType type) : m_algebra(toEllipticCurveAlgebra(type)) {}
    ~EllipticCurveAlgebraContext() { elliptic_curve256_algebra_ctx_free(std::addressof(m_algebra)); }

    elliptic_curve256_algebra_ctx_t m_algebra;
};

std::tuple<PrivateKeySlice, PublicKey> tag_invoke(
    tag_t<createSecret> /*unused*/, PlayerImpl& player, network::Network auto& network, BytesConstView keyID, auto&&... args) {
    std::tuple<PrivateKeySlice, PublicKey> result;

    EllipticCurveAlgebraContext algebra(algorithm(player));
    std::vector<uint64_t> playersIDs;
}
}  // namespace ppc::mpc::player