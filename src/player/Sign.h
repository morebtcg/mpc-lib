#pragma once

#include "NetworkImpl.h"
#include "PlayerImpl.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/sign_algorithm.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "player/Concepts.h"
#include "player/Network.h"
#include "player/Player.h"
#include <openssl/rand.h>
#include <boost/throw_exception.hpp>
#include <memory>
#include <stdexcept>
#include <vector>

namespace ppc::mpc::player {

void tag_invoke(tag_t<sign> /*unused*/, auto& player, network::Network auto& network, const KeyID& keyID, BytesConstView data,
    const PrivateKeySlice& privateKeySlice, const PublicKey& publicKey, auto&&... args) {
    auto playerID = id(player);
    auto totalPlayers = players(player);
    auto algorithmType = toMPCAlgorithm(algorithm(player));

    std::vector<uint64_t> playersIDs;
    playersIDs.reserve(totalPlayers);
    for (int i = 0; i < totalPlayers; ++i) {
        playersIDs.push_back(i);
    }

    PlatformImpl platform(playerID);
    KeyPersistencyImpl persistency;
    fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service signService(platform, persistency);

    // Step1: commitments
    std::map<uint64_t, fireblocks::common::cosigner::commitment> commitments;
    auto& commitment = commitments[playerID];
    setupService.generate_setup_commitments(keyID, tenantID, algorithmType, playersIDs, playersIDs.size(), 0, {}, commitment);
    broadcastMessage(network, playerID, commitment, totalPlayers);
    receiveAllMessage(network, playerID, commitments, totalPlayers);

    // Step2: decommitments
    std::map<uint64_t, fireblocks::common::cosigner::setup_decommitment> decommitments;
    auto& decommitment = decommitments[playerID];
    setupService.store_setup_commitments(keyID, commitments, decommitment);
    broadcastMessage(network, playerID, decommitment, totalPlayers);
    receiveAllMessage(network, playerID, decommitments, totalPlayers);

    // Step3: proofs
    std::map<uint64_t, fireblocks::common::cosigner::setup_zk_proofs> proofs;
    auto& proof = proofs[playerID];
    setupService.generate_setup_proofs(keyID, decommitments, proof);
    broadcastMessage(network, playerID, proof, totalPlayers);
    receiveAllMessage(network, playerID, proofs, totalPlayers);

    // Step4: verify proofs
    std::map<uint64_t, std::map<uint64_t, std::vector<uint8_t>>> paillier_large_factor_proofs;
    auto& paillierProof = paillier_large_factor_proofs[playerID];
    setupService.verify_setup_proofs(keyID, proofs, paillierProof);
    broadcastMessage(network, playerID, paillierProof, totalPlayers);
    receiveAllMessage(network, playerID, paillier_large_factor_proofs, totalPlayers);

    // Last: create secret
    std::string publicKeyStr;
    setupService.create_secret(keyID, paillier_large_factor_proofs, publicKeyStr, algorithmType);
    if (publicKeyStr.size() != sizeof(publicKey)) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Unmatch public key size!"));
    }
    assert(publicKeyStr.size() == publicKey.size());
    std::uninitialized_copy(publicKeyStr.begin(), publicKeyStr.end(), publicKey.data());

    elliptic_curve256_scalar_t privateKeyScalar;
    cosigner_sign_algorithm privateKeyAlgorithm;
    persistency.load_key(keyID, privateKeyAlgorithm, privateKeyScalar);

    assert(sizeof(privateKeyScalar) == privateKeySlice.size());
    std::uninitialized_copy(privateKeyScalar, privateKeyScalar + sizeof(privateKeyScalar), privateKeySlice.data());

    return result;
}
}  // namespace ppc::mpc::player