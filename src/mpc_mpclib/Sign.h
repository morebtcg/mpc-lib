#pragma once

#include "KeyPersistencyImpl.h"
#include "NetworkImpl.h"
#include "PlatformImpl.h"
#include "PreprocessingPersistencyImpl.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "mpc/Concepts.h"
#include "mpc/Network.h"
#include "mpc/Player.h"
#include <openssl/rand.h>
#include <boost/throw_exception.hpp>
#include <vector>

namespace ppc::mpc::player {

Signature tag_invoke(tag_t<sign> /*unused*/, auto& player, auto& storage, network::Network auto& network, const KeyID& keyID, BytesConstView signData,
    const RequestID& requestID, const PrivateKeySlice& privateKeySlice) {
    auto playerID = id(player);
    auto totalPlayers = players(player);

    std::vector<uint64_t> playerIDs;
    playerIDs.reserve(totalPlayers);
    for (int i = 0; i < totalPlayers; ++i) {
        playerIDs.push_back(i);
    }
    std::set<uint64_t> playerIDSet;
    std::set<std::string> playersStr;
    for (auto i = 0; i < totalPlayers; ++i) {
        playerIDSet.insert(i);
        playersStr.insert(std::to_string(i));
    }

    PlatformImpl platform(playerID);
    KeyPersistencyImpl keyPersistency(storage);
    auto algorithmType = toMPCAlgorithm(algorithm(player));
    // elliptic_curve256_scalar_t mpcPrivateKeySlice;
    // std::ranges::copy(privateKeySlice, mpcPrivateKeySlice);
    // keyPersistency.store_key(keyID, algorithmType, mpcPrivateKeySlice, 0);

    PreprocessingPersistencyImpl preprocessingPersistency(storage);
    fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service signService(platform, keyPersistency, preprocessingPersistency);

    // Step1: mta request
    std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_request>> mtaRequests;
    auto& mtaRequest = mtaRequests[playerID];
    signService.start_ecdsa_signature_preprocessing(tenantID, keyID, requestID, 0, totalPlayers, totalPlayers, playerIDSet, mtaRequest);
    broadcastMessage(network, playerID, mtaRequest, totalPlayers);
    receiveAllMessage(network, playerID, mtaRequests, totalPlayers);

    // Step2: mta response
    std::map<uint64_t, fireblocks::common::cosigner::cmp_mta_responses> mtaResponses;
    auto& mtaResponse = mtaResponses[playerID];
    signService.offline_mta_response(requestID, mtaRequests, mtaResponse);
    broadcastMessage(network, playerID, mtaResponse, totalPlayers);
    receiveAllMessage(network, playerID, mtaResponses, totalPlayers);

    // Step3: delta
    std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_deltas>> deltas;
    auto& delta = deltas[playerID];
    signService.offline_mta_verify(requestID, mtaResponses, delta);
    broadcastMessage(network, playerID, delta, totalPlayers);
    receiveAllMessage(network, playerID, deltas, totalPlayers);

    // Store presigning data
    std::string gotKeyID;
    signService.store_presigning_data(requestID, deltas, gotKeyID);
    assert(gotKeyID == keyID);

    // Step4: signing
    const static std::vector<uint8_t> chaincode(32);
    fireblocks::common::cosigner::signing_data data{
        .chaincode = {},
    };
    auto& block = data.blocks.emplace_back();
    block.data.assign(signData.begin(), signData.end());
    block.path = {44, 60, 0, 0, 0};  // Ethereum default wallet

    std::map<uint64_t, std::vector<fireblocks::common::cosigner::recoverable_signature>> partialSigs;
    auto& partialSig = partialSigs[playerID];
    signService.ecdsa_sign(keyID, requestID, data, "", playersStr, playerIDSet, 0, partialSig);
    broadcastMessage(network, playerID, partialSig, totalPlayers);
    receiveAllMessage(network, playerID, partialSigs, totalPlayers);

    std::vector<fireblocks::common::cosigner::recoverable_signature> sigs;
    signService.ecdsa_offline_signature(keyID, requestID, algorithmType, partialSigs, sigs);
    assert(!sigs.empty());

    auto& sig = sigs.front();
    Signature signature;
    std::ranges::copy(sig.r, signature.r.data());
    std::ranges::copy(sig.s, signature.s.data());
    signature.v = sig.v;

    return signature;
}
}  // namespace ppc::mpc::player