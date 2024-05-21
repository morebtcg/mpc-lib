#pragma once

#include "NetworkImpl.h"
#include "PlayerImpl.h"
#include "Serialization.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/platform_service.h"
#include "cosigner/sign_algorithm.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "player/Concepts.h"
#include "player/Network.h"
#include "player/Player.h"
#include <openssl/rand.h>
#include <boost/throw_exception.hpp>
#include <memory>
#include <optional>
#include <stdexcept>
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

cosigner_sign_algorithm toMPCAlgorithm(AlgorithmType type) {
    switch (type) {
    case ECDSA_SECP256K1:
        return cosigner_sign_algorithm::ECDSA_SECP256K1;
    default:
        break;
    }
    return cosigner_sign_algorithm::ECDSA_SECP256K1;
}

constexpr static std::string tenantID = "weco";

class PlatformImpl : public fireblocks::common::cosigner::platform_service {
public:
    PlatformImpl(uint64_t playerID) : m_playerID(playerID) {}

    void gen_random(size_t len, uint8_t* random_data) const override;
    const std::string get_current_tenantid() const override;
    uint64_t get_id_from_keyid(const std::string& /*key_id*/) const override;
    void derive_initial_share(const fireblocks::common::cosigner::share_derivation_args& /*derive_from*/, cosigner_sign_algorithm /*algorithm*/,
        elliptic_curve256_scalar_t* /*key*/) const override;
    fireblocks::common::cosigner::byte_vector_t encrypt_for_player(
        uint64_t id, const fireblocks::common::cosigner::byte_vector_t& data) const override;
    fireblocks::common::cosigner::byte_vector_t decrypt_message(const fireblocks::common::cosigner::byte_vector_t& encrypted_data) const override;
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key,
        const fireblocks::common::cosigner::cmp_key_metadata& metadata, const fireblocks::common::cosigner::auxiliary_keys& aux) override;
    void start_signing(const std::string& key_id, const std::string& txid, const fireblocks::common::cosigner::signing_data& data,
        const std::string& metadata_json, const std::set<std::string>& players) override;
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override;
    bool is_client_id(uint64_t player_id) const override;
    uint64_t now_msec() const override;

    uint64_t m_playerID;
};

class PersistencyImpl : public fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency {
public:
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id, fireblocks::common::cosigner::cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id, fireblocks::common::cosigner::auxiliary_keys& aux) const override;
    void store_key(
        const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) override;
    void store_key_metadata(const std::string& key_id, const fireblocks::common::cosigner::cmp_key_metadata& metadata, bool allow_override) override;
    void store_auxiliary_keys(const std::string& key_id, const fireblocks::common::cosigner::auxiliary_keys& aux) override;
    void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) override;
    void store_setup_data(const std::string& key_id, const fireblocks::common::cosigner::setup_data& metadata) override;
    void load_setup_data(const std::string& key_id, fireblocks::common::cosigner::setup_data& metadata) override;
    void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override;
    void load_setup_commitments(const std::string& key_id, std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override;
    void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) override;

    struct KeyInfo {
        cosigner_sign_algorithm algorithm;
        elliptic_curve256_scalar_t private_key;
        std::optional<fireblocks::common::cosigner::cmp_key_metadata> metadata;
        fireblocks::common::cosigner::auxiliary_keys aux_keys;
    };

    std::map<std::string, KeyInfo> m_keys;
    std::map<std::string, fireblocks::common::cosigner::setup_data> m_setup_data;
    std::map<std::string, std::map<uint64_t, fireblocks::common::cosigner::commitment>> m_commitments;
};

std::tuple<PrivateKeySlice, PublicKey> tag_invoke(
    tag_t<createSecret> /*unused*/, PlayerImpl& player, network::Network auto& network, KeyID keyID, auto&&... args) {
    std::tuple<PrivateKeySlice, PublicKey> result;
    auto& [privateKeySlice, publicKey] = result;

    auto playerID = id(player);
    auto totalPlayers = players(player);
    auto algorithmType = toMPCAlgorithm(algorithm(player));

    std::unique_ptr<elliptic_curve256_algebra_ctx_t,
        decltype([](elliptic_curve256_algebra_ctx_t* algebra) { elliptic_curve256_algebra_ctx_free(algebra); })>
        algebra(toEllipticCurveAlgebra(algorithm(player)));
    std::vector<uint64_t> playersIDs;
    playersIDs.reserve(totalPlayers);
    for (int i = 0; i < totalPlayers; ++i) {
        playersIDs.push_back(i);
    }

    PlatformImpl platform(playerID);
    PersistencyImpl persistency;
    fireblocks::common::cosigner::cmp_setup_service setupService(platform, persistency);

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
    std::uninitialized_copy(publicKeyStr.begin(), publicKeyStr.end(), publicKey.data());

    elliptic_curve256_scalar_t privateKeyScalar;
    cosigner_sign_algorithm privateKeyAlgorithm;
    persistency.load_key(keyID, privateKeyAlgorithm, privateKeyScalar);
    std::uninitialized_copy(privateKeyScalar, privateKeyScalar + sizeof(privateKeyScalar), privateKeySlice.data());

    return result;
}
}  // namespace ppc::mpc::player