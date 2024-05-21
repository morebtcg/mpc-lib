#pragma once

#include "PlayerImpl.h"
#include "player/Concepts.h"
#include <openssl/rand.h>
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

class platform : public fireblocks::common::cosigner::platform_service {
public:
    platform(uint64_t id) : _id(id) {}

private:
    void gen_random(size_t len, uint8_t* random_data) const override { RAND_bytes(random_data, len); }

    uint64_t now_msec() const override {
        return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()).time_since_epoch().count();
    }

    const std::string get_current_tenantid() const override { return TENANT_ID; }
    uint64_t get_id_from_keyid(const std::string& key_id) const override { return _id; }
    void derive_initial_share(const fireblocks::common::cosigner::share_derivation_args& derive_from, cosigner_sign_algorithm algorithm,
        elliptic_curve256_scalar_t* key) const override {
        assert(0);
    }
    fireblocks::common::cosigner::byte_vector_t encrypt_for_player(
        uint64_t id, const fireblocks::common::cosigner::byte_vector_t& data) const override {
        return data;
    }
    fireblocks::common::cosigner::byte_vector_t decrypt_message(const fireblocks::common::cosigner::byte_vector_t& encrypted_data) const override {
        return encrypted_data;
    }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key,
        const fireblocks::common::cosigner::cmp_key_metadata& metadata, const fireblocks::common::cosigner::auxiliary_keys& aux) override {
        return true;
    }
    void start_signing(const std::string& key_id, const std::string& txid, const fireblocks::common::cosigner::signing_data& data,
        const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override { assert(0); }
    bool is_client_id(uint64_t player_id) const override { return false; }

    uint64_t _id;
};

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