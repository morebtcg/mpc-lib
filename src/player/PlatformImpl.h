#pragma once

#include "cosigner/platform_service.h"

namespace ppc::mpc::player {

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

}  // namespace ppc::mpc::player