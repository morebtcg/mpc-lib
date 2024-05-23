#include "PlatformImpl.h"
#include "mpc/Concepts.h"
#include <openssl/rand.h>
#include <chrono>

void ppc::mpc::player::PlatformImpl::gen_random(size_t len, uint8_t* random_data) const {
    RAND_bytes(random_data, len);
}

const std::string ppc::mpc::player::PlatformImpl::get_current_tenantid() const {
    return tenantID;
}

uint64_t ppc::mpc::player::PlatformImpl::get_id_from_keyid(const std::string& /*key_id*/) const {
    return m_playerID;
}

void ppc::mpc::player::PlatformImpl::derive_initial_share(const fireblocks::common::cosigner::share_derivation_args& /*derive_from*/,
    cosigner_sign_algorithm /*algorithm*/, elliptic_curve256_scalar_t* /*key*/) const {
    assert(0);
}

fireblocks::common::cosigner::byte_vector_t ppc::mpc::player::PlatformImpl::encrypt_for_player(
    uint64_t id, const fireblocks::common::cosigner::byte_vector_t& data) const {
    return data;
}

fireblocks::common::cosigner::byte_vector_t ppc::mpc::player::PlatformImpl::decrypt_message(
    const fireblocks::common::cosigner::byte_vector_t& encrypted_data) const {
    return encrypted_data;
}

bool ppc::mpc::player::PlatformImpl::backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm,
    const elliptic_curve256_scalar_t& private_key, const fireblocks::common::cosigner::cmp_key_metadata& metadata,
    const fireblocks::common::cosigner::auxiliary_keys& aux) {
    return true;
}

void ppc::mpc::player::PlatformImpl::start_signing(const std::string& key_id, const std::string& txid,
    const fireblocks::common::cosigner::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) {}

void ppc::mpc::player::PlatformImpl::fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const {
    assert(0);
}

bool ppc::mpc::player::PlatformImpl::is_client_id(uint64_t player_id) const {
    return false;
}

uint64_t ppc::mpc::player::PlatformImpl::now_msec() const {
    return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()).time_since_epoch().count();
}