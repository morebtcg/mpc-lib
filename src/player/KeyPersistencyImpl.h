#pragma once
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cmp_setup_service.h"
#include <optional>

namespace ppc::mpc::player {

class KeyPersistencyImpl : public fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency {
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
}  // namespace ppc::mpc::player