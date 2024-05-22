#pragma once
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include <array>

namespace ppc::mpc::player {

constexpr static std::array<uint8_t, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)> ZERO{};

class PreprocessingPersistencyImpl : public fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service::preprocessing_persistency {
    void store_preprocessing_metadata(
        const std::string& request_id, const fireblocks::common::cosigner::preprocessing_metadata& data, bool override) override;

    void load_preprocessing_metadata(const std::string& request_id, fireblocks::common::cosigner::preprocessing_metadata& data) const override;

    void store_preprocessing_data(
        const std::string& request_id, uint64_t index, const fireblocks::common::cosigner::ecdsa_signing_data& data) override;

    void load_preprocessing_data(
        const std::string& request_id, uint64_t index, fireblocks::common::cosigner::ecdsa_signing_data& data) const override;

    void delete_preprocessing_data(const std::string& request_id) override;

    void create_preprocessed_data(const std::string& key_id, uint64_t size) override;

    void store_preprocessed_data(
        const std::string& key_id, uint64_t index, const fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override;

    void load_preprocessed_data(
        const std::string& key_id, uint64_t index, fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override;

    void delete_preprocessed_data(const std::string& key_id) override;

    std::map<std::string, fireblocks::common::cosigner::preprocessing_metadata> m_metadata;
    std::map<std::string, std::map<uint64_t, fireblocks::common::cosigner::ecdsa_signing_data>> m_signing_data;
    std::map<std::string, std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data>> m_preprocessed_data;
};
}  // namespace ppc::mpc::player