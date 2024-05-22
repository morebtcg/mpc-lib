#pragma once
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "player/Storage.h"
#include <boost/throw_exception.hpp>
#include <array>
#include <functional>

namespace ppc::mpc::player {

constexpr static std::array<uint8_t, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)> ZERO{};

template <class Storage>
class PreprocessingPersistencyImpl : public fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service::preprocessing_persistency {
private:
    std::reference_wrapper<Storage> m_storage;

    enum FIELD {
        PREPROCESSING_METADATA,
        PREPROCESSING_DATA,
        PREPROCESSED_DATA,
    };

public:
    void store_preprocessing_metadata(
        const std::string& request_id, const fireblocks::common::cosigner::preprocessing_metadata& data, bool override) override {
        storage::write(m_storage.get(), std::tuple{request_id, PREPROCESSING_METADATA}, data);
    }

    void load_preprocessing_metadata(const std::string& request_id, fireblocks::common::cosigner::preprocessing_metadata& data) const override {
        auto dataValue =
            storage::read.operator()<fireblocks::common::cosigner::preprocessing_metadata>(m_storage.get(), {request_id, PREPROCESSING_METADATA});
        if (!dataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        data = *dataValue;
    }

    void store_preprocessing_data(
        const std::string& request_id, uint64_t index, const fireblocks::common::cosigner::ecdsa_signing_data& data) override {
        storage::write(m_storage.get(), std::tuple{request_id, PREPROCESSING_DATA}, data);
    }

    void load_preprocessing_data(
        const std::string& request_id, uint64_t index, fireblocks::common::cosigner::ecdsa_signing_data& data) const override {
        auto dataValue =
            storage::read.operator()<fireblocks::common::cosigner::ecdsa_signing_data>(m_storage.get(), {request_id, PREPROCESSING_DATA});
        if (!dataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        data = *dataValue;
    }

    void delete_preprocessing_data(const std::string& request_id) override {
        storage::remove(m_storage.get(), {request_id, PREPROCESSING_METADATA});
        storage::remove(m_storage.get(), {request_id, PREPROCESSING_DATA});
    }

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