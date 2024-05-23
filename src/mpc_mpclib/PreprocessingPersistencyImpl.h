#pragma once
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "mpc/Storage.h"
#include <boost/throw_exception.hpp>
#include <array>
#include <functional>

namespace ppc::mpc::player {

constexpr static std::array<uint8_t, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)> ZERO{};

template <class Storage>
class PreprocessingPersistencyImpl : public fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service::preprocessing_persistency {
private:
    std::reference_wrapper<Storage> m_storage;

    constexpr static std::string_view PREPROCESSING_METADATA = "preprocessing_metadata";
    constexpr static std::string_view PREPROCESSING_DATA = "preprocessing_data";
    constexpr static std::string_view PREPROCESSED_DATA = "preprocessed_data";
    constexpr static std::string_view PREPROCESSED_COUNT = "preprocessed_count";

public:
    explicit PreprocessingPersistencyImpl(Storage& storage) : m_storage(storage) {}

    void store_preprocessing_metadata(
        const std::string& request_id, const fireblocks::common::cosigner::preprocessing_metadata& data, bool override) override {
        storage::write(m_storage.get(), std::tuple{request_id, PREPROCESSING_METADATA}, data);
    }

    void load_preprocessing_metadata(const std::string& request_id, fireblocks::common::cosigner::preprocessing_metadata& data) const override {
        auto dataValue = storage::read.operator()<fireblocks::common::cosigner::preprocessing_metadata>(
            m_storage.get(), std::tuple{request_id, PREPROCESSING_METADATA});
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
            storage::read.operator()<fireblocks::common::cosigner::ecdsa_signing_data>(m_storage.get(), std::tuple{request_id, PREPROCESSING_DATA});
        if (!dataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        data = *dataValue;
    }

    void delete_preprocessing_data(const std::string& request_id) override {
        storage::remove(m_storage.get(), std::tuple{request_id, PREPROCESSING_METADATA});
        storage::remove(m_storage.get(), std::tuple{request_id, PREPROCESSING_DATA});
    }

    void create_preprocessed_data(const std::string& key_id, uint64_t size) override {
        storage::write(m_storage.get(), std::tuple{key_id, PREPROCESSED_COUNT}, size);
    }
    void store_preprocessed_data(
        const std::string& key_id, uint64_t index, const fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override {
        auto count = storage::read.operator()<uint64_t>(m_storage.get(), std::tuple{key_id, PREPROCESSED_COUNT});
        if (!count) {
            BOOST_THROW_EXCEPTION(
                fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION));
        }
        if (index >= *count) {
            BOOST_THROW_EXCEPTION(
                fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX));
        }
        storage::write(m_storage.get(), std::tuple{key_id, PREPROCESSED_DATA, index}, data);
    }
    void load_preprocessed_data(
        const std::string& key_id, uint64_t index, fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override {
        auto count = storage::read.operator()<uint64_t>(m_storage.get(), std::tuple{key_id, PREPROCESSED_COUNT});
        if (!count) {
            BOOST_THROW_EXCEPTION(
                fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION));
        }
        if (index >= *count) {
            BOOST_THROW_EXCEPTION(
                fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX));
        }

        auto dataValue = storage::read.operator()<fireblocks::common::cosigner::cmp_signature_preprocessed_data>(
            m_storage.get(), std::tuple{key_id, PREPROCESSED_DATA, index});
        if (!dataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        data = *dataValue;
    }
    void delete_preprocessed_data(const std::string& key_id) override {
        auto count = storage::read.operator()<uint64_t>(m_storage.get(), std::tuple{key_id, PREPROCESSED_COUNT});
        if (!count) {
            BOOST_THROW_EXCEPTION(
                fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION));
        }
        for (uint64_t i = 0; i < *count; ++i) {
            storage::remove(m_storage.get(), std::tuple{key_id, PREPROCESSED_DATA, i});
        }
        storage::remove(m_storage.get(), std::tuple{key_id, PREPROCESSED_COUNT});
    }
};
}  // namespace ppc::mpc::player