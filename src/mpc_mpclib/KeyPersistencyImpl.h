#pragma once
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cosigner_exception.h"
#include "mpc/Concepts.h"
#include "mpc/Storage.h"
#include <boost/throw_exception.hpp>
#include <functional>

namespace ppc::mpc::player {

template <class Storage>
class KeyPersistencyImpl : public fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency {
private:
    std::reference_wrapper<Storage> m_storage;

public:
    explicit KeyPersistencyImpl(Storage& storage) : m_storage(storage) {}
    constexpr static std::string_view ALGORITHM_FIELD = "algorithm_field";
    constexpr static std::string_view PRIVATE_KEY_FIELD = "private_key_field";
    constexpr static std::string_view METADATA_FIELD = "metadata_field";
    constexpr static std::string_view AUX_KEYS = "aux_keys";
    constexpr static std::string_view TTL_FIELD = "ttl_field";
    constexpr static std::string_view SETUP_DATA = "setup_data";
    constexpr static std::string_view COMMITMENT = "commitment";

    bool key_exist(const std::string& key_id) const override {
        auto value = storage::read.operator()<cosigner_sign_algorithm>(m_storage.get(), std::tuple{key_id, ALGORITHM_FIELD});
        return value.has_value();
    }

    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override {
        auto algorithmValue = storage::read.operator()<cosigner_sign_algorithm>(m_storage.get(), std::tuple{key_id, ALGORITHM_FIELD});
        auto privateKeyValue = storage::read.operator()<elliptic_curve256_scalar_t>(m_storage.get(), std::tuple{key_id, PRIVATE_KEY_FIELD});
        if (!algorithmValue || !privateKeyValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        algorithm = *algorithmValue;
        std::ranges::copy(*privateKeyValue, private_key);
    }

    const std::string get_tenantid_from_keyid(const std::string& key_id) const override { return ppc::mpc::tenantID; }

    void load_key_metadata(const std::string& key_id, fireblocks::common::cosigner::cmp_key_metadata& metadata, bool full_load) const override {
        auto metadataValue =
            storage::read.operator()<fireblocks::common::cosigner::cmp_key_metadata>(m_storage.get(), std::tuple{key_id, METADATA_FIELD});
        if (!metadataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        metadata = *metadataValue;
    }

    void load_auxiliary_keys(const std::string& key_id, fireblocks::common::cosigner::auxiliary_keys& aux) const override {
        auto auxValue = storage::read.operator()<fireblocks::common::cosigner::auxiliary_keys>(m_storage.get(), std::tuple{key_id, AUX_KEYS});
        if (!auxValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        aux = *auxValue;
    }

    void store_key(
        const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) override {
        storage::write(m_storage.get(), std::tuple{key_id, ALGORITHM_FIELD}, algorithm);
        storage::write(m_storage.get(), std::tuple{key_id, PRIVATE_KEY_FIELD}, private_key);
        storage::write(m_storage.get(), std::tuple{key_id, TTL_FIELD}, ttl);
    }

    void store_key_metadata(const std::string& key_id, const fireblocks::common::cosigner::cmp_key_metadata& metadata, bool allow_override) override {
        auto metadataValue =
            storage::read.operator()<fireblocks::common::cosigner::cmp_key_metadata>(m_storage.get(), std::tuple{key_id, METADATA_FIELD});
        if (!allow_override && metadataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INTERNAL_ERROR));
        }
        storage::write(m_storage.get(), std::tuple{key_id, METADATA_FIELD}, metadata);
    }

    void store_auxiliary_keys(const std::string& key_id, const fireblocks::common::cosigner::auxiliary_keys& aux) override {
        storage::write(m_storage.get(), std::tuple{key_id, AUX_KEYS}, aux);
    }

    void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) override {}

    void store_setup_data(const std::string& key_id, const fireblocks::common::cosigner::setup_data& metadata) override {
        storage::write(m_storage.get(), std::tuple{key_id, SETUP_DATA}, metadata);
    }

    void load_setup_data(const std::string& key_id, fireblocks::common::cosigner::setup_data& metadata) override {
        auto metadataValue = storage::read.operator()<fireblocks::common::cosigner::setup_data>(m_storage.get(), std::tuple{key_id, SETUP_DATA});
        if (!metadataValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        metadata = *metadataValue;
    }

    void store_setup_commitments(
        const std::string& key_id, const std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override {
        storage::write(m_storage.get(), std::tuple{key_id, COMMITMENT}, commitments);
    }

    void load_setup_commitments(const std::string& key_id, std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override {
        auto commitmentsValue =
            storage::read.operator()<std::map<uint64_t, fireblocks::common::cosigner::commitment>>(m_storage.get(), std::tuple{key_id, COMMITMENT});
        if (!commitmentsValue) {
            BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
        }
        commitments = *commitmentsValue;
    }

    void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) override {
        storage::remove(m_storage.get(), std::tuple{key_id, COMMITMENT});
        storage::remove(m_storage.get(), std::tuple{key_id, SETUP_DATA});
        if (delete_key) {
            storage::remove(m_storage.get(), std::tuple{key_id, ALGORITHM_FIELD});
            storage::remove(m_storage.get(), std::tuple{key_id, PRIVATE_KEY_FIELD});
            storage::remove(m_storage.get(), std::tuple{key_id, METADATA_FIELD});
            storage::remove(m_storage.get(), std::tuple{key_id, AUX_KEYS});
            storage::remove(m_storage.get(), std::tuple{key_id, TTL_FIELD});
        }
    }
};
}  // namespace ppc::mpc::player