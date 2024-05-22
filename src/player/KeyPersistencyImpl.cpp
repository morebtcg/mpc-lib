#pragma once

#include "KeyPersistencyImpl.h"
#include "cosigner/cosigner_exception.h"
#include "player/Concepts.h"
#include <boost/throw_exception.hpp>

bool ppc::mpc::player::KeyPersistencyImpl::key_exist(const std::string& key_id) const {
    return m_keys.contains(key_id);
}
void ppc::mpc::player::KeyPersistencyImpl::load_key(
    const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const {
    auto it = m_keys.find(key_id);
    if (it == m_keys.end()) {
        BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
    }
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}
const std::string ppc::mpc::player::KeyPersistencyImpl::get_tenantid_from_keyid(const std::string& key_id) const {
    return ppc::mpc::tenantID;
}
void ppc::mpc::player::KeyPersistencyImpl::load_key_metadata(
    const std::string& key_id, fireblocks::common::cosigner::cmp_key_metadata& metadata, bool full_load) const {
    auto it = m_keys.find(key_id);
    if (it == m_keys.end()) {
        BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
    }
    metadata = it->second.metadata.value();
}
void ppc::mpc::player::KeyPersistencyImpl::load_auxiliary_keys(const std::string& key_id, fireblocks::common::cosigner::auxiliary_keys& aux) const {
    auto it = m_keys.find(key_id);
    if (it == m_keys.end()) {
        BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY));
    }
    aux = it->second.aux_keys;
}
void ppc::mpc::player::KeyPersistencyImpl::store_key(
    const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl) {
    auto& info = m_keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
}
void ppc::mpc::player::KeyPersistencyImpl::store_key_metadata(
    const std::string& key_id, const fireblocks::common::cosigner::cmp_key_metadata& metadata, bool allow_override) {
    auto& info = m_keys[key_id];
    if (!allow_override && info.metadata) {
        BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INTERNAL_ERROR));
    }

    info.metadata = metadata;
}
void ppc::mpc::player::KeyPersistencyImpl::store_auxiliary_keys(const std::string& key_id, const fireblocks::common::cosigner::auxiliary_keys& aux) {
    auto& info = m_keys[key_id];
    info.aux_keys = aux;
}
void ppc::mpc::player::KeyPersistencyImpl::store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) {}
void ppc::mpc::player::KeyPersistencyImpl::store_setup_data(const std::string& key_id, const fireblocks::common::cosigner::setup_data& metadata) {
    m_setup_data[key_id] = metadata;
}
void ppc::mpc::player::KeyPersistencyImpl::load_setup_data(const std::string& key_id, fireblocks::common::cosigner::setup_data& metadata) {
    metadata = m_setup_data[key_id];
}
void ppc::mpc::player::KeyPersistencyImpl::store_setup_commitments(
    const std::string& key_id, const std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) {
    if (m_commitments.find(key_id) != m_commitments.end())
        BOOST_THROW_EXCEPTION(fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INTERNAL_ERROR));

    m_commitments[key_id] = commitments;
}
void ppc::mpc::player::KeyPersistencyImpl::load_setup_commitments(
    const std::string& key_id, std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) {
    commitments = m_commitments[key_id];
}
void ppc::mpc::player::KeyPersistencyImpl::delete_temporary_key_data(const std::string& key_id, bool delete_key) {
    m_setup_data.erase(key_id);
    m_commitments.erase(key_id);
    if (delete_key) {
        m_keys.erase(key_id);
    }
}
