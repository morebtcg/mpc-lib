#include "PreprocessingPersistencyImpl.h"

void ppc::mpc::player::PreprocessingPersistencyImpl::store_preprocessing_metadata(
    const std::string& request_id, const fireblocks::common::cosigner::preprocessing_metadata& data, bool override) {
    if (!override && m_metadata.find(request_id) != m_metadata.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    m_metadata[request_id] = data;
}

void ppc::mpc::player::PreprocessingPersistencyImpl::load_preprocessing_metadata(
    const std::string& request_id, fireblocks::common::cosigner::preprocessing_metadata& data) const {
    auto it = m_metadata.find(request_id);
    if (it == m_metadata.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    data = it->second;
}

void ppc::mpc::player::PreprocessingPersistencyImpl::store_preprocessing_data(
    const std::string& request_id, uint64_t index, const fireblocks::common::cosigner::ecdsa_signing_data& data) {
    m_signing_data[request_id][index] = data;
}

void ppc::mpc::player::PreprocessingPersistencyImpl::load_preprocessing_data(
    const std::string& request_id, uint64_t index, fireblocks::common::cosigner::ecdsa_signing_data& data) const {
    auto it = m_signing_data.find(request_id);
    if (it == m_signing_data.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    auto index_it = it->second.find(index);
    if (index_it == it->second.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    data = index_it->second;
}

void ppc::mpc::player::PreprocessingPersistencyImpl::delete_preprocessing_data(const std::string& request_id) {
    m_metadata.erase(request_id);
    m_signing_data.erase(request_id);
}

void ppc::mpc::player::PreprocessingPersistencyImpl::create_preprocessed_data(const std::string& key_id, uint64_t size) {
    auto it = m_preprocessed_data.find(key_id);
    if (it != m_preprocessed_data.end()) {
        if (it->second.size() != size)
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    } else
        m_preprocessed_data.emplace(key_id, std::move(std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data>(size)));
}

void ppc::mpc::player::PreprocessingPersistencyImpl::store_preprocessed_data(
    const std::string& key_id, uint64_t index, const fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) {
    auto it = m_preprocessed_data.find(key_id);
    if (it == m_preprocessed_data.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    if (index >= it->second.size())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX);
    it->second[index] = data;
}

void ppc::mpc::player::PreprocessingPersistencyImpl::load_preprocessed_data(
    const std::string& key_id, uint64_t index, fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) {
    auto it = m_preprocessed_data.find(key_id);
    if (it == m_preprocessed_data.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
    if (index >= it->second.size() ||
        memcmp(it->second[index].k.data, ZERO.data(), sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)) == 0)
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX);
    data = it->second[index];
    memset(it->second[index].k.data, 0, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data));
}

void ppc::mpc::player::PreprocessingPersistencyImpl::delete_preprocessed_data(const std::string& key_id) {
    m_preprocessed_data.erase(key_id);
}
