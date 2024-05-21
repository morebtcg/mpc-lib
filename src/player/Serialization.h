#pragma once

#include "cosigner/cmp_setup_service.h"
#include "cosigner/types.h"

namespace boost::serialization {

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::commitment& commitment, unsigned int version) {
    archive & commitment.data.commitment;
    archive & commitment.data.salt;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::setup_decommitment& decommitment, unsigned int version) {
    archive & decommitment.ack;
    archive & decommitment.seed;
    archive & decommitment.share.X.data;
    archive & decommitment.share.schnorr_R.data;
    archive & decommitment.paillier_public_key;
    archive & decommitment.ring_pedersen_public_key;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::setup_zk_proofs& setupZK, unsigned int version) {
    archive & setupZK.schnorr_s.data;
    archive & setupZK.paillier_blum_zkp;
    archive & setupZK.ring_pedersen_param_zkp;
}

}  // namespace boost::serialization