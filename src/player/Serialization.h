#pragma once

#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/types.h"
#include <atomic>

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

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::cmp_mta_message& mtaMessage, unsigned int version) {
    archive & mtaMessage.message;
    archive & mtaMessage.commitment;
    archive & mtaMessage.proof;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::cmp_mta_request& mtaRequest, unsigned int version) {
    archive & mtaRequest.mta;
    archive & mtaRequest.mta_proofs;
    archive & mtaRequest.A;
    archive & mtaRequest.B;
    archive & mtaRequest.Z;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::cmp_mta_response& mtaResponse, unsigned int version) {
    archive & mtaResponse.k_gamma_mta;
    archive & mtaResponse.k_x_mta;
    archive & mtaResponse.GAMMA;
    archive & mtaResponse.gamma_proofs;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::cmp_mta_responses& mtaResponses, unsigned int version) {
    archive & mtaResponses.ack;
    archive & mtaResponses.response;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::cmp_mta_deltas& mtaDeltas, unsigned int version) {
    archive & mtaDeltas.delta;
    archive & mtaDeltas.DELTA;
    archive & mtaDeltas.proof;
}

template <class Archive>
void serialize(Archive& archive, fireblocks::common::cosigner::recoverable_signature& recoverableSignature, unsigned int version) {
    archive & recoverableSignature.r;
    archive & recoverableSignature.s;
    archive & recoverableSignature.v;
}

}  // namespace boost::serialization