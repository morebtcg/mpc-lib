#pragma once
#include <span>
#include <vector>

namespace ppc::mpc {
using BytesConstView = std::span<const std::byte>;
using BytesView = std::span<std::byte>;
using PlayerID = int;

enum AlgorithmType { ECDSA_SECP256K1 };

using PublicKey = std::vector<std::byte>;
using KeyID = std::vector<std::byte>;
}  // namespace ppc::mpc