#pragma once
#include <cstdint>
#include <span>
#include <string>

namespace ppc::mpc {
using BytesConstView = std::span<const std::byte>;
using BytesView = std::span<std::byte>;
using PlayerID = int;
using KeyID = std::string;

enum AlgorithmType { ECDSA_SECP256K1 };
constexpr static int ELLIPTIC_CURVE_SCALAR_LENGTH = 32;
constexpr static int ELLIPTIC_CURVE_POINT_LENGTH = 33;  // COMPRESSED POINT
using EllipticCurveScalar = std::array<std::byte, ELLIPTIC_CURVE_SCALAR_LENGTH>;
using EllipticCurvePoint = std::array<std::byte, ELLIPTIC_CURVE_POINT_LENGTH>;

using PublicKey = EllipticCurvePoint;
using PrivateKeySlice = EllipticCurveScalar;
struct Signature {
    EllipticCurveScalar r;
    EllipticCurveScalar s;
    uint8_t v;
};

template <auto& Tag>
using tag_t = std::decay_t<decltype(Tag)>;
}  // namespace ppc::mpc