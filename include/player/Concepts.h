#pragma once
#include <span>

namespace ppc::mpc {
using BytesConstView = std::span<const std::byte>;
using BytesView = std::span<std::byte>;
}  // namespace ppc::mpc