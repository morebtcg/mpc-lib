#pragma once
#include <boost/algorithm/hex.hpp>
#include <iostream>

namespace std {

template <size_t N>
ostream& operator<<(ostream& stream, const std::array<uint8_t, N> array) {
    std::string hexPrivateKey;
    std::string_view input((const char*)array.data(), array.size());
    boost::algorithm::hex_lower(input, std::back_inserter(hexPrivateKey));
    stream << "0x" << hexPrivateKey;
    return stream;
}

}  // namespace std