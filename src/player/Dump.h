#pragma once
#include <boost/algorithm/hex.hpp>
#include <iostream>
#include <ostream>
#include <span>

namespace std {

ostream& operator<<(ostream& stream, const std::span<const uint8_t>& array) {
    std::string hexPrivateKey;
    std::string_view input((const char*)array.data(), array.size());
    boost::algorithm::hex_lower(input, std::back_inserter(hexPrivateKey));
    stream << "0x" << hexPrivateKey;
    return stream;
}

template <size_t N>
ostream& operator<<(ostream& stream, const std::array<uint8_t, N>& array) {
    stream << std::span(array);
    return stream;
}

template <size_t N>
ostream& operator<<(ostream& stream, uint8_t (&array)[N]) {
    stream << std::span(array);
    return stream;
}

}  // namespace std