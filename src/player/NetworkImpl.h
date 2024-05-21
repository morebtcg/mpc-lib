#pragma once

#include "player/Network.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <iterator>
#include <sstream>
#include <type_traits>

namespace ppc::mpc::player {

inline void broadcastMessage(network::Network auto& network, int playerID, BytesConstView bufferView, int totalPlayers) {
    for (int i = 0; i < totalPlayers; ++i) {
        if (i != playerID) {
            network::sendMessage(network, i, bufferView);
        }
    }
};

template <class Object>
inline void broadcastMessage(network::Network auto& network, int playerID, const Object& object, int totalPlayers) {
    if constexpr (std::is_trivial_v<Object> && std::is_standard_layout_v<Object>) {
        BytesConstView bufferView{reinterpret_cast<const uint8_t*>(std::addressof(object)), sizeof(object)};
        broadcastMessage(network, playerID, bufferView, totalPlayers);
    } else {
        std::stringbuf buffer;
        boost::archive::binary_oarchive archive(buffer);
        archive << object;
        auto view = buffer.view();
        BytesConstView bufferView = {reinterpret_cast<const uint8_t*>(view.data()), view.size()};
        broadcastMessage(network, playerID, bufferView, totalPlayers);
    }
}

inline void receiveAllMessage(network::Network auto& network, int playerID, auto& container, int totalPlayers) {
    using ValueType = typename std::decay_t<decltype(container)>::value_type;
    if constexpr (std::is_trivial_v<ValueType> && std::is_standard_layout_v<ValueType>) {
        for (int i = 0; i < totalPlayers; ++i) {
            if (i != playerID) {
                auto& object = container[i];
                BytesView buffer(reinterpret_cast<uint8_t*>(std::addressof(object)), sizeof(object));
                network::receiveMessage(network, i, buffer.begin());
            }
        }
    } else {
        std::string buffer;
        for (int i = 0; i < totalPlayers; ++i) {
            if (i != playerID) {
                network::receiveMessage(network, i, std::back_inserter(buffer));
                std::stringbuf bufferStream(buffer);
                boost::archive::binary_iarchive archive(bufferStream);
                auto& object = container[i];
                archive >> object;
                buffer.clear();
            }
        }
    }
}
}  // namespace ppc::mpc::player