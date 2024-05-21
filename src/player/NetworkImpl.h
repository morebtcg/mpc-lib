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

inline void broadcastMessage(network::Network auto& network, int excludePlayerID, BytesConstView bufferView, int totalPlayers) {
    for (int i = 0; i < totalPlayers; ++i) {
        if (i != excludePlayerID) {
            network::sendMessage(network, i, bufferView);
        }
    }
};

template <class Object>
inline void broadcastMessage(network::Network auto& network, int excludePlayerID, const Object& object, int totalPlayers) {
    if constexpr (std::is_trivial_v<Object> && std::is_standard_layout_v<Object>) {
        BytesConstView bufferView{reinterpret_cast<const uint8_t*>(std::addressof(object)), sizeof(object)};
        broadcastMessage(network, excludePlayerID, bufferView, totalPlayers);
    } else {
        std::stringbuf bufferStream;
        boost::archive::binary_oarchive archive(bufferStream);
        archive << object;
        auto view = bufferStream.view();
        BytesConstView bufferView = {reinterpret_cast<const uint8_t*>(view.data()), view.size()};
        broadcastMessage(network, excludePlayerID, bufferView, totalPlayers);
    }
}

inline void receiveAllMessage(network::Network auto& network, int excludePlayerID, auto& mapContainer, int totalPlayers) {
    using ValueType = typename std::decay_t<decltype(mapContainer)>::value_type;
    if constexpr (std::is_trivial_v<ValueType> && std::is_standard_layout_v<ValueType>) {
        for (int i = 0; i < totalPlayers; ++i) {
            if (i != excludePlayerID) {
                auto& object = mapContainer[i];
                BytesView buffer(reinterpret_cast<uint8_t*>(std::addressof(object)), sizeof(object));
                network::receiveMessage(network, i, buffer.begin());
            }
        }
    } else {
        std::string buffer;
        for (int i = 0; i < totalPlayers; ++i) {
            if (i != excludePlayerID) {
                network::receiveMessage(network, i, std::back_inserter(buffer));
                std::stringbuf bufferStream(buffer);
                boost::archive::binary_iarchive archive(bufferStream);
                auto& object = mapContainer[i];
                archive >> object;
                buffer.clear();
            }
        }
    }
}
}  // namespace ppc::mpc::player