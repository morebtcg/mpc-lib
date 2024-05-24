#include "CreateSecret.h"
#include "Dump.h"
#include "PlayerImpl.h"
#include "Sign.h"
#include "mpc/Concepts.h"
#include "mpc/Network.h"
#include "mpc/Player.h"
#include <openssl/rand.h>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/serialization/string.hpp>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <any>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>

class TestCreateSecretFixture {};

namespace boost::serialization {
template <class Archive>
void serialize(Archive& archive, std::tuple<std::string, std::string_view>& key, unsigned int version) {
    auto& [field, type] = key;
    archive & field;
    std::string typeStr(type);
    archive & typeStr;
}

template <class Archive>
void serialize(Archive& archive, std::tuple<std::string, std::string_view, uint64_t>& key, unsigned int version) {
    auto& [field, type, index] = key;
    archive & field;
    std::string typeStr(type);
    archive & typeStr;
    archive & index;
}
}  // namespace boost::serialization

BOOST_FIXTURE_TEST_SUITE(TestCreateSecret, TestCreateSecretFixture)

struct Router {
    std::mutex m_messageMutex;
    std::map<std::tuple<ppc::mpc::PlayerID, ppc::mpc::PlayerID>, std::deque<std::vector<uint8_t>>> m_messages;
};

struct MockNetwork {
    std::reference_wrapper<Router> m_router;
    int m_playerID;

    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::sendMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID toPlayerID,
        std::ranges::input_range auto&& buffer, auto&&... args) {
        std::unique_lock lock(network.m_router.get().m_messageMutex);
        std::vector<uint8_t> message(buffer.begin(), buffer.end());

        std::cout << "Send message: " << network.m_playerID << "->" << toPlayerID << ", buffer size:" << message.size() << "\n";
        network.m_router.get().m_messages[{network.m_playerID, toPlayerID}].push_back(std::move(message));
    }

    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::receiveMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID fromPlayerID,
        auto&& outputIterator, auto&&... args) {
        while (true) {
            std::unique_lock lock(network.m_router.get().m_messageMutex);
            auto& queue = network.m_router.get().m_messages[{fromPlayerID, network.m_playerID}];
            if (queue.empty()) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            auto& message = queue.front();
            std::cout << "Receive message: " << fromPlayerID << "->" << network.m_playerID << ", buffer size:" << message.size() << "\n";

            std::copy(message.begin(), message.end(), outputIterator);
            queue.pop_front();
            return;
        }
    }
};

struct MockStorage {
    std::map<std::string, std::any, std::less<>> m_storage;
};

std::string serialize(auto&& object) {
    std::stringstream ss;
    boost::archive::text_oarchive archive(ss);
    archive << std::forward<decltype(object)>(object);
    ss.flush();
    return ss.str();
}

template <class T>
std::any toAny(T&& object) {
    if constexpr (std::is_array_v<std::remove_reference_t<T>>) {
        std::array<std::ranges::range_value_t<T>, sizeof(T)> array;
        std::uninitialized_copy_n(object, sizeof(object), array.begin());
        return array;
    } else {
        return std::forward<T>(object);
    }
}

template <class T>
auto fromAny(const std::any& object) {
    if constexpr (std::is_array_v<T>) {
        auto array = std::any_cast<std::array<std::ranges::range_value_t<T>, sizeof(T)>>(object);
        return array;
    } else {
        return std::any_cast<T>(object);
    }
}

template <class T>
auto tag_invoke(ppc::mpc::tag_t<ppc::mpc::storage::read> /*unused*/, MockStorage& storage, auto&& key) {
    auto it = storage.m_storage.find(serialize(key));
    if (it == storage.m_storage.end()) {
        return std::optional<decltype(fromAny<T>(it->second))>{};
    }
    return std::make_optional(fromAny<T>(it->second));
}

void tag_invoke(ppc::mpc::tag_t<ppc::mpc::storage::write> /*unused*/, MockStorage& storage, auto&& key, auto&& value) {
    storage.m_storage[serialize(key)] = toAny(std::forward<decltype(value)>(value));
}

void tag_invoke(ppc::mpc::tag_t<ppc::mpc::storage::remove> /*unused*/, MockStorage& storage, auto&& key) {
    storage.m_storage.erase(serialize(key));
}

BOOST_AUTO_TEST_CASE(encode) {
    fireblocks::common::cosigner::setup_decommitment decommitment;
    RAND_bytes(decommitment.ack, sizeof(decommitment.ack));
    RAND_bytes(decommitment.seed, sizeof(decommitment.seed));
    RAND_bytes(decommitment.share.X.data, sizeof(decommitment.share.X.data));
    RAND_bytes(decommitment.share.schnorr_R.data, sizeof(decommitment.share.schnorr_R.data));
    decommitment.paillier_public_key.resize(100);
    RAND_bytes(decommitment.paillier_public_key.data(), decommitment.paillier_public_key.size());
    decommitment.ring_pedersen_public_key.resize(100);
    RAND_bytes(decommitment.ring_pedersen_public_key.data(), decommitment.ring_pedersen_public_key.size());

    std::stringbuf buffer;
    boost::archive::binary_oarchive archive(buffer);
    archive << decommitment;

    boost::archive::binary_iarchive input(buffer);
    fireblocks::common::cosigner::setup_decommitment decommitment2;
    input >> decommitment2;

    BOOST_CHECK(std::ranges::equal(decommitment.ack, decommitment2.ack));
    BOOST_CHECK(std::ranges::equal(decommitment.seed, decommitment2.seed));
    BOOST_CHECK(std::ranges::equal(decommitment.share.X.data, decommitment2.share.X.data));
    BOOST_CHECK(std::ranges::equal(decommitment.share.schnorr_R.data, decommitment2.share.schnorr_R.data));
    BOOST_CHECK_EQUAL(decommitment.paillier_public_key, decommitment2.paillier_public_key);
    BOOST_CHECK_EQUAL(decommitment.ring_pedersen_public_key, decommitment2.ring_pedersen_public_key);
}

auto catchError(int num, auto lambda) {
    return [=]() {
        try {
            lambda();
        } catch (std::exception& e) {
            std::cout << "Thread " << num << " exit with error: " << boost::diagnostic_information(e) << "\n";
            BOOST_THROW_EXCEPTION(e);
        }
    };
}

constexpr static std::string keyID{"MyID"};

std::vector<std::tuple<ppc::mpc::PrivateKeySlice, ppc::mpc::PublicKey>> testCreate(int count) {
    std::vector<ppc::mpc::player::PlayerImpl> players;
    players.reserve(count);

    Router router;
    std::vector<MockNetwork> networks;
    networks.reserve(count);

    std::vector<std::thread> threads;
    threads.reserve(count);

    std::vector<std::tuple<ppc::mpc::PrivateKeySlice, ppc::mpc::PublicKey>> results(count);
    for (auto i = 0; i < count; ++i) {
        players.emplace_back(i, ppc::mpc::ECDSA_SECP256K1, count);
        networks.emplace_back(MockNetwork{.m_router = router, .m_playerID = i});
        threads.emplace_back(catchError(i, [i, &results, &players, &networks]() {
            MockStorage mockStorage;
            results[i] = ppc::mpc::player::createSecret(players[i], mockStorage, networks[i], keyID);
        }));
    }

    for (auto i = 0; i < count; ++i) {
        threads[i].join();
    }

    return results;
}

std::vector<ppc::mpc::Signature> testSign(int count, ppc::mpc::BytesConstView signData) {
    auto keys = testCreate(count);

    std::vector<ppc::mpc::player::PlayerImpl> players;
    players.reserve(count);
    Router router;
    std::vector<MockNetwork> networks;
    networks.reserve(count);
    std::vector<MockStorage> storages(count);

    std::vector<std::thread> threads;
    threads.reserve(count);

    std::vector<std::tuple<ppc::mpc::PrivateKeySlice, ppc::mpc::PublicKey>> results(count);
    for (auto i = 0; i < count; ++i) {
        players.emplace_back(i, ppc::mpc::ECDSA_SECP256K1, count);
        networks.emplace_back(MockNetwork{.m_router = router, .m_playerID = i});
        threads.emplace_back(catchError(i, [i, &results, &players, &networks, &storages]() {
            results[i] = ppc::mpc::player::createSecret(players[i], storages[i], networks[i], keyID);
        }));
    }
    for (auto i = 0; i < count; ++i) {
        threads[i].join();
    }
    router.m_messages.clear();
    threads.clear();

    constexpr static ppc::mpc::RequestID requestID{"myRequestID"};
    std::vector<ppc::mpc::Signature> signatures(count);
    for (auto i = 0; i < count; ++i) {
        threads.emplace_back(catchError(i, [i, &keys, &players, &networks, &signData, &signatures, &storages]() {
            signatures[i] = ppc::mpc::player::sign(players[i], storages[i], networks[i], keyID, signData, requestID, std::get<0>(keys[i]));
        }));
    }
    for (auto i = 0; i < count; ++i) {
        threads[i].join();
    }

    return signatures;
}

BOOST_AUTO_TEST_CASE(key_serialize) {
    using namespace std::string_literals;
    using namespace std::string_view_literals;
    auto key1 = serialize(std::tuple{"key1"s, "key2"sv, 100LU});
    auto key2 = serialize(std::tuple{"key1"s, "key2"sv, 200LU});

    std::cout << key1 << "\n";
    std::cout << key2 << "\n";
    BOOST_CHECK_NE(key1, key2);
}

BOOST_AUTO_TEST_CASE(create) {
    for (auto i = 3; i < 10; ++i) {
        auto results = testCreate(i);
        auto expectPublicKey = std::get<1>(results[0]);
        for (auto& [privateKeySlice, publicKey] : results) {
            BOOST_CHECK_EQUAL(expectPublicKey, publicKey);
        }
    }
}

BOOST_AUTO_TEST_CASE(sign) {
    for (auto i = 3; i < 10; ++i) {
        auto signData = std::string(32, '0');
        auto results = testSign(i, ppc::mpc::BytesConstView((const uint8_t*)signData.data(), signData.size()));
    }
}

BOOST_AUTO_TEST_SUITE_END()