#include "CreateSecret.h"
#include "Dump.h"
#include "PlayerImpl.h"
#include "Sign.h"
#include "player/Concepts.h"
#include "player/Network.h"
#include "player/Player.h"
#include <openssl/rand.h>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

class TestCreateSecretFixture {};

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

BOOST_AUTO_TEST_CASE(serialize) {
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
        threads.emplace_back(
            catchError(i, [i, &results, &players, &networks]() { results[i] = ppc::mpc::player::createSecret(players[i], networks[i], keyID); }));
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
    std::vector<std::thread> threads;
    threads.reserve(count);

    constexpr static ppc::mpc::RequestID requestID{"requestID!"};
    std::vector<ppc::mpc::Signature> signatures(count);
    for (auto i = 0; i < count; ++i) {
        players.emplace_back(i, ppc::mpc::ECDSA_SECP256K1, count);
        networks.emplace_back(MockNetwork{.m_router = router, .m_playerID = i});
        threads.emplace_back(catchError(i, [i, &keys, &players, &networks, &signData, &signatures]() {
            signatures[i] = ppc::mpc::player::sign(players[i], networks[i], keyID, signData, requestID, std::get<0>(keys[i]));
        }));
    }

    return signatures;
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
        auto signData = "To be sign! " + std::to_string(i);
        auto results = testSign(i, ppc::mpc::BytesConstView((const uint8_t*)signData.data(), signData.size()));
    }
}

BOOST_AUTO_TEST_SUITE_END()