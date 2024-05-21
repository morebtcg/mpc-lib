#include "CreateSecret.h"
#include "Dump.h"
#include "PlayerImpl.h"
#include "player/Concepts.h"
#include "player/Network.h"
#include "player/Player.h"
#include <openssl/rand.h>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <deque>
#include <mutex>
#include <thread>

class TestCreateSecretFixture {};

BOOST_FIXTURE_TEST_SUITE(TestCreateSecret, TestCreateSecretFixture)

struct MockNetwork {
    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::sendMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID playerID,
        std::ranges::input_range auto&& buffer, auto&&... args) {
        std::unique_lock lock(network.m_messageMutex);
        std::vector<uint8_t> message(buffer.begin(), buffer.end());

        std::cout << "Send to: " << playerID << " player, buffer size:" << message.size() << "\n";
        network.m_messages[playerID].push_back(std::move(message));
    }

    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::receiveMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID playerID,
        auto&& outputIterator, auto&&... args) {
        while (true) {
            std::unique_lock lock(network.m_messageMutex);
            auto& queue = network.m_messages[playerID];
            if (queue.empty()) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            auto& message = queue.front();
            std::cout << "Receive from: " << playerID << " player, buffer size:" << message.size() << "\n";

            std::copy(message.begin(), message.end(), outputIterator);
            queue.pop_front();
            return;
        }
    }

    std::mutex m_messageMutex;
    std::map<ppc::mpc::PlayerID, std::deque<std::vector<uint8_t>>> m_messages;
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

BOOST_AUTO_TEST_CASE(create) {
    ppc::mpc::player::PlayerImpl player1(0, ppc::mpc::ECDSA_SECP256K1, 3);
    ppc::mpc::player::PlayerImpl player2(1, ppc::mpc::ECDSA_SECP256K1, 3);
    ppc::mpc::player::PlayerImpl player3(2, ppc::mpc::ECDSA_SECP256K1, 3);

    MockNetwork mockNetwork;
    std::string keyID{"MyID"};

    ppc::mpc::PrivateKeySlice slice1{};
    ppc::mpc::PrivateKeySlice slice2{};
    ppc::mpc::PrivateKeySlice slice3{};
    ppc::mpc::PublicKey publicKey1{};
    ppc::mpc::PublicKey publicKey2{};
    ppc::mpc::PublicKey publicKey3{};

    std::thread thread1(catchError(1, [&]() { std::tie(slice1, publicKey1) = ppc::mpc::player::createSecret(player1, mockNetwork, keyID); }));
    std::thread thread2(catchError(2, [&]() { std::tie(slice2, publicKey2) = ppc::mpc::player::createSecret(player2, mockNetwork, keyID); }));
    std::thread thread3(catchError(3, [&]() { std::tie(slice3, publicKey3) = ppc::mpc::player::createSecret(player3, mockNetwork, keyID); }));

    thread1.join();
    thread2.join();
    thread3.join();

    // BOOST_CHECK_NE(slice1, slice2);
    // BOOST_CHECK_NE(slice2, slice3);
}

BOOST_AUTO_TEST_SUITE_END()