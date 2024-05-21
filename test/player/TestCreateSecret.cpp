#include "CreateSecret.h"
#include "Dump.h"
#include "PlayerImpl.h"
#include "player/Concepts.h"
#include "player/Network.h"
#include "player/Player.h"
#include <boost/test/unit_test.hpp>
#include <thread>

class TestCreateSecretFixture {};

BOOST_FIXTURE_TEST_SUITE(TestCreateSecret, TestCreateSecretFixture)

struct MockNetwork {
    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::sendMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID playerID,
        std::ranges::input_range auto&& buffer, auto&&... args) {}

    friend void tag_invoke(ppc::mpc::tag_t<ppc::mpc::network::receiveMessage> /*unused*/, MockNetwork& network, ppc::mpc::PlayerID playerID,
        auto&& outputIterator, auto&&... args) {}
};

static_assert(std::output_iterator<std::byte*, std::byte>);
static_assert(ppc::mpc::network::Network<MockNetwork>);

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

    std::thread thread1([&]() { std::tie(slice1, publicKey1) = ppc::mpc::player::createSecret(player1, mockNetwork, keyID); });
    std::thread thread2([&]() { std::tie(slice2, publicKey2) = ppc::mpc::player::createSecret(player2, mockNetwork, keyID); });
    std::thread thread3([&]() { std::tie(slice3, publicKey3) = ppc::mpc::player::createSecret(player3, mockNetwork, keyID); });

    thread1.join();
    thread2.join();
    thread3.join();

    BOOST_CHECK_NE(slice1, slice2);
    BOOST_CHECK_NE(slice2, slice3);
}

BOOST_AUTO_TEST_SUITE_END()