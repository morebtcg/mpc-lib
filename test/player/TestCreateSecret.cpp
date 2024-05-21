#include "PlayerImpl.h"
#include <boost/test/unit_test.hpp>

class TestCreateSecretFixture {};

BOOST_FIXTURE_TEST_SUITE(TestCreateSecret, TestCreateSecretFixture)

struct MockNetwork {
    friend void tag_invoke(auto& network, ppc::mpc::PlayerID playerID, ppc::mpc::BytesConstView buffer, auto&&... args);
};

BOOST_AUTO_TEST_CASE(create) {}

BOOST_AUTO_TEST_SUITE_END()