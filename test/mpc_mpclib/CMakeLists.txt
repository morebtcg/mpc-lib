list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_executable(mpcTest
    TestCreateSecret.cpp
    main.cpp
)

find_package(boost_unit_test_framework CONFIG REQUIRED)
target_link_libraries(mpcTest PRIVATE mpc_mpclib Boost::unit_test_framework)

add_test(NAME mpcTest COMMAND playerTest)
