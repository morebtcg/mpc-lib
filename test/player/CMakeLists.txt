list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_executable(playerTest
    TestCreateSecret.cpp
    main.cpp
)

find_package(boost_unit_test_framework CONFIG REQUIRED)
target_link_libraries(playerTest PRIVATE player Boost::unit_test_framework)

add_test(NAME playerTest COMMAND playerTest)
