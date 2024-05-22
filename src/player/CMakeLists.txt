add_library(player SHARED KeyPersistencyImpl.cpp PlatformImpl.cpp PreprocessingPersistencyImpl.cpp)

find_package(boost_exception CONFIG REQUIRED)
find_package(boost_serialization CONFIG REQUIRED)

target_include_directories(player PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(player PUBLIC cosigner Boost::exception Boost::serialization)
