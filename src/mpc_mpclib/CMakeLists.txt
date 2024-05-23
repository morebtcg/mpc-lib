add_library(mpc_mpclib SHARED PlatformImpl.cpp)

find_package(boost_exception CONFIG REQUIRED)
find_package(boost_serialization CONFIG REQUIRED)

target_include_directories(mpc_mpclib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mpc_mpclib PUBLIC cosigner Boost::exception Boost::serialization)
