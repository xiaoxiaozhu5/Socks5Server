cmake_minimum_required(VERSION 3.20)
project(socks_server)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(Boost 1.75.0 COMPONENTS context coroutine REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

add_executable(socks_server main.cpp SocksServer.h SocksServer.cpp ServerSession.cpp ServerSession.h NetworkIo.h Socks5Helper.h Socks5Helper.cpp Define.h)
target_link_libraries(socks_server ${Boost_LIBRARIES})
