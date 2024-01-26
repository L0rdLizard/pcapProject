cmake_minimum_required(VERSION 3.12)

project(task1)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

add_executable(task1 main.cpp PacketClassifier.cpp)
target_link_libraries(task1 ${PCAP_LIBRARY})
