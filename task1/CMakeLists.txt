cmake_minimum_required(VERSION 3.12)

include(FetchContent)

project(task1)

add_executable(task1 main.cpp)

FetchContent_Declare(
  pcap
  GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
  GIT_TAG        master
)
FetchContent_MakeAvailable(pcap)

target_link_libraries (task1 PRIVATE pcap)
