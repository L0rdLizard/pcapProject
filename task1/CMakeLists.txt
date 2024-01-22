cmake_minimum_required(VERSION 3.12)

# include(FetchContent)

project(task1)

# add_executable(task1 main.cpp)

# FetchContent_Declare(
#   mypcap
#   GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
#   GIT_TAG        master
# )

# FetchContent_MakeAvailable(mypcap)

# target_link_libraries (task1 PRIVATE mypcap)


set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

add_executable(task1 main.cpp)
target_link_libraries(task1 ${PCAP_LIBRARY})
