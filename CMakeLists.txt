cmake_minimum_required(VERSION 3.8)
project(analyze)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c hash.c hash.h packet.c packet.h protocol.h congestion.c congestion.h loss.c loss.h sample.c sample.h everflow.c everflow.h netseer.c netseer.h)
add_executable(analyze ${SOURCE_FILES})

target_link_libraries(analyze pcap)

include_directories(C:\\Users\\ZhouYu\\Desktop\\libpcap-1.9.0)

# link_libraries(pcap)