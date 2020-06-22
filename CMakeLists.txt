cmake_minimum_required(VERSION 3.14)
project(arpspoof C)

set(CMAKE_C_STANDARD 11)

#pkg-config
find_package(PkgConfig)

#get libnet config
pkg_check_modules(LIBNET REQUIRED libnet)
MESSAGE(STATUS ${LIBNET_LIBRARY_DIRS})
MESSAGE(STATUS ${LIBNET_INCLUDE_DIRS})
MESSAGE(STATUS ${LIBNET_LIBRARIES})

#get libpcap config
pkg_check_modules(LIBPCAP REQUIRED libpcap)
MESSAGE(STATUS ${LIBPCAP_LIBRARY_DIRS})
MESSAGE(STATUS ${LIBPCAP_INCLUDE_DIRS})
MESSAGE(STATUS ${LIBPCAP_LIBRARIES})

#lib dirs
link_directories(
        ${LIBNET_LIBRARY_DIRS}
        ${LIBPCAP_LIBRARY_DIRS}
)

#header dirs
include_directories(
        ${LIBNET_INCLUDE_DIRS}
        ${LIBPCAP_INCLUDE_DIRS}
)

add_executable(arpspoof arpspoof.c arp.c)

target_link_libraries(arpspoof ${LIBNET_LIBRARIES})
#target_link_libraries(arpspoof libnet.a)
target_link_libraries(arpspoof ${LIBPCAP_LIBRARIES})
#target_link_libraries(arpspoof libpcap.a)

install(TARGETS arpspoof RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})