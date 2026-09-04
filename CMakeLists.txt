cmake_minimum_required(VERSION 3.10)
project(xdns-bpf C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(xdns-ctl src/xdns_ctl.c)

# Mode selection: HOST (default) or GATEWAY
set(XDNS_MODE "HOST" CACHE STRING "Target mode: HOST or GATEWAY")
if (XDNS_MODE STREQUAL "GATEWAY")
    set(XDNS_MODE_DEF "-DXDNS_MODE_GATEWAY=1")
else()
    set(XDNS_MODE_DEF "-DXDNS_MODE_GATEWAY=0")
endif()

# Build eBPF object if clang is found
find_program(CLANG_PATH clang)
if (CLANG_PATH)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o
        COMMAND ${CLANG_PATH} -target bpf -O2 -g -Wall ${XDNS_MODE_DEF}
                -I${CMAKE_CURRENT_SOURCE_DIR}/src -I/usr/include
                -c ${CMAKE_CURRENT_SOURCE_DIR}/src/xdns_bpf.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o
        DEPENDS src/xdns_bpf.c src/xdns_bpf.h
        COMMENT "Building eBPF object xdns_bpf.o (${XDNS_MODE} mode)"
    )
    add_custom_target(bpf ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o)
endif()

install(TARGETS xdns-ctl DESTINATION bin)
if (CLANG_PATH)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o DESTINATION lib/bpf)
endif()
