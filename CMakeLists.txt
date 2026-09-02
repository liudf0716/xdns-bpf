cmake_minimum_required(VERSION 3.10)
project(xdns-bpf C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(xdns-ctl src/xdns_ctl.c)

# Build eBPF object if clang is found
find_program(CLANG_PATH clang)
if (CLANG_PATH)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o
        COMMAND ${CLANG_PATH} -target bpf -O2 -g -Wall
                -I${CMAKE_CURRENT_SOURCE_DIR}/src -I/usr/include
                -c ${CMAKE_CURRENT_SOURCE_DIR}/src/xdns_bpf.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o
        DEPENDS src/xdns_bpf.c src/xdns_bpf.h
        COMMENT "Building eBPF object xdns_bpf.o"
    )
    add_custom_target(bpf ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o)
endif()

install(TARGETS xdns-ctl DESTINATION bin)
if (CLANG_PATH)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xdns_bpf.o DESTINATION lib/bpf)
endif()
install(FILES files/xdns.conf DESTINATION /etc/config RENAME xdns)
install(FILES files/xdns.init DESTINATION /etc/init.d RENAME xdns PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES files/whitelist.txt DESTINATION /etc/xdns)
