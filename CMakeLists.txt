cmake_minimum_required(VERSION 3.20)
project(custom-tls)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
set(CSL_SOURCES kdf.c frame.c io.c handshake.c net.c dh.c)

option(CSL_DEBUG "Print debug messages" OFF)
if(CSL_DEBUG)
    add_compile_definitions(CSL_DEBUG)
endif()

option(BUILD_TESTS "Build unit tests (with sanitizers)" OFF)

add_executable(server
    server.c
    ${CSL_SOURCES}
)
add_executable(client
    client.c
    ${CSL_SOURCES}
)

target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(BUILD_TESTS)
    add_executable(test_frame test_frame.c ${CSL_SOURCES})
    add_executable(test_dh test_dh.c  ${CSL_SOURCES})
    target_compile_options(test_frame PRIVATE -fsanitize=address,undefined -g)
    target_link_options(test_frame PRIVATE -fsanitize=address,undefined)
    target_link_libraries(test_frame PRIVATE OpenSSL::Crypto)
    target_link_libraries(test_dh PRIVATE OpenSSL::Crypto)
endif()
