cmake_minimum_required(VERSION 3.20)
project(custom-tls)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

option(CSL_DEBUG "Print debug messages" OFF)
if(CSL_DEBUG)
    add_compile_definitions(CSL_DEBUG)
endif()

option(BUILD_TESTS "Build unit tests (with sanitizers)" OFF)

add_executable(server
    server.c
    frame.c
    io.c
    net.c
)
add_executable(client
    client.c
    frame.c
    io.c
    net.c
)

if(BUILD_TESTS)
    add_executable(test_frame test_frame.c frame.c io.c)
    target_compile_options(test_frame PRIVATE -fsanitize=address,undefined -g)
    target_link_options(test_frame PRIVATE -fsanitize=address,undefined)
endif()
