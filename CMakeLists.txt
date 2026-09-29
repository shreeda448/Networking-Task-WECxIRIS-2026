cmake_minimum_required(VERSION 3.20)
project(custom-tls)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)
add_executable(server
    server.c
    io.c
    net.c
)
add_executable(client
    client.c
    io.c
    net.c
)
