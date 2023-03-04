cmake_minimum_required(VERSION 3.24)
project(crypto_quant C)

set(CMAKE_C_STANDARD 11)


add_executable(crypto_quant main.c)

target_link_libraries(crypto_quant -lwslay -lssl -lcrypto)



