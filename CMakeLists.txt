cmake_minimum_required(VERSION 3.10)
project(chacha20_poly1305 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# --- Library ---

add_library(chacha20_poly1305 STATIC
    src/chacha20.c
    src/poly1305.c
)

target_include_directories(chacha20_poly1305
    PUBLIC  include
    PRIVATE src
)

# --- Tests (Unity) ---

enable_testing()

add_library(unity STATIC Unity/src/unity.c)
target_include_directories(unity PUBLIC Unity/src)

foreach(test_name chacha20 poly1305)
    add_executable(test_${test_name} test/test_${test_name}.c)
    target_link_libraries(test_${test_name} chacha20_poly1305 unity)
    target_include_directories(test_${test_name} PRIVATE src)
    add_test(NAME test_${test_name} COMMAND test_${test_name})
endforeach()
