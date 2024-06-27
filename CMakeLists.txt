cmake_minimum_required(VERSION 3.0)
project(lief-instrum)

set(CMAKE_CXX_STANDARD 11)

find_package(LIEF REQUIRED)

add_executable(lief-instrum src/main.cc src/api.cc)
target_link_libraries(lief-instrum LIEF::LIEF)

add_subdirectory(lib)
add_subdirectory(patchee)