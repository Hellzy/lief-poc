cmake_minimum_required(VERSION 3.0)
project(lief-instrum)

set(CMAKE_CXX_STANDARD 11)

find_package(LIEF REQUIRED)

add_subdirectory(lib)
add_subdirectory(patchee)

add_library(api src/api.cc)

add_executable(static_patch src/static_patch.cc)
target_link_libraries(static_patch LIEF::LIEF api)

add_executable(call_rewrite src/call_rewrite.cc)
target_link_libraries(call_rewrite LIEF::LIEF api)