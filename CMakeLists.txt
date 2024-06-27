cmake_minimum_required(VERSION 3.0)
project(lief-instrum)

set(CMAKE_CXX_STANDARD 11)

find_package(LIEF REQUIRED)

add_executable(static_patch src/static_patch.cc src/api.cc)
target_link_libraries(static_patch LIEF::LIEF)

add_executable(call_rewrite src/call_rewrite.cc src/api.cc)
target_link_libraries(call_rewrite LIEF::LIEF)

add_subdirectory(lib)
add_subdirectory(patchee)