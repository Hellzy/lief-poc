cmake_minimum_required(VERSION 3.0)
project(lief-instrum)

set(CMAKE_CXX_STANDARD 11)

find_package(LIEF REQUIRED)

add_subdirectory(lib)
add_subdirectory(patchee)

add_library(api src/api.cc)
target_link_libraries(api LIEF::LIEF)

add_executable(static_patch src/static_patch.cc)
target_link_libraries(static_patch api)

add_executable(call_rewrite src/call_rewrite.cc)
target_link_libraries(call_rewrite api)

add_executable(dyn_patch src/dyn_patch.cc)
target_link_libraries(dyn_patch api)