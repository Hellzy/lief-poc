cmake_minimum_required(VERSION 3.0)
project(lief-instrum)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "-g -O0")

add_executable(patchee main.cc)