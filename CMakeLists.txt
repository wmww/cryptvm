cmake_minimum_required(VERSION 3.1)

project(cryptVM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Werror -pthread")

find_package(PkgConfig REQUIRED)

add_subdirectory("palisade/")

set(cryptvm_sources
    src/main.cpp
)

add_executable(cryptvm ${cryptvm_sources})

