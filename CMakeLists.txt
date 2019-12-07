cmake_minimum_required(VERSION 3.1)

project(cryptVM)

# Palisade wont build without this
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

add_subdirectory("palisade/" EXCLUDE_FROM_ALL)
include_directories($<TARGET_PROPERTY:allmodules,INCLUDE_DIRECTORIES>)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -pthread -fopenmp")

#find_package(PkgConfig REQUIRED)

set(cryptvm_sources
    src/main.cpp
)

add_executable(cryptvm ${cryptvm_sources})

add_dependencies(cryptvm allmodules)
