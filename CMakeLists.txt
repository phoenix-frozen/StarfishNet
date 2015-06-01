cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet-CC2530 C)

#Tell the build system we're building for the CC2530
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_C_COMPILER sdcc)

add_definitions(--std-c99 -DuECC_CURVE=uECC_secp160r1)

set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")

#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG -DSN_DEBUG_LEVEL=4 -DMAC_DEBUG")
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

include_directories(include)
include_directories(extern/libsha1)
include_directories(extern/micro-ecc)

#headers
file(GLOB HEADERS RELATIVE_PATH CMAKE_CURRENT_SOURCE_DIR include/*.h)
list(APPEND HEADERS extern/micro-ecc/uECC.h)
list(APPEND HEADERS extern/libsha1/libsha1.h)

#headers with source
file(GLOB LOCAL_HEADERS RELATIVE_PATH CMAKE_CURRENT_SOURCE_DIR src/*.h)
list(APPEND HEADERS ${LOCAL_HEADERS})

#source
file(GLOB SOURCES RELATIVE_PATH CMAKE_CURRENT_SOURCE_DIR src/*.c)
list(APPEND SOURCES extern/micro-ecc/uECC.c)
list(APPEND SOURCES extern/libsha1/sha1.c)

add_executable(StarfishNet ${SOURCES} ${HEADERS})
