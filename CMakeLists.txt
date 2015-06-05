cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet-CC2530 C)

#as of now, this is a dummy configuration to make CLion happy.
#StarfishNet is now a Contiki networking module

#uECC configuration
add_definitions(-DuECC_CURVE=uECC_secp160r1 -DuECC_PLATFORM=uECC_arch_other -DuECC_ASM=uECC_asm_none -DuECC_WORD_SIZE=1)

#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG_LEVEL=4")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DCC2530_RF_CONF_HEXDUMP")
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

include_directories(include)
include_directories(extern/libsha1)
include_directories(extern/micro-ecc)
include_directories(../contiki/platform/cc2530dk)
include_directories(../contiki/cpu/cc253x)
include_directories(../contiki/core)

#core
file(GLOB HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} include/*.h)
file(GLOB LOCAL_HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} src/*.h)
list(APPEND HEADERS ${LOCAL_HEADERS})
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} src/*.c)

#uECC
list(APPEND HEADERS extern/micro-ecc/uECC.h)
list(APPEND SOURCES extern/micro-ecc/uECC.c)

#libsha1
list(APPEND HEADERS extern/libsha1/libsha1.h)
list(APPEND SOURCES extern/libsha1/sha1.c)

add_executable(StarfishNet ${SOURCES} ${HEADERS})
