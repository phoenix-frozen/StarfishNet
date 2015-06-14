cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet C)

#as of now, this is a dummy configuration to make CLion happy.
#StarfishNet is now a Contiki networking module

#uECC configuration
add_definitions(-DuECC_CURVE=uECC_secp160r1 -DuECC_PLATFORM=uECC_arch_other -DuECC_ASM=uECC_asm_none -DuECC_WORD_SIZE=1)

include_directories(../contiki/platform/cc2530dk)
include_directories(../contiki/cpu/cc253x)
include_directories(../contiki/core)

#core
file(GLOB HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ./*.h)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ./*.c)

#uECC
list(APPEND HEADERS extern/micro-ecc/uECC.h)
list(APPEND SOURCES extern/micro-ecc/uECC.c)

#libsha1
list(APPEND HEADERS extern/libsha1/libsha1.h)
list(APPEND SOURCES extern/libsha1/sha1.c)

add_executable(StarfishNet ${SOURCES} ${HEADERS})
