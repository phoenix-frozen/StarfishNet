cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet)

set(SRC_DIR src)
set(TEST_DIR test)

add_definitions(-std=gnu99 -Wall -DuECC_CURVE=uECC_secp160r1 -DPOLARSSL_CONFIG_FILE=<config-starfishnet.h>)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSN_DEBUG -DSN_DEBUG_LEVEL=4 -DMAC_DEBUG")
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

include_directories(include)
include_directories(src/polarssl)
include_directories(extern/micro-ecc)
include_directories(extern/polarssl/include)

#begin core code
file(GLOB HEADERS include/*.h)
list(APPEND HEADERS extern/micro-ecc/uECC.h)
list(APPEND HEADERS extern/polarssl/include/polarssl/aes.h)
list(APPEND HEADERS extern/polarssl/include/polarssl/aesni.h)
list(APPEND HEADERS extern/polarssl/include/polarssl/sha1.h)
list(APPEND HEADERS extern/polarssl/include/polarssl/check_config.h)

file(GLOB_RECURSE LOCAL_HEADERS src/*.h)
list(APPEND HEADERS ${LOCAL_HEADERS})

file(GLOB_RECURSE SOURCES src/*.c)
list(APPEND SOURCES extern/micro-ecc/uECC.c)
list(APPEND SOURCES extern/polarssl/library/aes.c)
list(APPEND SOURCES extern/polarssl/library/aesni.c)
list(APPEND SOURCES extern/polarssl/library/sha1.c)

add_library(StarfishNet STATIC ${SOURCES} ${HEADERS})

#begin tests

#routertest
add_executable(routertest test/routertest.c)
target_link_libraries(routertest StarfishNet)

#coordtest
add_executable(coordtest test/coordtest.c)
target_link_libraries(coordtest StarfishNet)

#leaftest
add_executable(leaftest test/leaftest.c)
target_link_libraries(leaftest StarfishNet)


#hack for CLion
add_custom_target(ALL DEPENDS StarfishNet routertest coordtest leaftest)
