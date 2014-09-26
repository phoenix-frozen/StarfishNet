cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet)

set(SRC_DIR src)
set(TEST_DIR test)

add_definitions(-std=gnu99 -g -Wall -DuECC_CURVE=uECC_secp160r1 -DPOLARSSL_CONFIG_FILE=<config-starfishnet.h>)
add_definitions(-DSN_DEBUG)
#add_definitions(-DSN_DEBUG_LEVEL=4)
#add_definitions(-DMAC_DEBUG)
#add_definitions(-DNDEBUG)

include_directories(include)
include_directories(src/polarssl)
include_directories(extern/micro-ecc)
include_directories(extern/polarssl/include)

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

aux_source_directory(${TEST_DIR} TESTSRCS)

foreach(TESTSRC ${TESTSRCS})
  string(REGEX REPLACE "test/(.*)\\.c$" "\\1" TEST ${TESTSRC})
  add_executable(${TEST} ${TESTSRC})
  target_link_libraries(${TEST} StarfishNet)
  list(APPEND TESTS ${TEST})
endforeach(TESTSRC)

add_custom_target(ALL DEPENDS StarfishNet ${TESTS})
