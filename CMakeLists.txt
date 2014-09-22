cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet)

set(SRC_DIR src)
set(TEST_DIR test)

add_definitions(-std=gnu99 -g -Wall -DuECC_CURVE=uECC_secp160r1)
add_definitions(-DuECC_PLATFORM=uECC_x86_64)
add_definitions(-DSN_DEBUG)
#add_definitions(-DSN_DEBUG_LEVEL=4)
#add_definitions(-DMAC_DEBUG)
#add_definitions(-DNDEBUG)

include_directories(include)

AUX_SOURCE_DIRECTORY(${SRC_DIR} SOURCES)

add_library(StarfishNet STATIC ${SOURCES})

AUX_SOURCE_DIRECTORY(${TEST_DIR} TESTSRCS)
set(TESTS "")

foreach(TESTSRC ${TESTSRCS})
  string(REGEX REPLACE "test/(.*)\\.c$" "\\1" TEST ${TESTSRC})
  add_executable(${TEST} ${TESTSRC})
  target_link_libraries(${TEST} StarfishNet)
  set(TESTS "${TESTS};${TEST}")
endforeach(TESTSRC)

add_custom_target(ALL DEPENDS StarfishNet ${TESTS})
