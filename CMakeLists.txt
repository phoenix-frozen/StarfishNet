cmake_minimum_required(VERSION 2.8.4)
project(StarfishNet C)

#as of now, this is a dummy configuration to make CLion happy.
#StarfishNet is now a Contiki networking module

#uECC configuration
add_definitions(-DuECC_CURVE=uECC_secp160r1 -DuECC_PLATFORM=uECC_arch_other -DuECC_ASM=uECC_asm_none -DuECC_WORD_SIZE=1 -DuECC_SQUARE_FUNC=0)

#contiki configuration
add_definitions(-DNETSTACK_CONF_RDC=nullrdc_driver)
add_definitions(-DNULLRDC_CONF_802154_AUTOACK=0 -DNULLRDC_CONF_802154_AUTOACK_HW=0 -DNULLRDC_CONF_ADDRESS_FILTER=0)
add_definitions(-DCC2530_RF_CONF_AUTOACK=0 -DCC2530_RF_CONF_LEDS)
add_definitions(-DLINKADDR_CONF_SIZE=8 -DPACKETBUF_CONF_WITH_PACKET_TYPE -DNETSTACK_CONF_VARIABLE_SIZE_LINK_ADDRESSES)
add_definitions(-DMMEM_CONF_SIZE=1)
#add_definitions(-DDMA_CONF_ON)

#starfishnet configuration
add_definitions(-DSN_DEBUG)
add_definitions(-DSN_DEBUG_LEVEL=4)

include_directories(../contiki/platform/cc2530dk)
include_directories(../contiki/cpu/cc253x)
include_directories(../contiki/core)

file(GLOB HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ./*.h)
file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ./*.c)

add_executable(StarfishNet ${SOURCES} ${HEADERS})
