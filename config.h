#ifndef STARFISHNET_CONFIG_H_
#define STARFISHNET_CONFIG_H_

#include "types.h"

typedef struct SN_Config {
    SN_Keypair_t device_root_key;

    struct {
        //routing tree config
        //globals
        uint8_t         tree_branching_factor; //routing tree branching factor. power of two. tree-global
        uint16_t        leaf_blocks;      //number of address blocks reserved for leaf nodes. tree-global
        //node config
        uint8_t         tree_position;   //where we are on the routing tree
        uint8_t         enable_routing;  //used internally to determine whether routing is enabled

        //address allocator config
        uint16_t        router_blocks_allocated;  //number of sub-blocks allocated to routers
        uint16_t        leaf_addresses_allocated; //number of addresses actually allocated to leaf nodes

        //retransmission config
        uint8_t         tx_retry_limit; //number of retransmits before reporting failure
        uint16_t        tx_retry_timeout; //time to wait between retransmits

        //parent pointer
        uint16_t        parent_address;
        SN_Public_key_t parent_public_key;
    } nib;

    struct {
    } mib;

    struct {
    } pib;
} SN_Config_t;

extern SN_Config_t starfishnet_config;

#endif //STARFISHNET_CONFIG_H_
