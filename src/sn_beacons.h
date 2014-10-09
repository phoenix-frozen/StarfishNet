#ifndef __SN_BEACONS_H__
#define __SN_BEACONS_H__

#include <sn_types.h>

#define BEACON_HASH_LENGTH        sizeof(SN_Hash_t)

typedef struct __attribute__((packed)) beacon_payload {
    //protocol ID information
    uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
    uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

    //routing tree information
    uint8_t  branching_factor; //routing tree branching factor. power of two. tree-global
    uint8_t  tree_position; //depth in the tree of this router
    uint16_t leaf_blocks;   //number of blocks reserved for leaf nodes. tree-global

    //capacity information
    uint8_t router_capacity; //remaining router address blocks
    uint8_t leaf_capacity;   //remaining leaf addresses

    //mac_address_t address; //64-bit mode. in case I'm broadcasting with my short address
    uint16_t address;

    SN_Public_key_t public_key;
} beacon_payload_t;

int SN_Beacon_update(SN_Session_t* session);

#endif /* __SN_BEACONS_H__ */
