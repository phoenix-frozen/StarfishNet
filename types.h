#ifndef __SN_TYPES_H__
#define __SN_TYPES_H__

#include "lib/aes-128.h"
#include <stdint.h>
#include <stdbool.h>

/* Crypto */

#define SN_PK_key_bits  160
#define SN_Hash_bits    160 //size of SHA1 hash
#define SN_Tag_bits      64 //matches IEEE 802.15.4 required security mode

#define SN_PK_key_size    (SN_PK_key_bits/8)
#define SN_AES_block_size AES_128_BLOCK_SIZE
#define SN_AES_key_size   AES_128_KEY_LENGTH
#define SN_Hash_size      (SN_Hash_bits/8)
#define SN_Tag_size       (SN_Tag_bits/8)

typedef struct SN_Public_key {
    uint8_t data[SN_PK_key_size + 1]; //in packed format
} SN_Public_key_t;

typedef struct SN_Private_key {
    uint8_t data[SN_PK_key_size];
} SN_Private_key_t;

typedef struct SN_Keypair {
    SN_Public_key_t  public_key;
    SN_Private_key_t private_key;
} SN_Keypair_t;

typedef struct SN_Signature {
    uint8_t data[SN_PK_key_size * 2]; //size of ECDSA signature
} SN_Signature_t;

typedef struct SN_AES_key {
    uint8_t data[SN_AES_key_size];
} SN_AES_key_t;

typedef struct SN_Hash {
    uint8_t data[SN_Hash_size];
} SN_Hash_t;

typedef struct SN_Kex_result {
    union {
        SN_Hash_t    raw;

        SN_AES_key_t key;
    };
} SN_Kex_result_t;

typedef struct SN_Certificate {
    struct {
        SN_Public_key_t subject;
        uint8_t         type;
        SN_Hash_t       assertion; //type indicates whether this is actually a hash, or a plain assertion
    } protected_data;

    SN_Signature_t  signature;
    SN_Public_key_t endorser;
} SN_Certificate_t;

/* Alternate streams */

#define SN_MAX_ALT_STREAM_IDX_BITS (128 + 16) //sized to fit an IPv6 address + a UDP port number
#define SN_MAX_ALT_STREAM_IDX_SIZE (SN_MAX_ALT_STREAM_IDX_BITS/8)

typedef struct SN_Altstream {
    uint8_t  stream_idx_length;
    uint8_t* stream_idx;
} SN_Altstream_t;

/* Networking */

typedef enum {
    SN_ENDPOINT_LONG_ADDRESS = 1,
    SN_ENDPOINT_SHORT_ADDRESS,
    SN_ENDPOINT_PUBLIC_KEY
} SN_Endpoint_type_t;

typedef struct SN_Endpoint {
    SN_Endpoint_type_t type;
    union {
        uint8_t long_address[8];
        uint16_t short_address;
        SN_Public_key_t public_key;
    };
    SN_Altstream_t* altstream;
} SN_Endpoint_t;

#define SN_BROADCAST_ADDRESS   0xFFFF
#define SN_NO_SHORT_ADDRESS    0xFFFE
#define SN_COORDINATOR_ADDRESS 0x0000

typedef struct SN_Network_config {
    //routing tree configuration
    uint8_t         routing_tree_branching_factor;
    uint16_t        leaf_blocks;

    //router information
    uint8_t         routing_tree_position;
    uint16_t        router_address;
    SN_Public_key_t router_public_key;
} SN_Network_config_t;

typedef struct SN_Network_descriptor {
    //MAC information
    uint16_t        pan_id;
    uint8_t         radio_channel;

    SN_Network_config_t* network_config;
} SN_Network_descriptor_t;

/* Messages */

//the order of items in this enum is important!
typedef enum SN_Message_type {
    SN_No_message,         //NULL marker
    SN_Dissociation_request, //used by the network layer to signal a dissociation request from another node. implicitly invalidates any short address(es) we've taken from or given to it, forcing a recursive dissociation if needs be
    SN_Association_request,  //used by the network layer to signal an association request from another node
    SN_Data_message,       //standard data message
    SN_Explicit_Evidence_message,   //send a certificate to a StarfishNet node
    SN_Implicit_Evidence_message,   //send a partial certificate to a StarfishNet node. we are its implicit signer
} SN_Message_type_t;

//StarfishNet messages
typedef union SN_Message {
    SN_Message_type_t type;

    struct {
        SN_Message_type_t type;
        uint8_t*          payload;
        uint8_t           payload_length;
    } data_message;

    struct {
        SN_Message_type_t type;
        SN_Certificate_t* evidence;
    } explicit_evidence_message;

    //TODO: implicit_evidence_message

    struct {
        SN_Message_type_t type;
    } association_message;
} SN_Message_t;
#define SN_MAX_DATA_MESSAGE_LENGTH 127
//TODO: make SN_MAX_DATA_MESSAGE_LENGTH right



#endif /* __SN_TYPES_H__ */
