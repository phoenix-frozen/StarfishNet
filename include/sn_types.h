#ifndef __SN_TYPES_H__
#define __SN_TYPES_H__

#include <stdint.h>
#include "mac802154_types.h"

/* Crypto */

#define SN_PK_key_bits  160
#define SN_AES_key_bits 128 //mandated by IEEE 802.15.4
#define SN_Hash_bits    160
#define SN_Tag_bits     128

#define SN_PK_key_size    (SN_PK_key_bits/8)
#define SN_AES_block_size (128/8) //mandated by AES
#define SN_AES_key_size   (SN_AES_key_bits/8)
#define SN_Hash_size      (SN_Hash_bits/8)
#define SN_Tag_size       (SN_Tag_bits/8)

typedef struct __attribute__((packed)) SN_Public_key {
    uint8_t data[SN_PK_key_size + 1]; //in packed format
} SN_Public_key_t;

typedef struct SN_Private_key {
    uint8_t data[SN_PK_key_size];
} SN_Private_key_t;

typedef struct SN_Keypair {
    SN_Public_key_t  public_key;
    SN_Private_key_t private_key;
} SN_Keypair_t;

typedef struct __attribute__((packed)) SN_Signature {
    uint8_t data[SN_PK_key_size * 2]; //size of ECDSA signature
} SN_Signature_t;

typedef struct __attribute__((packed)) SN_AES_key {
    uint8_t data[SN_AES_key_size];
} SN_AES_key_t;

typedef struct __attribute__((packed)) SN_AES_key_id {
    uint8_t data[SN_Hash_size - SN_AES_key_size];
} SN_AES_key_id_t;

typedef struct __attribute__((packed)) SN_Hash {
    uint8_t data[SN_Hash_size];
} SN_Hash_t;

typedef struct __attribute__((packed)) SN_Kex_result {
    union {
        SN_Hash_t raw;

        struct __attribute__((packed)) {
            SN_AES_key_t    key;
            SN_AES_key_id_t key_id;
        };
    };
} SN_Kex_result_t;

typedef struct __attribute__((packed)) SN_Certificate {
    struct __attribute__((packed)) {
        SN_Public_key_t subject;
        uint8_t         type;
        SN_Hash_t       assertion; //type indicates whether this is actually a hash, or a plain assertion
    } protected_data;

    SN_Signature_t  signature;
    SN_Public_key_t endorser;
} SN_Certificate_t;

typedef struct SN_Certificate_storage {
    unsigned int     capacity; //number of certificates that can be stored in this structure, in total
    unsigned int     size;     //number of certificates that are currently stored in this structure
    SN_Certificate_t contents[];
} SN_Certificate_storage_t;

/* Networking */

typedef struct SN_Address {
    mac_address_t address;
    mac_address_mode_t type;
} SN_Address_t;
#define SN_NO_SHORT_ADDRESS 0xFFFE

typedef struct SN_Nib {
    //routing tree config
    //globals
    uint8_t         tree_depth;      //maximum depth of the routing tree
    //node config
    uint8_t         tree_position;   //where we are on the routing tree
    uint8_t         tree_leaf_count; //how much of our address range should be used
                                     // for leaf nodes (the rest is delegable blocks). power of two.
    uint8_t         enable_routing;  //used internally to determine whether routing is enabled

    //retransmission config
    uint8_t         tx_retry_limit; //number of retransmits before reporting failure
    uint16_t        tx_retry_timeout; //time to wait between retransmits

    //parent pointer
    SN_Address_t    parent_address;
    SN_Public_key_t parent_public_key;
} SN_Nib_t;

typedef struct SN_Session {
    mac_session_handle_t mac_session;
    SN_Nib_t      nib;
    mac_mib_t     mib;
    mac_pib_t     pib;

    uint32_t      table_entries; //XXX: HACK! assumes table uses bitfields for allocation

    SN_Keypair_t  device_root_key;
} SN_Session_t;

#endif /* __SN_TYPES_H__ */
