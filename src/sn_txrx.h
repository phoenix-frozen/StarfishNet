#ifndef __SN_TXRX_H__
#define __SN_TXRX_H__

#include <stdint.h>
#include <sn_types.h>

/*StarfishNet header ordering:
 * network_header_t
 * node_details_header_t
 * association_transaction_header_t
 * key_confirmation_header_t
 * address_[block_]header_t
 */

//StarfishNet packet header
//XXX: order of members is assumed by packet encryption routines
typedef struct __attribute__((packed)) network_header {
    uint8_t protocol_id;
    uint8_t protocol_ver;

    uint16_t src_addr;
    uint16_t dst_addr;
    union {
        struct {
            uint8_t encrypt      :1;
                //if true, the packet is AES-128-CCM encrypted, with the CCM tag in the tag field
                //if false, the packet is unencrypted, with a truncated SHA1 hash in the tag field
            uint8_t req_details  :1; //requests that the remote party send its details
            uint8_t details      :1; //flags the presence of a node details header
            uint8_t associate    :1; //flags the presence of an association request header
            uint8_t key_confirm  :1; //flags the presence of a key confirmation header
            uint8_t evidence     :1; //indicates that the payload is a certificate, not plain data
            uint8_t mbz          :2;
        };
        uint8_t attributes;
    };
} network_header_t;

typedef struct __attribute__((packed)) node_details_header {
    //node information
    SN_Public_key_t signing_key;
} node_details_header_t;

typedef struct __attribute__((packed)) association_request_header {
    //key agreement information
    SN_Public_key_t key_agreement_key;

    //flags
    union {
        struct {
            uint8_t dissociate :1; //flags that this is a dissociation message
            uint8_t child      :1;
            //in a request   : request an address as well (implying you're my neighbor)
            //in a reply     : flags the presence of an address allocation header
            //in a dissociate: this is an address revocation, not a full dissociation
            uint8_t router     :1; //only valid if child == 1
            //in a request   : the address request is for a block, not a single
            //in a reply     : the following address allocation header is for a block
            //in a dissociate: ignored
            uint8_t delegate   :1; //only valid if child == 1
            //in a request   : request that the remote node perform association transactions on our behalf
            //in a reply     : indicates that the remote node is willing to perform association transactions on our behalf
            //in a dissociate: this is a delegate revocation, not a full dissociation
            uint8_t mbz        :4;
        };
        uint8_t flags;
    };
} association_request_header_t;

typedef struct __attribute__((packed)) encryption_header {
    uint16_t counter;
    uint8_t  tag[SN_Tag_size];
} encryption_header_t;

typedef struct __attribute__((packed)) key_confirmation_header {
    SN_Hash_t       challenge;
} key_confirmation_header_t;

typedef struct __attribute__((packed)) address_allocation_header {
    uint16_t address;
} address_allocation_header_t;

typedef struct __attribute__((packed)) address_block_allocation_header {
    uint16_t address;
    uint8_t  block_size; //size of address block being granted. power of 2
} address_block_allocation_header_t;

typedef struct __attribute__((packed)) packet_signature_header {
    SN_Signature_t signature;
} packet_signature_header_t;

#endif /* __SN_TXRX_H__ */
