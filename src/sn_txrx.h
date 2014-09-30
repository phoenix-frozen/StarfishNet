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
            uint8_t encrypt      :1; //this packed is encrypted. (false means it's signed.)
            uint8_t req_details  :1; //requests that the remote party send its details
            uint8_t details      :1; //flags the presence of a node details header
            uint8_t associate    :1; //flags the presence of an association request header
            uint8_t key_confirm  :1; //flags the presence of a key confirmation header
            uint8_t evidence     :1; //indicates that the payload is a certificate, not plain data
            uint8_t ack          :1; //indicates the presence of a data acknowledgement header
            uint8_t mbz          :1;
        };
        uint8_t attributes;
    };
} network_header_t;

typedef struct __attribute__((packed)) node_details_header {
    //node information
    SN_Public_key_t signing_key;
} node_details_header_t;

typedef struct __attribute__((packed)) association_header {
    //key agreement information
    SN_Public_key_t key_agreement_key;

    //flags
    union {
        struct {
            uint8_t dissociate :1; //this is a dissociation message
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

            //note: dissociate, child, and delegate may all be true
        };
        uint8_t flags;
    };
} association_header_t;

typedef struct __attribute__((packed)) key_confirmation_header {
    SN_Hash_t challenge;
} key_confirmation_header_t;

typedef struct __attribute__((packed)) address_allocation_header {
    uint16_t address;
} address_allocation_header_t;

typedef struct __attribute__((packed)) address_block_allocation_header {
    uint16_t address;
    uint8_t  block_size; //size of address block being granted. power of 2
} address_block_allocation_header_t;

typedef struct __attribute__((packed)) encryption_header {
    uint16_t counter;
    uint8_t  tag[SN_Tag_size];
} encryption_header_t;

typedef struct __attribute__((packed)) signature_header {
    SN_Signature_t signature;
} signature_header_t;

typedef struct __attribute__((packed)) encrypted_ack_header {
    uint16_t counter;
    uint8_t  range; //we can use this to acknowledge several messages at once
} encrypted_ack_header_t;

typedef struct __attribute__((packed)) signed_ack_header {
    SN_Signature_t signature; //the signature of the packet we're acknowledging
} signed_ack_header_t;

typedef struct packet {
    struct packet_layout {
        network_header_t                 * network_header;
        node_details_header_t            * node_details_header;
        association_header_t             * association_header;
        encryption_header_t              * encryption_header;
        key_confirmation_header_t        * key_confirmation_header;
        address_allocation_header_t      * address_allocation_header;
        address_block_allocation_header_t* address_block_allocation_header;
        signature_header_t               * signature_header;
        encrypted_ack_header_t           * encrypted_ack_header;
        signed_ack_header_t              * signed_ack_header;

        uint8_t                          * payload_data;

        uint8_t payload_length;
        uint8_t crypto_margin;
    } packet_layout;

    mac_primitive_t packet_data;
} packet_t;

//#define PACKET_HEADER(packet, header, req_type) (header##_header_t*)((packet).packet_data.MCPS_DATA_##req_type.msdu + (packet).packet_layout.##header##_header)
//#define PACKET_DATA(packet, req_type) ((packet).packet_data.MCPS_DATA_##req_type.msdu + (packet).packet_layout.payload_data)
#define PACKET_HEADER(packet, header, req_type) ((packet).packet_layout.header##_header)
#define PACKET_DATA(packet, req_type) ((packet).packet_layout.payload_data)
#define PACKET_SIZE(packet, req_type) ((packet).packet_data.MCPS_DATA_##req_type.msduLength)

#endif /* __SN_TXRX_H__ */
