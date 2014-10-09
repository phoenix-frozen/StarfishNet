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
    //flags
    union {
        struct {
            uint8_t dissociate :1; //this is a dissociation message (if 0, a key-agreement header follows)
            uint8_t child      :1;
            //in a request   : request an address as well (implying you're my neighbor)
            //in a reply     : flags the presence of an address allocation header
            //in a dissociate: this is an address revocation, not a full dissociation
            uint8_t router     :1; //only valid if child == 1
            //in a request   : the address request is for a block, not a single
            //in a reply     : the following address allocation header is for a block
            //in a dissociate: ignored
            uint8_t mbz        :5;
        };
        uint8_t flags;
    };
} association_header_t;

typedef struct __attribute__((packed)) key_agreement_header {
    SN_Public_key_t key_agreement_key;
} key_agreement_header_t;

typedef struct __attribute__((packed)) key_confirmation_header {
    SN_Hash_t challenge;
} key_confirmation_header_t;

typedef struct __attribute__((packed)) encryption_header {
    uint8_t  tag[SN_Tag_size];
} encryption_header_t;

typedef struct __attribute__((packed)) signature_header {
    SN_Signature_t signature;
} signature_header_t;

typedef struct __attribute__((packed)) encrypted_ack_header {
    uint32_t counter;
} encrypted_ack_header_t;

typedef struct __attribute__((packed)) signed_ack_header {
    SN_Signature_t signature; //the signature of the packet we're acknowledging
} signed_ack_header_t;

typedef uint8_t payload_data_t;

typedef struct packet {
    /* This structure is a table of offsets in contents.MCPS_DATA_{indication,request}.msdu.
     * It also contains a bitfield indicating which of thses offsets are valid.
     *
     * The PACKET_ENTRY macro does the appropriate pointer arithmetic and typecasts to make
     * use of them. In particular, it will generate a NULL pointer when looking up an entry
     * whose present bit isn't set.
     *
     * The names of the various pieces that go into making this system work must abide by
     * the following pattern:
     * * presence entry is called [name] (_header for header entries, by convention)
     * * table    entry is called [name]
     * * structure type is called [name]_t
     */
    struct packet_layout {
        union {
            struct {
                uint16_t network_header                  :1;
                uint16_t node_details_header             :1;
                uint16_t association_header              :1;
                uint16_t key_agreement_header            :1;
                uint16_t encryption_header               :1;
                uint16_t key_confirmation_header         :1;
                uint16_t signature_header                :1;
                uint16_t encrypted_ack_header            :1;
                uint16_t signed_ack_header               :1;

                uint16_t payload_data                    :1;
            };

            uint16_t raw;
        } present;

        uint8_t network_header;
        uint8_t node_details_header;
        uint8_t association_header;
        uint8_t key_agreement_header;
        uint8_t encryption_header;
        uint8_t key_confirmation_header;
        uint8_t signature_header;
        uint8_t encrypted_ack_header;
        uint8_t signed_ack_header;

        uint8_t payload_data;
        uint8_t payload_length;
    } layout;

    mac_primitive_t contents;
} packet_t;

/*argument type notes:
 * packet must be of type packet_t (not packet_t*)
 * req_type must be one of:
 *  "request", if this is an outgoing packet
 *  "indication", if this is an incoming packet
 */
#define PACKET_ENTRY(packet, header, req_type) ((header##_t*)((packet).layout.present.header ? (packet).contents.MCPS_DATA_##req_type.msdu + (packet).layout.header : NULL))
#define PACKET_SIZE(packet, req_type) ((packet).contents.MCPS_DATA_##req_type.msduLength)

#endif /* __SN_TXRX_H__ */
