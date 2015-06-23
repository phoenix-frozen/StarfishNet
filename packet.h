#ifndef __SN_PACKET_H__
#define __SN_PACKET_H__

#include "types.h"
#include "node_table.h"

/*StarfishNet header ordering:
 * network_header_t
 * node_details_header_t
 * association_transaction_header_t
 * key_confirmation_header_t
 * address_[block_]header_t
 */

//StarfishNet packet header
//XXX: order of members is assumed by packet encryption routines
typedef struct network_header {
    uint8_t protocol_id;
    uint8_t protocol_ver;

    uint16_t src_addr;
    uint16_t dst_addr;
    union {
        struct {
            uint8_t alt_stream  :1; //indicates the presence of an alternate stream header
            uint8_t data        :1; //this is a data packet (1: follow data_attributes; 0: follow control_attributes)
            uint8_t A           :1; //packet type dependent
            uint8_t key_confirm :1; //flags the presence of a key confirmation header
            uint8_t type_dep    :4; //packet type dependent
        };
        struct {
            uint8_t alt_stream  :1;
            uint8_t data        :1;
            uint8_t ack         :1; //indicates the presence of a data acknowledgement header
            uint8_t key_confirm :1; //flags the presence of a key confirmation header
            uint8_t evidence    :1; //0: the payload is plain data; 1: it is evidence, and an evidence header is present
            uint8_t unused      :3;
        } data_attributes;
        struct {
            uint8_t alt_stream  :1;
            uint8_t data        :1;
            uint8_t associate   :1; //flags the presence of an association request header
            uint8_t key_confirm :1; //flags the presence of a key confirmation header
            uint8_t req_details :1; //requests that the remote party send its details
            uint8_t details     :1; //flags the presence of a node details header
            uint8_t unused      :2;
        } control_attributes;
        uint8_t attributes;
    };
} network_header_t;
#define ATTRIBUTE(network_header, attribute) ((network_header)->attribute)
#define DATA_ATTRIBUTE(network_header, attribute) (ATTRIBUTE(network_header, data) && (network_header)->data_attributes.attribute)
#define CONTROL_ATTRIBUTE(network_header, attribute) (!ATTRIBUTE(network_header, data) && (network_header)->control_attributes.attribute)

typedef struct alt_stream_header {
    //alternate stream
    uint8_t length;
    uint8_t stream_idx[];
} alt_stream_header_t;

typedef struct node_details_header {
    //node information
    SN_Public_key_t signing_key;
} node_details_header_t;

typedef struct association_header {
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

typedef struct key_agreement_header {
    SN_Public_key_t key_agreement_key;
} key_agreement_header_t;

typedef struct key_confirmation_header {
    SN_Hash_t challenge;
} key_confirmation_header_t;

typedef struct encryption_header {
    uint8_t  tag[SN_Tag_size];
} encryption_header_t;

typedef struct signature_header {
    SN_Signature_t signature;
} signature_header_t;

typedef struct encrypted_ack_header {
    uint32_t counter;
} encrypted_ack_header_t;

typedef struct evidence_header {
    //some evidence-related metadata. at the moment only contains a type bit
    union {
        struct {
            uint8_t certificate :1; //true: this is an SN_Certificate_t, signed as normal
                                    //false: this is an assertion whose implicit signer is the sender
            uint8_t mbz :7;
        };
        uint8_t flags;
    };
} evidence_header_t;

typedef uint8_t payload_data_t;

#define SN_MAXIMUM_PACKET_SIZE (127 - 9 - 2) /* PHY_max is 127 bytes. Then 9 for minimum MAC header size, 2 because we always have two addresses */

typedef struct packet {
    /* This structure is a table of offsets in contents.MCPS_DATA_{indication,request}.msdu.
     * It also contains a bitfield indicating which of these offsets are valid.
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
    struct {
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
                uint16_t evidence_header                 :1;
                uint16_t alt_stream_header               :1;

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
        uint8_t evidence_header;
        uint8_t alt_stream_header;

        uint8_t payload_data;
        uint8_t payload_length;
    } layout;

    uint8_t length;

    uint8_t* data;
} packet_t;

/*argument type notes:
 * packet must be of type packet_t (not packet_t*)
 * req_type must be one of:
 *  "request", if this is an outgoing packet
 *  "indication", if this is an incoming packet
 */
#define PACKET_ENTRY(packet, entry, req_type) ((entry##_t*)((packet).layout.present.entry ? (packet).data + (packet).layout.entry : NULL))
#define PACKET_SIZE(packet, req_type) ((packet).length)

/* transmit side */
int packet_encrypt_authenticate(packet_t* packet, SN_Public_key_t* key_agreement_key, SN_AES_key_t* link_key, uint32_t encryption_counter, bool pure_ack);
int packet_generate_headers(packet_t* packet, SN_Table_entry_t* table_entry, SN_Message_t* message);
int packet_generate_payload(packet_t* packet, SN_Message_t* message);

/* receive side */
int packet_detect_layout(packet_t* packet);
int packet_security_checks(packet_t* packet, SN_Table_entry_t* table_entry);
int packet_public_key_operations(packet_t* packet, SN_Table_entry_t* table_entry);
int packet_process_headers(packet_t* packet, SN_Table_entry_t* table_entry);
int packet_decrypt_verify(packet_t* packet, SN_Public_key_t* key_agreement_key, SN_AES_key_t* link_key, uint32_t encryption_counter, bool pure_ack);


#endif /* __SN_PACKET_H__ */
