#ifndef __SN_TABLE_H__
#define __SN_TABLE_H__

#include "types.h"

/* Interface to StarfishNet's node table.
 *
 * This is basically a routing table on steroids. For each node we know about,
 * it contains a long and short address, routing distance, public key, and
 * a chain of evidence.
 */

//StarfishNet node association states
typedef enum SN_Association_state {
    SN_Unassociated,
    SN_Associate_received,
    SN_Awaiting_reply,
    SN_Awaiting_finalise,
    SN_Send_finalise,
    SN_Associated
} SN_Association_state_t;

typedef struct SN_Table_entry {
    //addressing information
    uint8_t          long_address[8];
    uint16_t         short_address;
    SN_Public_key_t  public_key; //TODO: store this in ROM, and put a pointer here

    SN_Altstream_t altstream;

    //relationship metadata
    union {
        struct {
            uint16_t state         :3; //taken from SN_Association_state
            uint16_t details_known :1; //we know the other node's details; don't ask for them
            uint16_t knows_details :1; //the other node needs our details; send them in our next transmission
            uint16_t neighbor      :1; //this node is our neighbor
            uint16_t child         :1; //only valid if neighbor == 1. this node is our child
            uint16_t router        :1; //only valid if child == 1. this node is a router (and thus possesses an address block)
            uint16_t ack           :1; //we've received new packets. send an acknowledgement in the next transmission
            uint16_t unavailable   :1; //we've lost contact with this node. bank up any transmissions until we hear from it again
        };
    };

    //cryptographic data
    //TODO: put all this in ROM?
    SN_Keypair_t    local_key_agreement_keypair; //our ephemeral keypair
    SN_Public_key_t remote_key_agreement_key;    //remote party's ephemeral public key
    SN_AES_key_t    link_key;                    //shared secret for packet encryption
    uint32_t        packet_tx_counter;           //packet transmit count
    uint32_t        packet_rx_counter;           //packet receive count
} SN_Table_entry_t;

//insert an entry into the table. entire data structure must be valid
int SN_Table_insert(SN_Table_entry_t* entry);
//update an existing entry. entire data structure must be valid
int SN_Table_update(SN_Table_entry_t* entry);
//delete an entry. any one of: long address, short address, key, must be valid.
int SN_Table_delete(SN_Table_entry_t* entry);
//delete all entries related to a session
void SN_Table_clear();

/* lookups can be by address, by public key, or by implementation-specific
 * heuristic based on available data. appropriate fields must be filled in entry,
 * which will then be filled with information from the table.
 * entry->session and entry->stream_idx[_length] must be valid
 */
int SN_Table_lookup(SN_Endpoint_t *endpoint, SN_Table_entry_t *entry);

//indicate that no entries belonging to this session should be considered neighbors anymore
void SN_Table_clear_all_neighbors();

#endif /* __SN_TABLE_H__ */
