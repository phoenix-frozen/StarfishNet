#ifndef __SN_TABLE_H__
#define __SN_TABLE_H__

#include "sn_types.h"

/* Interface to StarfishNet's node table.
 *
 * This is basically a routing table on steroids. For each node we know about,
 * it contains a long and short address, routing distance, public key, and
 * a chain of evidence.
 */

typedef struct SN_Table_entry {
    //session pointer
    SN_Session_t*    session;

    //addressing information
    mac_address_t    long_address; //always in 64-bit mode
    uint16_t         short_address;
    SN_Public_key_t  public_key;

    //relationship metadata
    union {
        struct {
            uint8_t state         :3; //taken from SN_Association_state
            uint8_t details_known :1; //we know the other node's details; don't ask for them
            uint8_t knows_details :1; //the other node needs our details; send them in our next transmission
            uint8_t neighbor      :1; //this node is our neighbor
            uint8_t child         :1; //only valid if neighbor == 1. this node is our child
            uint8_t router        :1; //only valid if child == 1. this node is a router (and thus possesses an address block)
        };
        uint8_t     relationship;
    };

    //cryptographic data
    SN_Keypair_t    local_key_agreement_keypair; //our ephemeral keypair
    SN_Public_key_t remote_key_agreement_key;    //remote party's ephemeral public key
    SN_Kex_result_t link_key;                    //result of ECDH transaction
    uint16_t        packet_tx_count;             //packet transmission count
} SN_Table_entry_t;

//insert an entry into the table. entire data structure must be valid
int SN_Table_insert (SN_Table_entry_t* entry);
//update an existing entry. entire data structure must be valid
int SN_Table_update (SN_Table_entry_t* entry);
//delete an entry. any one of: long address, short address, key, must be valid. note: you're responsible for any certificate storage you've assigned to this entry
int SN_Table_delete (SN_Table_entry_t* entry);
//delete all entries related to a session
void SN_Table_clear (SN_Session_t* session);
//add security metadata
int SN_Table_associate_metadata (SN_Table_entry_t* entry, SN_Certificate_storage_t* storage);

//lookups can be by address or by public key. first parameter is input, second and third are output
//entry->session must be valid
int SN_Table_lookup_by_address    (SN_Address_t*    address,    SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence);
int SN_Table_lookup_by_public_key (SN_Public_key_t* public_key, SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence);

#endif /* __SN_TABLE_H__ */
