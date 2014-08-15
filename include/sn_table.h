#ifndef __SN_TABLE_H__
#define __SN_TABLE_H__

#include "sn_core.h"

/* Interface to StarfishNet's node table.
 *
 * This is basically a routing table on steroids. For each node we know about,
 * it contains a long and short address, routing distance, public key, and
 * a chain of evidence.
 */

typedef struct SN_Table_entry {
    SN_Session_t*        session;
    mac_address_t        long_address; //always in 64-bit mode
    uint16_t             short_address;
    SN_ECC_public_key_t  public_key;

    SN_AES_key_t         link_key;
    uint8_t              is_neighbor;
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
int SN_Table_lookup_by_address    (SN_Address_t* address,           SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence);
int SN_Table_lookup_by_public_key (SN_ECC_public_key_t* public_key, SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence);

#endif /* __SN_TABLE_H__ */

