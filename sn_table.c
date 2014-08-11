#include "sn_table.h"
#include "sn_status.h"
#include "sn_logging.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//implemented as 32-entry table with free bitmap
#define TABLE_SIZE 32

typedef struct internal_table_entry {
    SN_Table_entry_t          data;
    SN_Certificate_storage_t* evidence;
} internal_table_entry_t;

#define BIT(x) (1UL << (x))
typedef uint32_t table_bitmap_t;

static internal_table_entry_t table[TABLE_SIZE];
static table_bitmap_t entry_bitmap = 0;

//TODO: consistency checks in update regarding addresses and keys

static int lookup_by_long_address(table_bitmap_t limit, mac_address_t* address) {
    if(address == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & limit & BIT(i)) && !memcmp(address->ExtendedAddress, table[i].data.long_address.ExtendedAddress, 8))
            return i;
    }

    return -1;
}

static int lookup_by_short_address(table_bitmap_t limit, mac_address_t* address) {
    if(address == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & limit & BIT(i)) && !memcmp(&address->ShortAddress, &table[i].data.short_address.ShortAddress, 2))
            return i;
    }

    return -1;
}

static int lookup_by_key(table_bitmap_t limit, SN_ECC_key_t* key) {
    if(key == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & limit & BIT(i)) && !memcmp(key->data, table[i].data.key.data, sizeof(key->data)))
            return i;
    }

    return -1;
}

static int find_entry(SN_Table_entry_t* entry) {
    table_bitmap_t limit = entry->session->table_entries;

    int ret = lookup_by_long_address(limit, &entry->long_address);
    if(ret >= 0)
        return ret;

    ret = lookup_by_short_address(limit, &entry->short_address);
    if(ret >= 0)
        return ret;

    ret = lookup_by_key(limit, &entry->key);
    if(ret >= 0)
        return ret;

    return -1;
}

static int alloc_entry() {
    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if(!(entry_bitmap & BIT(i))) {
            entry_bitmap |= BIT(i);
            return i;
        }
    }

    return -1;
}

// insert an entry into the table. entire data structure must be valid
int SN_Table_insert(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret >= 0)
        //it does. return an error
        return -SN_ERR_UNEXPECTED;

    //entry doesn't exist. allocate a new one
    ret = alloc_entry();
    if(ret < 0)
        //no free entries. error
        return -SN_ERR_RESOURCES;

    //fill new entry with data
    memcpy(&table[ret].data, entry, sizeof(table[ret].data));
    table[ret].evidence = NULL;
    entry->session->table_entries |= BIT(ret);

    return SN_OK;
}

// update an existing entry. entire data structure must be valid
int SN_Table_update(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0)
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;

    //fill entry with data
    memcpy(&table[ret].data, entry, sizeof(table[ret].data));

    return SN_OK;
}

// delete an entry. any one of: long address, short address, key, must be valid.
int SN_Table_delete(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0)
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;

    //mark entry as free, effectively deleting it
    entry_bitmap &= ~BIT(ret);
    entry->session->table_entries &= ~BIT(ret);

    //TODO: delete metadata

    return SN_OK;
}

// associate security metadata. also used to clear
int SN_Table_associate_metadata(SN_Table_entry_t* entry, SN_Certificate_storage_t* storage) {
    if(entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0)
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;

    //fill entry with data
    table[ret].evidence = storage;

    return SN_OK;
}

// lookups can be by address or by public key. first parameter is input, second and third are output
int SN_Table_lookup_by_address(SN_Address_t* address, SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence) {
    if(address == NULL || entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    int ret = -1;

    if(address->type == mac_extended_address) {
        ret = lookup_by_long_address(entry->session->table_entries, &address->address);
    } else if(address->type == mac_short_address) {
        ret = lookup_by_short_address(entry->session->table_entries, &address->address);
    } else {
        return -SN_ERR_INVALID;
    }

    if(ret < 0)
        return -SN_ERR_UNKNOWN;

    *entry = table[ret].data;

    if(evidence != NULL)
        *evidence = table[ret].evidence;

    return SN_OK;
}
int SN_Table_lookup_by_key(SN_ECC_key_t* key, SN_Table_entry_t* entry, SN_Certificate_storage_t** evidence) {
    if(key == NULL || entry == NULL || entry->session == NULL)
        return -SN_ERR_NULL;

    int ret = lookup_by_key(entry->session->table_entries, key);
    if(ret < 0)
        return -SN_ERR_UNKNOWN;

    *entry = table[ret].data;

    if(evidence != NULL)
        *evidence = table[ret].evidence;

    return SN_OK;
}

void SN_Table_clear(SN_Session_t* session) {
    if(session == NULL)
        return;

    entry_bitmap &= ~session->table_entries;
    session->table_entries = 0;

    //TODO: evidence / memory ownership issues
}

