#include "sn_table.h"
#include "sn_status.h"

#define SN_DEBUG
#include "sn_logging.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//implemented as 32-entry table with free bitmap
#define TABLE_SIZE 32

typedef struct internal_table_entry {
    SN_Table_entry_t        data;
    SN_Security_metadata_t* security;
} internal_table_entry_t;

#define BIT(x) (1UL << (x))
typedef uint32_t table_bitmap_t;

static internal_table_entry_t table[TABLE_SIZE];
static table_bitmap_t entry_bitmap = 0;

static int lookup_by_long_address(mac_address_t* address) {
    if(address == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) && !memcmp(address->ExtendedAddress, table[i].data.long_address.ExtendedAddress, 8))
            return i;
    }

    return -1;
}

static int lookup_by_short_address(mac_address_t* address) {
    if(address == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) && !memcmp(&address->ShortAddress, &table[i].data.short_address.ShortAddress, 2))
            return i;
    }

    return -1;
}

static int lookup_by_key(SN_ECC_key_t* key) {
    if(key == NULL)
        return -1;

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) && !memcmp(key->data, table[i].data.key.data, sizeof(key->data)))
            return i;
    }

    return -1;
}

static int find_entry(SN_Table_entry_t* entry) {
    int ret = lookup_by_long_address(&entry->long_address);
    if(ret >= 0)
        return ret;

    ret = lookup_by_short_address(&entry->short_address);
    if(ret >= 0)
        return ret;

    ret = lookup_by_key(&entry->key);
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
    if(entry == NULL)
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
    table[ret].security = NULL;

    return SN_OK;
}

// update an existing entry. entire data structure must be valid
int SN_Table_update(SN_Table_entry_t* entry) {
    if(entry == NULL)
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
    if(entry == NULL)
        return -SN_ERR_NULL;

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0)
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;

    //mark entry as free, effectively deleting it
    entry_bitmap &= ~BIT(ret);

    //TODO: delete metadata

    return SN_OK;
}

// add security metadata TODO
// TODO: who owns the memory?
int SN_Table_add_metadata(SN_Table_entry_t* entry, SN_Security_metadata_t* security);

// lookups can be by address or by public key. first parameter is input, second and third are output
// TODO: memory ownership issues...
int SN_Table_lookup_by_address(SN_Address_t* address, SN_Table_entry_t* entry, SN_Security_metadata_t** security) {
    if(address == NULL)
        return -SN_ERR_NULL;

    int ret = -1;

    if(address->type == mac_extended_address) {
        ret = lookup_by_long_address(&address->address);
    } else if(address->type == mac_short_address) {
        ret = lookup_by_short_address(&address->address);
    } else {
        return -SN_ERR_INVALID;
    }

    if(ret < 0)
        return -SN_ERR_UNKNOWN;

    if(entry != NULL)
        memcpy(entry, &table[ret].data, sizeof(table[ret].data));

    //TODO: security / memory ownership issues

    return SN_OK;
}
int SN_Table_lookup_by_key(SN_ECC_key_t* key, SN_Table_entry_t* entry, SN_Security_metadata_t** security) {
    if(key == NULL)
        return -SN_ERR_NULL;

    int ret = lookup_by_key(key);
    if(ret < 0)
        return -SN_ERR_UNKNOWN;

    if(entry != NULL)
        *entry = table[ret].data;

    if(security != NULL)
        *security = table[ret].security;

    return SN_OK;
}

void SN_Table_clear() {
    entry_bitmap = 0;
}

