#include <sn_table.h>
#include <sn_status.h>
#include <sn_logging.h>

#include <stdlib.h>
#include <string.h>

//implemented as 32-entry table with free bitmap
#define TABLE_SIZE 32

#define BIT(x) (1UL << (x))

typedef uint32_t table_bitmap_t;

static SN_Table_entry_t table[TABLE_SIZE] = {};

static table_bitmap_t entry_bitmap = 0;

static int lookup_by_long_address(table_bitmap_t limit, mac_address_t* address) {
    if(address == NULL) {
        return -1;
    }

    mac_address_t null_address;
    memset(&null_address, 0, sizeof(null_address));
    if(!memcmp(address, &null_address, sizeof(null_address))) {
        return -1;
    }

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++)
        if((entry_bitmap & limit & BIT(i)) &&
           !memcmp(address, &table[i].long_address, sizeof(table[i].long_address))) {
            return i;
        }

    return -1;
}

static int lookup_by_short_address(table_bitmap_t limit, uint16_t address) {
    if(address == SN_NO_SHORT_ADDRESS) {
        return -1;
    }

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & limit & BIT(i)) && address == table[i].short_address) {
            return i;
        }
    }

    return -1;
}

static int lookup_by_public_key(table_bitmap_t limit, SN_Public_key_t* public_key) {
    if(public_key == NULL) {
        return -1;
    }

    SN_Public_key_t null_key = {};
    if(!memcmp(&null_key, public_key, sizeof(null_key))) {
        return -1;
    }

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & limit & BIT(i)) &&
           !memcmp(public_key->data, table[i].public_key.data, sizeof(public_key->data))) {
            return i;
        }
    }

    return -1;
}

static int find_entry(SN_Table_entry_t* entry) {
    if(entry == NULL) {
        return -1;
    }

    table_bitmap_t limit = entry->session->table_entries;
    int            ret;

    ret = lookup_by_long_address(limit, &entry->long_address);
    if(ret >= 0) {
        return ret;
    }

    ret = lookup_by_public_key(limit, &entry->public_key);
    if(ret >= 0) {
        return ret;
    }

    ret = lookup_by_short_address(limit, entry->short_address);
    if(ret >= 0) {
        return ret;
    }

    return -1;
}

static int alloc_entry() {
    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if(!(entry_bitmap & BIT(i))) {
            //found an entry, mark it in use
            entry_bitmap |= BIT(i);

            //clear its data
            memset(&table[i], 0, sizeof(table[i]));
            table[i].short_address = SN_NO_SHORT_ADDRESS;

            //we're done
            return i;
        }
    }

    return -1;
}

//insert an entry into the table. entire data structure must be valid
int SN_Table_insert(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL) {
        return -SN_ERR_NULL;
    }

    int ret;

    //see if entry already exists
    ret = find_entry(entry);
    if(ret >= 0) {
        //it does. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //consistency checks to make sure we don't pollute the table with BS entries
    mac_address_t   null_address;
    memset(&null_address, 0, sizeof(null_address));
    SN_Public_key_t null_key;
    memset(&null_key, 0, sizeof(null_key));
    if((!memcmp(&entry->long_address, &null_address, sizeof(null_address)))
       && (entry->short_address == SN_NO_SHORT_ADDRESS)
       && (!memcmp(&entry->public_key, &null_key, sizeof(null_key)))) {
        return -SN_ERR_INVALID;
    }

    //entry doesn't exist. allocate a new one
    ret = alloc_entry();
    if(ret < 0) {
        //no free entries. error
        return -SN_ERR_RESOURCES;
    }

    //fill new entry with data, and mark in this sessions 'in-use' word
    table[ret] = *entry;
    entry->session->table_entries |= BIT(ret);

    return SN_OK;
}

//update an existing entry. entire data structure must be valid
int SN_Table_update(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0) {
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //fill entry with data
    /*XXX: (consistency checks)
     * There are no consistency checks here because the
     * expected usage pattern is insert(); lookup(); update();
     */
    table[ret] = *entry;

    return SN_OK;
}

//delete an entry. at least one of: long address, short address, public_key, must be valid.
// note: you're responsible for any certificate storage you've assigned to this entry. look it up and delete it.
int SN_Table_delete(SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    int ret = find_entry(entry);
    if(ret < 0) {
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //mark entry as free, effectively deleting it
    entry_bitmap &= ~BIT(ret);
    entry->session->table_entries &= ~BIT(ret);

    return SN_OK;
}

//lookups can be by address or by public public_key. first parameter is input, second and third are output
int SN_Table_lookup_by_address(SN_Address_t* address, SN_Table_entry_t* entry) {
    if(address == NULL || entry == NULL || entry->session == NULL) {
        return -SN_ERR_NULL;
    }

    int ret;

    if(address->type == mac_extended_address) {
        ret = lookup_by_long_address(entry->session->table_entries, &address->address);
    } else {
        ret = lookup_by_short_address(entry->session->table_entries, address->address.ShortAddress);
    }
    if(ret < 0) {
        return -SN_ERR_UNKNOWN;
    }

    *entry = table[ret];

    return SN_OK;
}

int SN_Table_lookup_by_public_key(SN_Public_key_t* public_key, SN_Table_entry_t* entry) {
    if(entry == NULL || entry->session == NULL) {
        return -SN_ERR_NULL;
    }

    if(public_key == NULL) {
        public_key = &entry->public_key;
    }

    int ret = lookup_by_public_key(entry->session->table_entries, public_key);
    if(ret < 0) {
        return -SN_ERR_UNKNOWN;
    }

    *entry = table[ret];

    return SN_OK;
}

//delete all entries related to a session
void SN_Table_clear(SN_Session_t* session) {
    if(session == NULL) {
        return;
    }

    entry_bitmap &= ~session->table_entries;
    session->table_entries = 0;
}

void SN_Table_clear_all_neighbors(SN_Session_t* session) {
    if(session == NULL) {
        return;
    }

    for(table_bitmap_t i = 0; i < TABLE_SIZE; i++) {
        if((entry_bitmap & session->table_entries & BIT(i))) {
            table[i].neighbor = 0;
        }
    }
}
