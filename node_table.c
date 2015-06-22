#include "node_table.h"
#include "status.h"
#include "util.h"

#include <string.h>

//implemented as 32-entry table with free bitmap
#ifndef SN_TABLE_SIZE
#define SN_TABLE_SIZE 8
#endif //SN_TABLE_SIZE

#define BIT(x) (1UL << (x))

typedef uint32_t table_bitmap_t;

static SN_Table_entry_t table[SN_TABLE_SIZE];
static table_bitmap_t entry_bitmap = 0;

static int lookup_by_long_address(uint8_t* address, uint8_t stream_idx_len, uint8_t* stream_idx) {
    table_bitmap_t i;

    if(address == NULL) {
        return -1;
    }

    for(i = 0; i < SN_TABLE_SIZE; i++)
        if((entry_bitmap & BIT(i)) &&
           !memcmp(address, &table[i].long_address, sizeof(table[i].long_address)) &&
           table[i].altstream.stream_idx_length == stream_idx_len &&
            (stream_idx_len > 0 ? !memcmp(table[i].altstream.stream_idx, stream_idx, stream_idx_len) : 1)) {
            return i;
        }

    return -1;
}

static int lookup_by_short_address(uint16_t address, uint8_t stream_idx_len, uint8_t* stream_idx) {
    table_bitmap_t i;

    if(address == SN_NO_SHORT_ADDRESS) {
        return -1;
    }

    for(i = 0; i < SN_TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) && address == table[i].short_address &&
            table[i].altstream.stream_idx_length == stream_idx_len &&
            (stream_idx_len > 0 ? !memcmp(table[i].altstream.stream_idx, stream_idx, stream_idx_len) : 1)) {
            return i;
        }
    }

    return -1;
}

static int lookup_by_public_key(SN_Public_key_t* public_key) {
    table_bitmap_t i;

    if(public_key == NULL) {
        return -1;
    }

    if(!memcmp(&null_key, public_key, sizeof(null_key))) {
        return -1;
    }

    for(i = 0; i < SN_TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) &&
           !memcmp(public_key->data, table[i].public_key.data, sizeof(public_key->data))) {
            return i;
        }
    }

    return -1;
}

static int lookup_by_public_key_and_stream(SN_Public_key_t* public_key, uint8_t stream_idx_len, uint8_t* stream_idx) {
    table_bitmap_t i;

    if(public_key == NULL) {
        return -1;
    }

    if(!memcmp(&null_key, public_key, sizeof(null_key))) {
        return -1;
    }

    for(i = 0; i < SN_TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i)) &&
           !memcmp(public_key->data, table[i].public_key.data, sizeof(public_key->data)) &&
            table[i].altstream.stream_idx_length == stream_idx_len &&
            (stream_idx_len > 0 ? !memcmp(table[i].altstream.stream_idx, stream_idx, stream_idx_len) : 1)) {
            return i;
        }
    }

    return -1;
}

static int find_entry(SN_Table_entry_t* entry) {
    int ret;

    if(entry == NULL) {
        return -1;
    }

    ret = lookup_by_long_address(entry->long_address, entry->altstream.stream_idx_length, entry->altstream.stream_idx);
    if(ret >= 0) {
        return ret;
    }

    ret = lookup_by_public_key_and_stream(&entry->public_key, entry->altstream.stream_idx_length, entry->altstream.stream_idx);
    if(ret >= 0) {
        return ret;
    }

    ret = lookup_by_public_key(&entry->public_key);
    if(ret >= 0) {
        return ret;
    }

    ret = lookup_by_short_address(entry->short_address, entry->altstream.stream_idx_length, entry->altstream.stream_idx);
    if(ret >= 0) {
        return ret;
    }

    return -1;
}

static int alloc_entry() {
    table_bitmap_t i;

    for(i = 0; i < SN_TABLE_SIZE; i++) {
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
    int ret;

    if(entry == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    ret = find_entry(entry);
    if(ret >= 0) {
        //it does. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //consistency checks to make sure we don't pollute the table with BS entries
    if((!memcmp(entry->long_address, null_address, sizeof(null_address)))
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
    memcpy(&(table[ret]), entry, sizeof(*entry));

    return SN_OK;
}

//update an existing entry. entire data structure must be valid
int SN_Table_update(SN_Table_entry_t* entry) {
    int ret;

    if(entry == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    ret = find_entry(entry);
    if(ret < 0) {
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //fill entry with data
    /*XXX: (consistency checks)
     * There are no consistency checks here because the
     * expected usage pattern is insert(); lookup(); update();
     */
    memcpy(&(table[ret]), entry, sizeof(*entry));

    return SN_OK;
}

//delete an entry. at least one of: long address, short address, public_key, must be valid.
// note: you're responsible for any certificate storage you've assigned to this entry. look it up and delete it.
int SN_Table_delete(SN_Table_entry_t* entry) {
    int ret;

    if(entry == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    ret = find_entry(entry);
    if(ret < 0) {
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //mark entry as free, effectively deleting it
    entry_bitmap &= ~BIT(ret);

    return SN_OK;
}

int SN_Table_lookup(SN_Endpoint_t *endpoint, SN_Table_entry_t *entry) {
    int ret = -1;

    if (entry == NULL) {
        return -SN_ERR_NULL;
    }

    //see if entry already exists
    if (endpoint == NULL) {
        ret = find_entry(entry);
    } else {
        switch(endpoint->type) {
            case SN_ENDPOINT_LONG_ADDRESS:
                ret = lookup_by_long_address(endpoint->long_address, endpoint->altstream == NULL ? (uint8_t)0 : endpoint->altstream->stream_idx_length, endpoint->altstream == NULL ? NULL : endpoint->altstream->stream_idx);
                break;

            case SN_ENDPOINT_SHORT_ADDRESS:
                ret = lookup_by_short_address(endpoint->short_address, endpoint->altstream == NULL ? (uint8_t)0 : endpoint->altstream->stream_idx_length, endpoint->altstream == NULL ? NULL : endpoint->altstream->stream_idx);
                break;

            case SN_ENDPOINT_PUBLIC_KEY:
                if(endpoint->altstream == NULL || endpoint->altstream->stream_idx_length == 0) {
                    ret = lookup_by_public_key(&endpoint->public_key);
                } else {
                    ret = lookup_by_public_key_and_stream(&endpoint->public_key, endpoint->altstream->stream_idx_length, endpoint->altstream->stream_idx);
                }
        }
    }

    if (ret < 0) {
        //it doesn't. return an error
        return -SN_ERR_UNEXPECTED;
    }

    //fill entry with data
    memcpy(entry, &(table[ret]), sizeof(*entry));

    return SN_OK;
}

//delete all entries related to a session
void SN_Table_clear() {
    entry_bitmap = 0;
}

void SN_Table_clear_all_neighbors() {
    table_bitmap_t  i;
    for(i = 0; i < SN_TABLE_SIZE; i++) {
        if((entry_bitmap & BIT(i))) {
            table[i].neighbor = 0;
        }
    }
}
