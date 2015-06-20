#include "retransmission_queue.h"
#include "routing_tree.h"
#include "status.h"
#include "logging.h"
#include "config.h"
#include "util.h"
#include "packet.h"

#include "net/netstack.h"
#include "net/packetbuf.h"

#include <assert.h>
#include <string.h>

#ifndef SN_TRANSMISSION_SLOT_COUNT
#define SN_TRANSMISSION_SLOT_COUNT 8
#endif /* SN_TRANSMISSION_SLOT_COUNT */

typedef struct transmission_slot {
    union {
        struct {
            uint8_t valid     :1;
            uint8_t allocated :1;
        };
        uint8_t flags;
    };

    unsigned int retries;

    SN_Endpoint_t dst_address;

    uint8_t next_hop_size;
    linkaddr_t next_hop;

    int transmit_status;

    uint32_t counter;

    packet_t packet;
} transmission_slot_t;

static transmission_slot_t transmission_queue[SN_TRANSMISSION_SLOT_COUNT];
//TODO: reimplement this using queuebufs

int allocate_slot() {
    static int next_free_slot = 0;
    int i;
    int slot = -1;

    for(i = 0; i < SN_TRANSMISSION_SLOT_COUNT && slot < 0; i++) {
        if(next_free_slot >= SN_TRANSMISSION_SLOT_COUNT) {
            next_free_slot -= SN_TRANSMISSION_SLOT_COUNT;
        }

        if(!transmission_queue[next_free_slot].allocated) {
            slot = next_free_slot;
            memset(&transmission_queue[next_free_slot], 0, sizeof(transmission_slot_t));
            transmission_queue[next_free_slot].allocated = 1;
            transmission_queue[next_free_slot].valid = 0;
        }

        next_free_slot++;
    }

    return slot;
}

static void setup_packetbuf_for_transmission() {
    linkaddr_t src_address;

    packetbuf_set_attr(PACKETBUF_ATTR_NETWORK_ID, starfishnet_config.mib.macPANId);
    packetbuf_set_attr(PACKETBUF_ATTR_CHANNEL, starfishnet_config.pib.phyChannel);

    //figure out which address type we're using
    if(starfishnet_config.mib.macShortAddress != SN_NO_SHORT_ADDRESS) {;
        SN_InfoPrintf("sending from our short address, %#06x\n", starfishnet_config.mib.macShortAddress);
        packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
        src_address.u16 = starfishnet_config.mib.macShortAddress;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_InfoPrintf("sending from our long address, %#018"PRIx64"\n", *(uint64_t*)session->mib.macIEEEAddress.ExtendedAddress);
        packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 8);
        memcpy(src_address.u8, starfishnet_config.mib.macExtendedAddress, sizeof(starfishnet_config.mib.macExtendedAddress));
    }

    //set addresses in packetbuf
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &src_address);
}

static int determine_destination_address(SN_Table_entry_t* table_entry, transmission_slot_t* slot) {
    linkaddr_t dst_addr;
    uint8_t dst_addr_size;

    if(table_entry == NULL) {
        return -SN_ERR_NULL;
    }

    //perform routing calculations to determine destination address
    if(
        table_entry->short_address != SN_NO_SHORT_ADDRESS && //sending to a short address
        starfishnet_config.mib.macShortAddress != SN_NO_SHORT_ADDRESS && //we have a short address
        starfishnet_config.nib.enable_routing && //routing is switched on
        !(table_entry->state < SN_Associated && table_entry->child) //not an associate_reply with an address
        ) {
        //normal circumstances
        int ret = SN_Tree_route(starfishnet_config.mib.macShortAddress, table_entry->short_address, &dst_addr.u16);
        if(ret < 0) {
            return ret;
        }
        dst_addr_size = 2;
    } else if(table_entry->child || table_entry->short_address == SN_NO_SHORT_ADDRESS) {
        //it's to a long address, so no routing to do. just send direct
        if(memcmp(table_entry->long_address, null_address, 8) == 0) {
            SN_ErrPrintf("trying to send to a node without an address...\n");
            return -SN_ERR_INVALID;
        }
        dst_addr_size = 8;
        memcpy(dst_addr.u8, table_entry->long_address, 8);
    } else {
        //it's to a short address, but we can't route. just send direct
        dst_addr_size = 2;
        dst_addr.u16 = table_entry->short_address;
    }

    packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, dst_addr_size);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &dst_addr);

    if(slot != NULL) {
        memcpy(&slot->next_hop, &dst_addr, sizeof(dst_addr));
        slot->next_hop_size = dst_addr_size;
    }

    return SN_OK;
}

int SN_TX_Packetbuf(uint16_t source, uint16_t destination) {
    linkaddr_t next_hop;
    int ret;

    assert(starfishnet_config.nib.enable_routing);
    if(!starfishnet_config.nib.enable_routing) {
        return -SN_ERR_INVALID;
    }

    ret = SN_Tree_route(source, destination, &next_hop.u16);
    if(ret != SN_OK) {
        return ret;
    }

    setup_packetbuf_for_transmission();
    packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &next_hop);

    NETSTACK_LLSEC.send(NULL, NULL);

    return SN_OK;
}


static void retransmission_mac_callback(void *ptr, int status, int transmissions) {
    (void)transmissions; //shut up CC

    if(ptr != NULL) {
        transmission_slot_t* slot_data = (transmission_slot_t*)ptr;
        slot_data->transmit_status = status; //TODO: BUG!! this currently doesn't actually go anywhere
        slot_data->retries++;
    }
}

int SN_Retransmission_register(SN_Table_entry_t* table_entry, packet_t* packet, uint32_t counter) {
    transmission_slot_t* slot_data;
    int ret;

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }
    if(table_entry->short_address == SN_NO_SHORT_ADDRESS && memcmp(table_entry->long_address, null_address, 8) == 0) {
        SN_ErrPrintf("trying to send to node with unknown address\n");
        return -SN_ERR_INVALID;
    }

    //1. If appropriate, allocate a slot and fill it.
    if(PACKET_ENTRY(*packet, key_confirmation_header, request) == NULL && PACKET_ENTRY(*packet, encrypted_ack_header, request) != NULL && PACKET_ENTRY(*packet, payload_data, request) == NULL) {
        //this is a pure acknowledgement packet
        SN_InfoPrintf("just sent pure acknowledgement packet; not performing retransmissions\n");
        slot_data = NULL;
    } else
    if(PACKET_ENTRY(*packet, encryption_header, request) == NULL && PACKET_ENTRY(*packet, association_header, request) == NULL) {
        //this is a signed non-association packet; probably optimistic certificate transport
        SN_InfoPrintf("just sent unencrypted non-association packet (probably optimistic certificate transport; not performing retransmissions\n");
        slot_data = NULL;
    } else {
        int slot;
        //allocate and fill a slot
        SN_InfoPrintf("normal packet. allocating a transmission slot\n");
        slot = allocate_slot();
        slot_data = &transmission_queue[slot];

        if(slot < 0) {
            SN_ErrPrintf("no free transmission slots\n");
            return -SN_ERR_RESOURCES;
        }

        assert(slot_data->allocated);

        //fill slot with packet data

        packetbuf_copyto(slot_data->packet.data);
        detect_packet_layout(&slot_data->packet);
        slot_data->counter = counter;
        slot_data->retries = 0;
        slot_data->transmit_status = MAC_TX_DEFERRED;
        slot_data->valid = 1;
        if(table_entry->short_address == SN_NO_SHORT_ADDRESS) {
            slot_data->dst_address.type = SN_ENDPOINT_LONG_ADDRESS;
            memcpy(slot_data->dst_address.long_address, table_entry->long_address, 8);
        } else {
            slot_data->dst_address.type = SN_ENDPOINT_SHORT_ADDRESS;
            slot_data->dst_address.short_address = table_entry->short_address;
        }
    }

    //2. Address calculations and finish filling in the packetbuf
    setup_packetbuf_for_transmission();
    ret = determine_destination_address(table_entry, slot_data);
    if(ret < 0) {
        return ret;
    }

    //3. TX the packet
    NETSTACK_LLSEC.send(retransmission_mac_callback, slot_data);
    //TODO: BUG!!! I can't get the tx status from here, because there's no obvious way to wait for transmission

    return SN_OK;
}

/* convenience macro to iterate over allocated, valid, non-routing slots. provides:
 *  transmission_slot_t* slot    : a pointer to the current slot
 *  int                  slot_idx: the current slot's index
 * @param x A statement to execute on each slot.
 */
#define FOR_EACH_ACTIVE_SLOT(x)\
    /* for each transmission slot... */{int slot_idx;\
    for(slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {\
        transmission_slot_t* slot = &transmission_queue[slot_idx];\
        /* ... if the slot is allocated and valid ... */\
        if(slot->allocated && slot->valid) {\
            /* ... do work x. */\
            x;\
        }\
    }}

//convenience macro to determine whether a SN_Table_entry_t matches a SN_Endpoint_t
#define TABLE_ENTRY_MATCHES_ADDRESS(table_entry, proto_address)\
    (((proto_address).type == SN_ENDPOINT_SHORT_ADDRESS && (proto_address).short_address == (table_entry).short_address)\
     ||\
     ((proto_address).type == SN_ENDPOINT_LONG_ADDRESS && memcmp((proto_address).long_address, (table_entry).long_address, 8) == 0))

int SN_Retransmission_acknowledge_data(SN_Table_entry_t* table_entry, uint32_t counter) {
    int rv = -SN_ERR_UNKNOWN;

    SN_InfoPrintf("enter\n");

    if(table_entry == NULL) {
        SN_ErrPrintf("table_entry must be valid\n");
        return -SN_ERR_NULL;
    }

    //for each active slot...
    FOR_EACH_ACTIVE_SLOT({
        //... if it's in my session and its packet's destination is the one I'm talking about...
        if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
            //... and it's encrypted with the right counter...
            if(PACKET_ENTRY(slot->packet, encryption_header, request) != NULL && slot->counter <= counter) {
                //... acknowledge it.
                slot->allocated = 0;

                rv = SN_OK;
            }
        }
    });

    SN_InfoPrintf("exit\n");
    return rv;
}

int SN_Retransmission_acknowledge_implicit(SN_Table_entry_t* table_entry, packet_t* packet) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    if(PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL) {
        //this is either an association reply or an association finalise

        if(PACKET_ENTRY(*packet, association_header, indication) != NULL) {
            //this is an association reply; it acknowledges an association_request

            //for each active slot...
            FOR_EACH_ACTIVE_SLOT({
                //... if it's in my session and its packet's destination is the one I'm talking about...
                if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
                    //... and it's an association request...
                    if(PACKET_ENTRY(slot->packet, association_header, request) != NULL &&
                       PACKET_ENTRY(slot->packet, key_confirmation_header, request) == NULL) {

                        //... acknowledge it.
                        slot->allocated = 0;

                        SN_InfoPrintf("exit\n");
                        return SN_OK;
                    }
                }
            });
        } else {
            //this is an association finalise; it acknowledges an association_reply

            //for each active slot...
            FOR_EACH_ACTIVE_SLOT({
                //... if it's in my session and its packet's destination is the one I'm talking about...
                if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
                    //... and it's an association reply...
                    if(PACKET_ENTRY(slot->packet, association_header, request) != NULL &&
                       PACKET_ENTRY(slot->packet, key_confirmation_header, request) != NULL) {

                        //... acknowledge it.
                        slot->allocated = 0;

                        SN_InfoPrintf("exit\n");
                        return SN_OK;
                    }
                }
            });
        }
    }

    SN_ErrPrintf("acknowledgement entry not found\n");
    return -SN_ERR_UNKNOWN;
}

void SN_Retransmission_retry(bool count_towards_disconnection) {
    SN_InfoPrintf("enter\n");

    FOR_EACH_ACTIVE_SLOT({
        SN_InfoPrintf("doing retransmission processing for slot %d\n", slot_idx);

        if(count_towards_disconnection ? slot->retries < starfishnet_config.nib.tx_retry_limit : 1) {
            setup_packetbuf_for_transmission();
            packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, slot->next_hop_size);
            packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &slot->next_hop);

            packetbuf_copyfrom(slot->packet.data, PACKET_SIZE(slot->packet, request));

            NETSTACK_LLSEC.send(retransmission_mac_callback, slot);
            //TODO: BUG!!! I can't get the tx status from here, because there's no obvious way to wait for transmission
        }


        if(count_towards_disconnection) {
            slot->retries++;
            if(slot->retries >= starfishnet_config.nib.tx_retry_limit) {
                SN_Table_entry_t table_entry;

                SN_ErrPrintf("slot %d has reached its retry limit\n", slot_idx);

                if(SN_Table_lookup(&slot->dst_address, &table_entry) == SN_OK) {
                    table_entry.unavailable = 1;
                    SN_Table_update(&table_entry);
                }
            }
        } else {
            slot->retries = 1;
        }

        SN_InfoPrintf("retransmission processing for slot %d done\n", slot_idx);
    });

    SN_InfoPrintf("exit\n");
}

void SN_Retransmission_clear() {
    int i;
    for(i = 0; i < SN_TRANSMISSION_SLOT_COUNT; i++) {
        transmission_slot_t* slot = &transmission_queue[i];
        slot->allocated = 0;
    }
}
