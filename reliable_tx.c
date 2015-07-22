#include "reliable_tx.h"
#include "routing_tree.h"
#include "status.h"
#include "logging.h"
#include "config.h"
#include "util.h"
#include "packet.h"
#include "raw_tx.h"

#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/linkaddr.h"
#include "sys/etimer.h"

#include <string.h>
#include <assert.h>

#ifndef SN_TRANSMISSION_SLOT_COUNT
#define SN_TRANSMISSION_SLOT_COUNT QUEUEBUF_NUM
#endif /* SN_TRANSMISSION_SLOT_COUNT */

typedef struct transmission_slot {
    union {
        struct {
            uint8_t valid     :1;
            uint8_t allocated :1;
        };
        uint8_t flags;
    };

    SN_Endpoint_t dst_address;
    uint32_t counter;
    packet_t packet;
    struct queuebuf* queuebuf;

    uint8_t retries;
    int8_t  transmit_status;
} transmission_slot_t;

static transmission_slot_t transmission_queue[SN_TRANSMISSION_SLOT_COUNT];

int8_t allocate_slot() {
    static int8_t next_free_slot = 0;
    int8_t i;
    int8_t slot = -1;

    for(i = 0; i < SN_TRANSMISSION_SLOT_COUNT && slot < 0; i++) {
        if(next_free_slot >= SN_TRANSMISSION_SLOT_COUNT) {
            next_free_slot -= SN_TRANSMISSION_SLOT_COUNT;
        }

        if(!transmission_queue[next_free_slot].allocated) {
            slot = next_free_slot;
            transmission_queue[next_free_slot].allocated = 1;
            transmission_queue[next_free_slot].valid = 0;
        }

        next_free_slot++;
    }

    return slot;
}

void free_slot(uint8_t slot) {
    transmission_queue[slot].allocated = 0;
    queuebuf_free(transmission_queue[slot].queuebuf);
}

static int8_t setup_packetbuf_for_transmission(SN_Table_entry_t* table_entry) {
    linkaddr_t dst_addr;
    linkaddr_t src_addr;

    if(table_entry == NULL) {
        return -SN_ERR_NULL;
    }

    //figure out which address type we're using
    if(starfishnet_config.short_address != FRAME802154_INVALIDADDR) {;
        SN_InfoPrintf("sending from our short address, 0x%04x\n", starfishnet_config.short_address);
        packetbuf_set_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE, 2);
        STORE_SHORT_ADDRESS(src_addr.u8, starfishnet_config.short_address);
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_InfoPrintf("sending from our long address, 0x%08"PRIx32"%08"PRIx32"\n", *(uint32_t*)linkaddr_node_addr.u8, *(((uint32_t*)linkaddr_node_addr.u8) + 1));
        packetbuf_set_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE, 8);
        memcpy(src_addr.u8, linkaddr_node_addr.u8, 8);
    }

    //perform routing calculations to determine destination address
    if(
        table_entry->short_address != FRAME802154_INVALIDADDR && //sending to a short address
        starfishnet_config.short_address != FRAME802154_INVALIDADDR && //we have a short address
        starfishnet_config.enable_routing && //routing is switched on
        !(table_entry->state < SN_Associated && table_entry->child) //not an associate_reply with an address
        ) {
        //normal circumstances
        uint16_t dst_addr_short;
        int8_t ret = SN_Tree_route(starfishnet_config.short_address, table_entry->short_address, &dst_addr_short);
        if(ret < 0) {
            return ret;
        }
        STORE_SHORT_ADDRESS(dst_addr.u8, dst_addr_short);
        packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
    } else if(table_entry->child || table_entry->short_address == FRAME802154_INVALIDADDR) {
        //it's to a long address, so no routing to do. just send direct
        if(table_entry->long_address == NULL || memcmp(table_entry->long_address, null_address, 8) == 0) {
            SN_ErrPrintf("trying to send to a node without an address...\n");
            return -SN_ERR_INVALID;
        }
        packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 8);
        memcpy(dst_addr.u8, table_entry->long_address, 8);
    } else {
        //it's to a short address, but we can't route. just send direct
        packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
        STORE_SHORT_ADDRESS(dst_addr.u8, table_entry->short_address);
    }

    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &src_addr);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &dst_addr);

    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
    packetbuf_set_attr(PACKETBUF_ATTR_NETWORK_ID, starfishnet_config.pan_id);

    return SN_OK;
}

static void retransmission_mac_callback(void *ptr, int status, int transmissions) {
    (void)transmissions; //shut up CC

    if(ptr != NULL) {
        transmission_slot_t* slot_data = (transmission_slot_t*)ptr;
        slot_data->transmit_status = status; // TODO: BUG!! this currently doesn't actually go anywhere
        slot_data->retries++;
    }
}

int8_t SN_Retransmission_send(packet_t *packet, SN_Table_entry_t *table_entry) {
    transmission_slot_t* slot_data;
    int8_t ret;

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }
    if(table_entry->short_address == FRAME802154_INVALIDADDR && (table_entry->long_address == NULL || memcmp(table_entry->long_address, null_address, 8) == 0)) {
        SN_ErrPrintf("trying to send to node with unknown address\n");
        return -SN_ERR_INVALID;
    }

    //1. If appropriate, allocate a slot and fill it.
    if(!packet->layout.present.encryption_header && !(packet->layout.present.association_header && !PACKET_ENTRY(*packet, association_header)->dissociate)) {
        //this is a signed non-association packet; probably optimistic certificate transport, or a dissociation
        SN_InfoPrintf("just sent unencrypted non-association packet (probably optimistic certificate transport; not performing retransmissions\n");
        slot_data = NULL;
    } else {
        int8_t slot;
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

        slot_data->counter = table_entry->packet_tx_counter - 1;
        slot_data->retries = 0;
        slot_data->transmit_status = MAC_TX_DEFERRED;
        if(table_entry->short_address == FRAME802154_INVALIDADDR) {
            if(table_entry->long_address == NULL) {
                return -SN_ERR_INVALID;
            }
            slot_data->dst_address.type = SN_ENDPOINT_LONG_ADDRESS;
            memcpy(slot_data->dst_address.long_address, table_entry->long_address, 8);
        } else {
            slot_data->dst_address.type = SN_ENDPOINT_SHORT_ADDRESS;
            slot_data->dst_address.short_address = table_entry->short_address;
        }
        memcpy(&slot_data->packet, packet, sizeof(slot_data->packet));
    }

    //2. Address calculations, finish filling in the packetbuf, and allocate the queuebuf
    ret = setup_packetbuf_for_transmission(table_entry);
    packetbuf_set_datalen(PACKET_SIZE(*packet));
    if(ret < 0) {
        return ret;
    }
    if(slot_data != NULL) {
        slot_data->queuebuf = queuebuf_new_from_packetbuf();
        if(slot_data->queuebuf == NULL) {
            SN_ErrPrintf("no free queuebuf entries\n");
            slot_data->allocated = 0;
            return -SN_ERR_RESOURCES;
        }
        slot_data->packet.data = queuebuf_dataptr(slot_data->queuebuf); //XXX: assumes queuebuf doesn't use swapping
        slot_data->valid = 1;
    }

    //3. TX the packet
    NETSTACK_LLSEC.send(retransmission_mac_callback, slot_data);
    //TODO: BUG!!! I can't get the tx status from here, because there's no obvious way to wait for transmission

    return SN_OK;
}

/* convenience macro to iterate over allocated, valid, non-routing slots. provides:
 *  transmission_slot_t* slot    : a pointer to the current slot
 *  int8_t               slot_idx: the current slot's index
 * @param x A statement to execute on each slot.
 */
#define FOR_EACH_ACTIVE_SLOT(var, x)\
    /* for each transmission slot... */{transmission_slot_t* var;\
    for(var = transmission_queue; (var - transmission_queue) < SN_TRANSMISSION_SLOT_COUNT; var++) {\
        /* ... if the slot is allocated and valid ... */\
        if(var->allocated && var->valid) {\
            /* ... do work x. */\
            x;\
        }\
    }}

//convenience macro to determine whether a SN_Table_entry_t matches a SN_Endpoint_t
#define TABLE_ENTRY_MATCHES_ADDRESS(table_entry, proto_address)\
    (((proto_address).type == SN_ENDPOINT_SHORT_ADDRESS && (proto_address).short_address == (table_entry).short_address)\
     ||\
     ((proto_address).type == SN_ENDPOINT_LONG_ADDRESS && memcmp((proto_address).long_address, (table_entry).long_address, 8) == 0))

int8_t SN_Retransmission_acknowledge_data(SN_Table_entry_t *table_entry, uint32_t counter) {
    int8_t rv = -SN_ERR_UNKNOWN;

    SN_InfoPrintf("enter\n");

    if(table_entry == NULL) {
        SN_ErrPrintf("table_entry must be valid\n");
        return -SN_ERR_NULL;
    }

    //for each active slot...
    FOR_EACH_ACTIVE_SLOT(slot, {
        //... if it's in my session and its packet's destination is the one I'm talking about...
        if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
            //... and it's encrypted with the right counter...
            if(slot->packet.layout.present.encryption_header && slot->counter <= counter) {
                //... acknowledge it.
                free_slot((uint8_t)(slot - transmission_queue));

                rv = SN_OK;
            }
        }
    });

    SN_InfoPrintf("exit\n");
    return rv;
}

int8_t SN_Retransmission_acknowledge_implicit(packet_t *packet, SN_Table_entry_t *table_entry) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    if(packet->layout.present.key_confirmation_header) {
        //this is either an association reply or an association finalise

        if(packet->layout.present.association_header) {
            //this is an association reply; it acknowledges an association_request

            //for each active slot...
            FOR_EACH_ACTIVE_SLOT(slot, {
                //... if it's in my session and its packet's destination is the one I'm talking about...
                if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
                    //... and it's an association request...
                    if(slot->packet.layout.present.association_header && !slot->packet.layout.present.key_confirmation_header) {

                        //... acknowledge it.
                        free_slot((uint8_t)(slot - transmission_queue));

                        SN_InfoPrintf("exit\n");
                        return SN_OK;
                    }
                }
            });
        } else {
            //this is an association finalise; it acknowledges an association_reply

            //for each active slot...
            FOR_EACH_ACTIVE_SLOT(slot, {
                //... if it's in my session and its packet's destination is the one I'm talking about...
                if(TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
                    //... and it's an association reply...
                    if(slot->packet.layout.present.association_header && slot->packet.layout.present.key_confirmation_header) {

                        //... acknowledge it.
                        free_slot((uint8_t)(slot - transmission_queue));

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

static SN_Table_entry_t retx_temp_table_entry;
void SN_Retransmission_retry(uint8_t count_towards_disconnection) {

    SN_InfoPrintf("enter\n");

    FOR_EACH_ACTIVE_SLOT(slot, {
        SN_InfoPrintf("doing retransmission processing for slot %d\n", (uint8_t)(slot - transmission_queue));

        //look up the destination's entry in the node table
        if(slot->dst_address.type == SN_ENDPOINT_SHORT_ADDRESS) {
            SN_DebugPrintf("slot %d is for short address 0x%04x\n", (uint8_t)(slot - transmission_queue), slot->dst_address.short_address);
        } else if (slot->dst_address.type == SN_ENDPOINT_LONG_ADDRESS) {
            SN_DebugPrintf("slot %d is for long address 0x%08llx%08llx\n", (uint8_t)(slot - transmission_queue), *(uint32_t*)slot->dst_address.long_address, *(uint32_t*)(slot->dst_address.long_address + 4));
        } else {
            SN_DebugPrintf("slot %d has weird address type %d\n", (uint8_t)(slot - transmission_queue), slot->dst_address.type);
        }
        if(SN_Table_lookup(&slot->dst_address, &retx_temp_table_entry) != SN_OK) {
            SN_WarnPrintf("trying to retransmit to an unknown partner. dropping\n");
            free_slot((uint8_t)(slot - transmission_queue));
            continue;
        }

        //if we're not ignoring the disconnection counter, and we still have retries left, tx the packet
        if(count_towards_disconnection ? slot->retries < starfishnet_config.tx_retry_limit : 1) {
            queuebuf_to_packetbuf(slot->queuebuf);
            if(setup_packetbuf_for_transmission(&retx_temp_table_entry) != SN_OK) {
                retx_temp_table_entry.unavailable = 1;
            } else {
                NETSTACK_LLSEC.send(retransmission_mac_callback, slot);
                //TODO: BUG!!! I can't get the tx status from here, because there's no obvious way to wait for transmission
            }
        }

        //update the disconnection counter, and mark as disconnected if it's been reached
        if(count_towards_disconnection) {
            slot->retries++;
            if(slot->retries >= starfishnet_config.tx_retry_limit) {
                SN_ErrPrintf("slot %d has reached its retry limit\n", (uint8_t)(slot - transmission_queue));

                retx_temp_table_entry.unavailable = 1;
            }
        } else {
            slot->retries = 1;
        }

        SN_Table_update(&retx_temp_table_entry);

        SN_InfoPrintf("retransmission processing for slot %d done\n", (uint8_t)(slot - transmission_queue));
    });

    SN_InfoPrintf("exit\n");
}

void SN_Retransmission_clear() {
    transmission_slot_t* slot;
    for(slot = transmission_queue; slot - transmission_queue < SN_TRANSMISSION_SLOT_COUNT; slot++) {
        if(slot->allocated) {
            free_slot((uint8_t)(slot - transmission_queue));
        }
    }
}

PROCESS(starfishnet_retransmission_process, "StarfishNet retransmission process");
PROCESS_THREAD(starfishnet_retransmission_process, ev, data)
{
    static struct etimer timer = {
        .p = &starfishnet_retransmission_process,
        .next = NULL,
    };
    static uint8_t timeouts = 0;

    PROCESS_BEGIN();

    (void)data; //shut up GCC

    while(1) {
        etimer_set(&timer, starfishnet_config.tx_retry_timeout / 1000 * CLOCK_CONF_SECOND );

        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

        timeouts++;

        SN_Retransmission_retry(1);

        if(timeouts == starfishnet_config.tx_ack_timeout) {
            SN_InfoPrintf("starting acknowledgement transmission...\n");
            timeouts = 0;
            memset(&retx_temp_table_entry, 0, sizeof(retx_temp_table_entry));
            while(SN_Table_find_unacknowledged(&retx_temp_table_entry) == SN_OK) {
                SN_InfoPrintf("sending acknowledgements to 0x%04x\n", retx_temp_table_entry.short_address);
                SN_Send_acknowledgements(&retx_temp_table_entry);
            }
        }
    }

    PROCESS_END();
}

