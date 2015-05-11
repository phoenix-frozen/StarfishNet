#include "sn_delayed_tx.h"
#include "sn_queued_rx.h"
#include "mac_util.h"
#include "sn_routing_tree.h"

#include <sn_status.h>
#include <sn_logging.h>

#include <assert.h>
#include <string.h>
#include <inttypes.h>

#ifndef SN_TRANSMISSION_SLOT_COUNT
#define SN_TRANSMISSION_SLOT_COUNT 8
#endif /* SN_TRANSMISSION_SLOT_COUNT */

#if SN_TRANSMISSION_SLOT_COUNT > 255
#error "Transmission queue may be at most 255 slots in length."
#endif /* SN_TRANSMISSION_SLOT_COUNT > 255 */

typedef struct transmission_slot {
    union {
        struct {
            uint8_t valid     :1;
            uint8_t allocated :1;
            uint8_t routing   :1;
        };
        uint8_t flags;
    };

    unsigned int retries;

    SN_Session_t* session;

    SN_Address_t dst_address;
    uint16_t src_address; //only valid for routing packets

    uint32_t counter;

    packet_t packet;
} transmission_slot_t;

static transmission_slot_t transmission_queue[SN_TRANSMISSION_SLOT_COUNT];


//send out a datagram
//packet should only have msduLength and msdu filled; everything else is my problem
static int do_packet_transmission(int slot) {
    SN_InfoPrintf("enter\n");

    transmission_slot_t* slot_data = &transmission_queue[slot];

    if(slot >= 255 || slot < 0 || !slot_data->allocated || !slot_data->valid) {
        SN_ErrPrintf("cannot use slot %d\n", slot);
        return -SN_ERR_INVALID;
    }

    SN_Session_t* session = slot_data->session;
    mac_primitive_t* packet = &slot_data->packet.contents;

    int ret;

    uint8_t max_payload_size = aMaxMACPayloadSize - 2;
    /* aMaxMACPayloadSize is for a packet with a short destination address, and no source addressing
     * information. we always send a source address, which is at least 2 byte long
     */

    packet->type                         = mac_mcps_data_request;
    packet->MCPS_DATA_request.SrcPANId   = session->mib.macPANId;
    //packet->MCPS_DATA_request.SrcAddr     is filled below
    //packet->MCPS_DATA_request.SrcAddrMode is filled below
    packet->MCPS_DATA_request.DstPANId   = session->mib.macPANId;
    //packet->MCPS_DATA_request.DstAddr     is filled below
    //packet->MCPS_DATA_request.DstAddrMode is filled below
    packet->MCPS_DATA_request.msduHandle = (uint8_t)(slot + 1);
    packet->MCPS_DATA_request.TxOptions  = 0;
    //packet->MCPS_DATA_request.msduLength  is filled by caller
    //packet->MCPS_DATA_request.msdu        is filled by caller
    SN_InfoPrintf("attempting to transmit a %d-byte packet\n", packet->MCPS_DATA_request.msduLength);

    //SrcAddr and SrcAddrMode
    if(session->mib.macShortAddress != SN_NO_SHORT_ADDRESS) {;
        SN_InfoPrintf("sending from our short address, %#06x\n", session->mib.macShortAddress);
        packet->MCPS_DATA_request.SrcAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.SrcAddr.ShortAddress = session->mib.macShortAddress;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_InfoPrintf("sending from our long address, %#018"PRIx64"\n", *(uint64_t*)session->mib.macIEEEAddress.ExtendedAddress);
        packet->MCPS_DATA_request.SrcAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.SrcAddr     = session->mib.macIEEEAddress;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    }

    //DstAddr
    if(slot_data->routing) {
        SN_InfoPrintf("this is a routing slot\n");
        assert(slot_data->dst_address.type == mac_short_address);
        assert(slot_data->dst_address.address.ShortAddress != SN_NO_SHORT_ADDRESS);
        assert(slot_data->src_address != SN_NO_SHORT_ADDRESS);
        //this is a routing slot
        packet->MCPS_DATA_request.DstAddrMode = mac_short_address;
        ret = SN_Tree_route(session, slot_data->src_address, slot_data->dst_address.address.ShortAddress, &packet->MCPS_DATA_request.DstAddr.ShortAddress);
        if(ret != SN_OK) {
            SN_ErrPrintf("routing failed with %d\n", -ret);
            return ret;
        } else {
            SN_InfoPrintf("routing through short address %#06x\n", packet->MCPS_DATA_request.DstAddr.ShortAddress);
        }
    } else {
        //non-routing slot
        SN_Table_entry_t table_entry = {
            .session = session,
            .stream_idx_length = slot_data->dst_address.stream_idx_length,
        };
        memcpy(table_entry.stream_idx, slot_data->dst_address.stream_idx, slot_data->dst_address.stream_idx_length);
        if(slot_data->dst_address.type == mac_extended_address) {
            table_entry.short_address = SN_NO_SHORT_ADDRESS;
            table_entry.long_address = slot_data->dst_address.address;
        } else {
            table_entry.short_address = slot_data->dst_address.address.ShortAddress;
        }

        ret = SN_Table_lookup_by_address(&table_entry, slot_data->dst_address.type);
        if(ret != SN_OK) {
            SN_WarnPrintf("transmitting packet to new node (lookup error %d)\n", -ret);
        } else if(table_entry.unavailable) {
            SN_ErrPrintf("lost contact with remote node; transmissions will resume when we find it again\n");
            return -SN_ERR_DISCONNECTED;
        }

        //sent to short address if and only if a) we know their short address, and b) we're not sending an association reply with an address
        if((PACKET_ENTRY(slot_data->packet, association_header, request) != NULL &&
            PACKET_ENTRY(slot_data->packet, key_confirmation_header, request) != NULL &&
            PACKET_ENTRY(slot_data->packet, association_header, request)->child
           ) || table_entry.short_address == SN_NO_SHORT_ADDRESS) {
            //XXX: this is the most disgusting way to print a MAC address ever invented by man
            SN_InfoPrintf("sending to long address %#018"PRIx64"\n",
                *(uint64_t*)table_entry.long_address.ExtendedAddress);
            packet->MCPS_DATA_request.DstAddrMode = mac_extended_address;
            packet->MCPS_DATA_request.DstAddr     = table_entry.long_address;
            max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
        } else {
            SN_InfoPrintf("sending to short address %#06x\n", table_entry.short_address);
            packet->MCPS_DATA_request.DstAddrMode = mac_short_address;
            if(table_entry.neighbor || session->mib.macShortAddress == SN_NO_SHORT_ADDRESS) {
                //if the peer is a neighbor (or we're joining the network), send directly
                SN_InfoPrintf("peer is a neighbor. transmitting directly\n");
                packet->MCPS_DATA_request.DstAddr.ShortAddress = table_entry.short_address;
            } else {
                //peer isn't a neighbor.
                if(session->nib.enable_routing) {
                    //if we're a router, then route.
                    ret = SN_Tree_route(session, session->mib.macShortAddress, table_entry.short_address, &packet->MCPS_DATA_request.DstAddr.ShortAddress);
                    if(ret != SN_OK) {
                        SN_ErrPrintf("routing failed with %d\n", -ret);
                        return ret;
                    } else {
                        SN_InfoPrintf("routing through short address %#06x\n", packet->MCPS_DATA_request.DstAddr.ShortAddress);
                    }
                } else {
                    //we're not a router. just send to our parent.
                    packet->MCPS_DATA_request.DstAddr.ShortAddress = session->nib.parent_address;
                    SN_InfoPrintf("peer is not a neighbor. routing though parent (%#06x)\n", packet->MCPS_DATA_request.DstAddr.ShortAddress);
                }
            }
        }
    }

    if(packet->MCPS_DATA_request.msduLength > max_payload_size) {
        SN_ErrPrintf("cannot transmit payload of size %d (max is %d)\n", packet->MCPS_DATA_request.msduLength, max_payload_size);
        return -SN_ERR_INVALID;
    }

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet->MCPS_DATA_request.msduLength; i += 8) {
        SN_DebugPrintf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
            packet->MCPS_DATA_request.msdu[i],
            packet->MCPS_DATA_request.msdu[i + 1],
            packet->MCPS_DATA_request.msdu[i + 2],
            packet->MCPS_DATA_request.msdu[i + 3],
            packet->MCPS_DATA_request.msdu[i + 4],
            packet->MCPS_DATA_request.msdu[i + 5],
            packet->MCPS_DATA_request.msdu[i + 6],
            packet->MCPS_DATA_request.msdu[i + 7]
        );
    }
    SN_DebugPrintf("end packet data\n");

    SN_InfoPrintf("beginning packet transmission with handle %d...\n", packet->MCPS_DATA_request.msduHandle);
    ret = mac_transmit(session->mac_session, packet);
    SN_InfoPrintf("packet transmission returned %d\n", ret);

    if(ret != 11 + (packet->MCPS_DATA_request.SrcAddrMode == mac_extended_address ? 8 : 2) +
              (packet->MCPS_DATA_request.DstAddrMode == mac_extended_address ? 8 : 2) +
              packet->MCPS_DATA_request.msduLength) { //27 if both address formats are extended
        SN_ErrPrintf("packet transmission failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    SN_InfoPrintf("waiting for transmission status report from radio...\n");
    mac_primitive_t status_report;
    while(1) {
        MAC_CALL(mac_receive, session->mac_session, &status_report);

        if(status_report.type == mac_mcps_data_confirm) {
            if(status_report.MCPS_DATA_confirm.msduHandle == (uint8_t)(slot + 1)) {
                SN_InfoPrintf("got transmission report\n");
                if(status_report.MCPS_DATA_confirm.status == mac_success) {
                    ret = SN_OK;
                } else {
                    ret = -SN_ERR_TXRXFAIL;
                }
                break;
            } else {
                SN_WarnPrintf("dropping MCPS-DATA.confirm for invalid handle %d\n", status_report.MCPS_DATA_confirm.msduHandle);
            }
        } else {
            /* we don't consider MLME-COMM-STATUS.indication, because it's only generated as a result of
             * either transmission via a .response primitive, or reception of an invalid frame
             */
            SN_WarnPrintf("got irrelevant primitive; banishing to the queue\n");
            SN_Enqueue(session, &status_report); //implicitly drops irrelevant primitives
        }
    }
    if(ret != SN_OK) {
        SN_ErrPrintf("received transmission status report. transmission failed with %d\n", status_report.MCPS_DATA_confirm.status);
    } else {
        SN_InfoPrintf("received transmission status report. transmission succeeded\n");
    }

    SN_InfoPrintf("exit\n");
    return ret;
}

int allocate_slot() {
    static int next_free_slot = 0;

    int slot = -1;

    for(int i = 0; i < SN_TRANSMISSION_SLOT_COUNT && slot < 0; i++) {
        if(next_free_slot >= SN_TRANSMISSION_SLOT_COUNT) {
            next_free_slot -= SN_TRANSMISSION_SLOT_COUNT;
        }

        if(!transmission_queue[next_free_slot].allocated) {
            slot = next_free_slot;
            memset(&transmission_queue[next_free_slot], 0, sizeof(transmission_slot_t));
            transmission_queue[next_free_slot].allocated = 1;
            transmission_queue[next_free_slot].src_address = SN_NO_SHORT_ADDRESS;
        }

        next_free_slot++;
    }

    return slot;
}

int SN_Delayed_forward(SN_Session_t* session, uint16_t source, uint16_t destination, packet_t* packet) {
    if(session == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    assert(session->nib.enable_routing);

    int slot = allocate_slot();

    if(slot < 0) {
        SN_ErrPrintf("no free transmission slots\n");
        return -SN_ERR_RESOURCES;
    }

    transmission_slot_t* slot_data = &transmission_queue[slot];

    assert(slot_data->allocated);

    slot_data->session     = session;
    slot_data->routing = true;
    slot_data->dst_address.type = mac_short_address;
    slot_data->dst_address.address.ShortAddress = destination;
    slot_data->src_address = source;
    slot_data->packet      = *packet;
    slot_data->valid       = 1;

    /* XXX: ordinarily, we'd need to translate from an indication to a request,
     *      but the 802.15.4 code I'm using puts all the relevant stuff in the same place,
     *      so I don't have to.
     *      Make the compiler guarantee this.
     */
    _Static_assert(slot_data->packet.contents.MCPS_DATA_request.msdu == slot_data->packet.contents.MCPS_DATA_indication.msdu, "Misaligned 802.15.4 primitives!");

    int ret = do_packet_transmission(slot);

    slot_data->allocated = 0;

    if(ret != SN_OK) {
        SN_ErrPrintf("packet transmission failed with %d\n", -ret);
    }

    return ret;
}

int SN_Delayed_transmit(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet, uint32_t counter) {
    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    int slot = allocate_slot();

    if(slot < 0) {
        SN_ErrPrintf("no free transmission slots\n");
        return -SN_ERR_RESOURCES;
    }

    transmission_slot_t* slot_data = &transmission_queue[slot];

    assert(slot_data->allocated);

    slot_data->session     = session;
    slot_data->routing     = false;
    if(table_entry->short_address == SN_NO_SHORT_ADDRESS) {
        slot_data->dst_address.type = mac_extended_address;
        slot_data->dst_address.address = table_entry->long_address;
    } else {
        slot_data->dst_address.type = mac_short_address;
        slot_data->dst_address.address.ShortAddress = table_entry->short_address;
    }
    slot_data->packet      = *packet;
    slot_data->valid       = 1;
    slot_data->counter     = counter;
    slot_data->retries     = 0;

    int ret = do_packet_transmission(slot);

    if(ret != SN_OK) {
        SN_ErrPrintf("packet transmission failed with %d\n", -ret);
        slot_data->allocated = 0;
        return ret;
    }

    if(PACKET_ENTRY(*packet, key_confirmation_header, request) == NULL && PACKET_ENTRY(*packet, encrypted_ack_header, request) != NULL && PACKET_ENTRY(*packet, payload_data, request) == NULL) {
        //this is a pure acknowledgement packet
        SN_InfoPrintf("just sent pure acknowledgement packet; not performing retransmissions\n");
        slot_data->allocated = 0;
    }

    if(PACKET_ENTRY(*packet, encryption_header, request) == NULL && PACKET_ENTRY(*packet, association_header, request) == NULL) {
        //this is a signed non-association packet; probably optimistic certificate transport
        SN_InfoPrintf("just sent unencrypted non-association packet (probably optimistic certificate transport; not performing retransmissions\n");
        slot_data->allocated = 0;
    }

    return SN_OK;
}

/* convenience macro to iterate over allocated, valid, non-routing slots. provides:
 *  transmission_slot_t* slot    : a pointer to the current slot
 *  int                  slot_idx: the current slot's index
 * @param x A statement to execute on each slot.
 */
#define FOR_EACH_ACTIVE_SLOT(x)\
    /* for each transmission slot... */\
    for(int slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {\
        transmission_slot_t* slot = &transmission_queue[slot_idx];\
        /* ... if the slot is allocated, valid, not a routing slot, and in my session... */\
        if(slot->allocated && slot->valid && !slot->routing) {\
            /* ... do work x. */\
            x;\
        }\
    }

//convenience macro to determine whether a SN_Table_entry_t matches a SN_Address_t
#define TABLE_ENTRY_MATCHES_ADDRESS(table_entry, proto_address)\
    (((proto_address).type == mac_short_address && (proto_address).address.ShortAddress == (table_entry).short_address)\
     ||\
     ((proto_address).type == mac_extended_address && memcmp(&(proto_address).address, &(table_entry).long_address, sizeof(mac_address_t)) == 0))

int SN_Delayed_acknowledge_encrypted(SN_Table_entry_t* table_entry, uint32_t counter) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL) {
        SN_ErrPrintf("table_entry must be valid\n");
        return -SN_ERR_NULL;
    }

    int rv = -SN_ERR_UNKNOWN;

    //for each active slot...
    FOR_EACH_ACTIVE_SLOT({
        //... if it's in my session and its packet's destination is the one I'm talking about...
        if(table_entry->session == slot->session && TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
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

int SN_Delayed_acknowledge_special(SN_Table_entry_t* table_entry, packet_t* packet) {
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
                if(table_entry->session == slot->session && TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
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
                if(table_entry->session == slot->session && TABLE_ENTRY_MATCHES_ADDRESS(*table_entry, slot->dst_address)) {
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

void SN_Delayed_tick(bool count_towards_disconnection) {
    SN_InfoPrintf("enter\n");

    FOR_EACH_ACTIVE_SLOT({
        SN_InfoPrintf("doing retransmission processing for slot %d\n", slot_idx);

        if(count_towards_disconnection ? slot->retries < slot->session->nib.tx_retry_limit : 1) {
            do_packet_transmission(slot_idx);
        }

        if(count_towards_disconnection) {
            slot->retries++;
            if(slot->retries >= slot->session->nib.tx_retry_limit) {
                SN_ErrPrintf("slot %d has reached its retry limit\n", slot_idx);

                SN_Table_entry_t table_entry = {};
                table_entry.session = slot->session;
                table_entry.stream_idx_length = slot->dst_address.stream_idx_length;
                memcpy(table_entry.stream_idx, slot->dst_address.stream_idx, slot->dst_address.stream_idx_length);
                if(slot->dst_address.type == mac_extended_address) {
                    table_entry.short_address = SN_NO_SHORT_ADDRESS;
                    table_entry.long_address = slot->dst_address.address;
                } else {
                    table_entry.short_address = slot->dst_address.address.ShortAddress;
                }

                if(SN_Table_lookup_by_address(&table_entry, slot->dst_address.type) == SN_OK) {
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

void SN_Delayed_clear(SN_Session_t* session) {
    if(session == NULL) {
        SN_ErrPrintf("session must be valid\n");
        return;
    }

    for(int i = 0; i < SN_TRANSMISSION_SLOT_COUNT; i++) {
        transmission_slot_t* slot = &transmission_queue[i];

        if(slot->allocated && slot->valid) {
            if(slot->session == session) {
                slot->valid = 0;
                slot->allocated = 0;
            }
        }
    }
}