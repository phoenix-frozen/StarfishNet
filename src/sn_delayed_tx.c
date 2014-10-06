#include "sn_delayed_tx.h"

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
        };
        uint8_t flags;
    };

    unsigned int retries;
    unsigned int ticks_remaining;

    SN_Session_t* session;

    SN_Public_key_t destination;

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
    SN_Table_entry_t table_entry = {
        .session = session,
    };

    int ret = SN_Table_lookup_by_public_key(&slot_data->destination, &table_entry, NULL);
    if(ret != SN_OK) {
        SN_ErrPrintf("cannot transmit to node with unknown address (lookup error %d)\n", -ret);
        return ret;
    }

    //TODO: rekeying: encryption here as well?

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
        SN_DebugPrintf("sending from our short address, %#06x\n", session->mib.macShortAddress);
        packet->MCPS_DATA_request.SrcAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.SrcAddr.ShortAddress = session->mib.macShortAddress;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending from our long address, %#018"PRIx64"\n", *(uint64_t*)session->mib.macIEEEAddress.ExtendedAddress);
        packet->MCPS_DATA_request.SrcAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.SrcAddr     = session->mib.macIEEEAddress;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    }

    //DstAddr
    //TODO: routing logic goes here
    if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
        SN_DebugPrintf("sending to short address %#06x\n", table_entry->short_address);
        packet->MCPS_DATA_request.DstAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.DstAddr.ShortAddress = table_entry.short_address;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending to long address %#018"PRIx64"\n", *(uint64_t*)table_entry->long_address.ExtendedAddress);
        packet->MCPS_DATA_request.DstAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.DstAddr     = table_entry.long_address;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
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

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = mac_transmit(session->mac_session, packet);
    SN_InfoPrintf("packet transmission returned %d\n", ret);

    if(ret != 11 + (packet->MCPS_DATA_request.SrcAddrMode == mac_extended_address ? 8 : 2) +
              (packet->MCPS_DATA_request.DstAddrMode == mac_extended_address ? 8 : 2) +
              packet->MCPS_DATA_request.msduLength) { //27 if both address formats are extended
        SN_ErrPrintf("packet transmission failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    //TODO: queueing behaviour: queue MCPS_DATA.indication while waiting for MCPS_DATA.confirm

    SN_InfoPrintf("waiting for transmission status report from radio...\n");
    //TODO: actual transmission status handling, including interpreting both MCPS_DATA.confirm and MLME_COMM_STATUS.indication
    uint8_t tx_confirm[] = {mac_mcps_data_confirm, (uint8_t)(slot + 1), mac_success};
    ret = mac_receive_primitive_exactly(session->mac_session, (mac_primitive_t*)tx_confirm);
    if(ret <= 0) {
        SN_ErrPrintf("wait for transmission status report failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }
    SN_InfoPrintf("received transmission status report\n");

    SN_InfoPrintf("exit\n");
    return SN_OK;
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
        }

        next_free_slot++;
    }

    return slot;
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
    slot_data->destination = table_entry->public_key;
    slot_data->packet      = *packet;
    slot_data->valid       = 1;
    slot_data->counter     = counter;

    int ret = do_packet_transmission(slot);

    if(ret != SN_OK) {
        SN_ErrPrintf("packet transmission failed with %d\n", -ret);
        slot_data->allocated = 0;
        return ret;
    }

    if((PACKET_ENTRY(*packet, encrypted_ack_header, request) != NULL || PACKET_ENTRY(*packet, signed_ack_header, request) != NULL) && PACKET_ENTRY(*packet, payload_data, request) == NULL) {
        //this is a pure acknowledgement packet
        SN_InfoPrintf("just sent pure acknowledgement packet; not performing retransmissions\n");
        slot_data->allocated = 0;
    }

    return SN_OK;
}

int SN_Delayed_acknowledge_encrypted(SN_Table_entry_t* table_entry, uint32_t counter) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL) {
        SN_ErrPrintf("table_entry must be valid\n");
        return -SN_ERR_NULL;
    }

    int rv = -SN_ERR_UNKNOWN;

    //for each transmission slot...
    for(int slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {
        transmission_slot_t* slot = &transmission_queue[slot_idx];

        //... if the slot is allocated, valid, and in my session...
        if(slot->allocated && slot->valid && table_entry->session == slot->session) {

            //... and its packet's destination is the one I'm talking about...
            if(memcmp(slot->destination.data, &table_entry->public_key.data, sizeof(SN_Public_key_t)) == 0) {

                //... and it's encrypted...
                if(PACKET_ENTRY(slot->packet, encryption_header, request) != NULL &&
                   slot->counter <= counter) {

                    //... acknowledge it.
                    slot->allocated = 0;

                    rv = SN_OK;
                }
            }
        }
    }

    SN_InfoPrintf("exit\n");
    return rv;
}

int SN_Delayed_acknowledge_signed(SN_Table_entry_t* table_entry, SN_Signature_t* signature) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL || signature == NULL) {
        SN_ErrPrintf("table_entry and signature must be valid\n");
        return -SN_ERR_NULL;
    }

    //for each transmission slot...
    for(int slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {
        transmission_slot_t* slot = &transmission_queue[slot_idx];

        //... if the slot is allocated, valid, and in my session...
        if(slot->allocated && slot->valid && table_entry->session == slot->session) {

            //... and its packet's destination is the one I'm talking about...
            if(memcmp(slot->destination.data, &table_entry->public_key.data, sizeof(SN_Public_key_t)) == 0) {

                //... and it's signed...
                if(PACKET_ENTRY(slot->packet, signature_header, request) != NULL &&
                   memcmp(PACKET_ENTRY(slot->packet, signature_header, request)->signature.data, signature->data, sizeof(signature->data)) != 0) {

                    //... acknowledge it.
                    slot->allocated = 0;

                    SN_InfoPrintf("exit\n");
                    return SN_OK;
                }
            }
        }
    }

    SN_ErrPrintf("acknowledgement entry not found\n");
    return -SN_ERR_UNKNOWN;
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

            //for each transmission slot...
            for(int slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {
                transmission_slot_t* slot = &transmission_queue[slot_idx];

                //... if the slot is allocated, valid, and in my session...
                if(slot->allocated && slot->valid && table_entry->session == slot->session) {

                    //... and its packet's destination is the one I'm talking about...
                    if(memcmp(slot->destination.data, &table_entry->public_key.data, sizeof(SN_Public_key_t)) == 0) {

                        //... and it's an association request...
                        if(PACKET_ENTRY(slot->packet, association_header, request) != NULL &&
                           PACKET_ENTRY(slot->packet, key_confirmation_header, request) == NULL) {

                            //... acknowledge it.
                            slot->allocated = 0;

                            SN_InfoPrintf("exit\n");
                            return SN_OK;
                        }
                    }
                }
            }
        } else {
            //this is an association finalise; it acknowledges an association_reply

            //for each transmission slot...
            for(int slot_idx = 0; slot_idx < SN_TRANSMISSION_SLOT_COUNT; slot_idx++) {
                transmission_slot_t* slot = &transmission_queue[slot_idx];

                //... if the slot is allocated, valid, and in my session...
                if(slot->allocated && slot->valid && table_entry->session == slot->session) {

                    //... and its packet's destination is the one I'm talking about...
                    if(memcmp(slot->destination.data, &table_entry->public_key.data, sizeof(SN_Public_key_t)) == 0) {

                        //... and it's an association reply...
                        if(PACKET_ENTRY(slot->packet, association_header, request) != NULL &&
                           PACKET_ENTRY(slot->packet, key_confirmation_header, request) != NULL) {

                            //... acknowledge it.
                            slot->allocated = 0;

                            SN_InfoPrintf("exit\n");
                            return SN_OK;
                        }
                    }
                }
            }
        }
    }

    SN_ErrPrintf("acknowledgement entry not found\n");
    return -SN_ERR_UNKNOWN;
}

void SN_Delayed_tick() {
    for(int i = 0; i < SN_TRANSMISSION_SLOT_COUNT; i++) {
        transmission_slot_t* slot = &transmission_queue[i];

        if(slot->allocated && slot->valid) {
            SN_InfoPrintf("doing retransmission processing for slot %d\n", i);

            slot->ticks_remaining--;
            slot->retries++;
            if(slot->ticks_remaining == 0) {
                SN_InfoPrintf("doing retransmission %d\n", slot->retries);
                do_packet_transmission(i);
            }
            slot->ticks_remaining = slot->session->nib.tx_retry_timeout;
            if(slot->retries >= slot->session->nib.tx_retry_limit) {
                //TODO: how do I fail, here?
            }

            SN_InfoPrintf("retransmission processing for slot %d done\n", i);
        }
    }
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
                slot->allocated = 0;
            }
        }
    }
}