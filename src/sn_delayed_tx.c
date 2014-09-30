#include "sn_delayed_tx.h"

#include <sn_status.h>
#include <sn_logging.h>

#include <assert.h>
#include <string.h>

#ifndef SN_TRANSMISSION_SLOT_COUNT
#define SN_TRANSMISSION_SLOT_COUNT 8
#endif /* SN_TRANSMISSION_SLOT_COUNT */

#if SN_TRANSMISSION_SLOT_COUNT > 255
#error "Transmission queue may be at most 255 slots in length."
#endif /* SN_TRANSMISSION_SLOT_COUNT > 255 */

//TODO: do I do the routing logic in here?

typedef struct transmission_slot {
    union {
        struct {
            uint8_t valid     :1;
            uint8_t allocated :1;
        };
        uint8_t flags;
    };

    unsigned int retries;

    SN_Session_t* session;
    SN_Table_entry_t* destination;

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
    mac_primitive_t* packet = &slot_data->packet.packet_data;
    SN_Table_entry_t* table_entry = slot_data->destination;

    //TODO: should do encryption here as well

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
    if(table_entry->short_address != SN_NO_SHORT_ADDRESS) {
        SN_DebugPrintf("sending to short address %#06x\n", table_entry->short_address);
        packet->MCPS_DATA_request.DstAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.DstAddr.ShortAddress = table_entry->short_address;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending to long address %#018"PRIx64"\n", *(uint64_t*)table_entry->long_address.ExtendedAddress);
        packet->MCPS_DATA_request.DstAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.DstAddr     = table_entry->long_address;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    }

    if(packet->MCPS_DATA_request.msduLength > max_payload_size) {
        SN_ErrPrintf("cannot transmit payload of size %d (max is %d)\n", packet->MCPS_DATA_request.msduLength, max_payload_size);
        return -SN_ERR_INVALID;
    }

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet->MCPS_DATA_request.msduLength; i += 4) {
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
    int ret = mac_transmit(session->mac_session, packet);
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

    slot_data->allocated = 0;

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

int SN_Delayed_transmit(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet) {
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

    //WARNING: EVIL POINTER ARITHMETIC AHEAD
    //this code generates a new packet layout structure pointing into the packet in the transmission slot structure
    slot_data->packet.packet_layout.network_header                  =
        packet->packet_layout.network_header == NULL ? NULL :
            (network_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                ((uint8_t*)packet->packet_layout.network_header -
                                 packet->packet_data.MCPS_DATA_request.msdu
                                )
            );
    slot_data->packet.packet_layout.node_details_header             =
        packet->packet_layout.node_details_header == NULL ? NULL :
            (node_details_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                     ((uint8_t*)packet->packet_layout.node_details_header -
                                      packet->packet_data.MCPS_DATA_request.msdu
                                     )
            );
    slot_data->packet.packet_layout.association_header              =
        packet->packet_layout.association_header == NULL ? NULL :
            (association_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                    ((uint8_t*)packet->packet_layout.association_header -
                                     packet->packet_data.MCPS_DATA_request.msdu
                                    )
            );
    slot_data->packet.packet_layout.encryption_header               =
        packet->packet_layout.encryption_header == NULL ? NULL :
            (encryption_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                   ((uint8_t*)packet->packet_layout.encryption_header -
                                    packet->packet_data.MCPS_DATA_request.msdu
                                   )
            );
    slot_data->packet.packet_layout.key_confirmation_header         =
        packet->packet_layout.key_confirmation_header == NULL ? NULL :
            (key_confirmation_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                         ((uint8_t*)packet->packet_layout.key_confirmation_header -
                                          packet->packet_data.MCPS_DATA_request.msdu
                                         )
            );
    slot_data->packet.packet_layout.address_allocation_header       =
        packet->packet_layout.address_allocation_header == NULL ? NULL :
            (address_allocation_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                           ((uint8_t*)packet->packet_layout.address_allocation_header -
                                            packet->packet_data.MCPS_DATA_request.msdu
                                           )
            );
    slot_data->packet.packet_layout.address_block_allocation_header =
        packet->packet_layout.address_block_allocation_header == NULL ? NULL :
            (address_block_allocation_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                                 ((uint8_t*)packet->packet_layout.address_block_allocation_header -
                                                  packet->packet_data.MCPS_DATA_request.msdu
                                                 )
            );
    slot_data->packet.packet_layout.signature_header                =
        packet->packet_layout.signature_header == NULL ? NULL :
            (signature_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                  ((uint8_t*)packet->packet_layout.signature_header -
                                   packet->packet_data.MCPS_DATA_request.msdu
                                  )
            );
    slot_data->packet.packet_layout.encrypted_ack_header            =
        packet->packet_layout.encrypted_ack_header == NULL ? NULL :
            (encrypted_ack_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                      ((uint8_t*)packet->packet_layout.encrypted_ack_header -
                                       packet->packet_data.MCPS_DATA_request.msdu
                                      )
            );
    slot_data->packet.packet_layout.signed_ack_header               =
        packet->packet_layout.signed_ack_header == NULL ? NULL :
            (signed_ack_header_t*)(slot_data->packet.packet_data.MCPS_DATA_request.msdu +
                                   ((uint8_t*)packet->packet_layout.signed_ack_header -
                                    packet->packet_data.MCPS_DATA_request.msdu
                                   )
            );

    slot_data->packet.packet_layout.payload_data = packet->packet_layout.payload_data == NULL ? NULL :
        (slot_data->packet.packet_data.MCPS_DATA_request.msdu +
         (packet->packet_layout.payload_data - packet->packet_data.MCPS_DATA_request.msdu)
        );

    slot_data->packet.packet_layout.payload_length = packet->packet_layout.payload_length;
    slot_data->packet.packet_layout.crypto_margin  = packet->packet_layout.crypto_margin;

    slot_data->session            = session;
    slot_data->destination        = table_entry;
    slot_data->packet.packet_data = packet->packet_data;
    slot_data->valid              = 1;

    return do_packet_transmission(slot);
}
