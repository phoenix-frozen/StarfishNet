/*StarfishNet message transmission rules:
 * SN_Associate_request:
 *   must be unencrypted.
 *   must be unacknowledged.
 *   must be first.
 *   may only be accompanied by:
 *    SN_Evidence_message
 *    SN_Address_request
 *
 * SN_Associate_reply:
 *   must be unencrypted.
 *   must be unacknowledged.
 *   must be first.
 *   may only be accompanied by:
 *    SN_Evidence_message
 *    SN_Address_grant
 *
 * SN_Associate_finalise:
 *   must be encrypted.
 *   must be first.
 *
 * SN_Dissociate_message:
 *   must be either encrypted or signed.
 *
 * SN_Evidence_message:
 *   may be unencrypted.
 *   may be unacknowledged.
 *
 * SN_Address_request:
 *   may be unencrypted.
 *   may be unacknowledged.
 *
 * SN_Address_grant:
 *   may be unencrypted.
 *   may be unacknowledged.
 *
 * SN_Node_details_message:
 *   must be either encrypted or signed.
 *
 * SN_Address_change_notify:
 *   must be sent using long source address.
 *
 * default:
 *   must be encrypted.
 *   must be acknowledged.
 */

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <sn_status.h>

#include <string.h>
#include <assert.h>

#include "polarssl/sha1.h"

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_txrx.h"
#include "sn_message.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

//send out a datagram
//packet should only have msduLength and msdu filled; everything else is my problem
static int do_packet_transmission(SN_Session_t* session, SN_Table_entry_t* table_entry, bool acknowledged, uint8_t src_address_constraint, uint8_t dst_address_constraint, mac_primitive_t* packet) {
    SN_InfoPrintf("enter\n");

    static uint8_t packet_handle = 1;

    if(packet_handle == 0)
        packet_handle++;

    uint8_t max_payload_size = aMaxMACPayloadSize - 2;
    /* aMaxMACPayloadSize is for a packet with a short destination address, and no source addressing
     * information. we always send a source address, which is at least 2 byte long
     */

    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, dst_addr, buffer, and buffer_size must all be valid");
        return -SN_ERR_NULL;
    }

    packet->type = mac_mcps_data_request,
    packet->MCPS_DATA_request.SrcPANId    = session->mib.macPANId;
    //packet->MCPS_DATA_request.SrcAddr     is filled below
    //packet->MCPS_DATA_request.SrcAddrMode is filled below
    packet->MCPS_DATA_request.DstPANId    = session->mib.macPANId;
    //packet->MCPS_DATA_request.DstAddr     is filled below
    //packet->MCPS_DATA_request.DstAddrMode is filled below
    packet->MCPS_DATA_request.msduHandle  = packet_handle;
    //TODO: packet->MCPS_DATA_request.TxOptions   = acknowledged ? MAC_TX_OPTION_ACKNOWLEDGED : 0;
    packet->MCPS_DATA_request.TxOptions   = MAC_TX_OPTION_ACKNOWLEDGED;
    //packet->MCPS_DATA_request.msduLength  is filled by caller
    //packet->MCPS_DATA_request.msdu        is filled by caller
    SN_InfoPrintf("attempting to transmit a %d-byte packet\n", packet->MCPS_DATA_request.msduLength);

    //SrcAddr and SrcAddrMode
    if(session->mib.macShortAddress != SN_NO_SHORT_ADDRESS && src_address_constraint != mac_extended_address) {;
        SN_DebugPrintf("sending from our short address, %#06x\n", session->mib.macShortAddress);
        packet->MCPS_DATA_request.SrcAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.SrcAddr.ShortAddress = session->mib.macShortAddress;
    } else if(src_address_constraint != mac_short_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending from our long address, %#018lx\n", *(uint64_t*)session->mib.macIEEEAddress.ExtendedAddress);
        packet->MCPS_DATA_request.SrcAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.SrcAddr     = session->mib.macIEEEAddress;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    } else {
        SN_ErrPrintf("source address constraint %d prohibits message transmission\n", src_address_constraint);
        return -SN_ERR_INVALID;
    }

    //DstAddr
    if(table_entry->short_address != SN_NO_SHORT_ADDRESS && dst_address_constraint != mac_extended_address) {
        SN_DebugPrintf("sending to short address %#06x\n", table_entry->short_address);
        packet->MCPS_DATA_request.DstAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.DstAddr.ShortAddress = table_entry->short_address;
    } else if(dst_address_constraint != mac_short_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending to long address %#018lx\n", *(uint64_t*)table_entry->long_address.ExtendedAddress);
        packet->MCPS_DATA_request.DstAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.DstAddr     = table_entry->long_address;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    } else {
        SN_ErrPrintf("destination address constraint %d prohibits message transmission\n", src_address_constraint);
        return -SN_ERR_INVALID;
    }

    if(packet->MCPS_DATA_request.msduLength > max_payload_size) {
        SN_ErrPrintf("cannot transmit payload of size %d (max is %d)\n", packet->MCPS_DATA_request.msduLength, max_payload_size);
        return -SN_ERR_INVALID;
    }

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet->MCPS_DATA_request.msduLength; i += 4) {
        SN_DebugPrintf("%2x %2x %2x %2x\n", packet->MCPS_DATA_request.msdu[i], packet->MCPS_DATA_request.msdu[i + 1], packet->MCPS_DATA_request.msdu[i + 2], packet->MCPS_DATA_request.msdu[i + 3]);
    }
    SN_DebugPrintf("end packet data\n");

    SN_InfoPrintf("beginning packet transmission...\n");
    int ret = mac_transmit(session->mac_session, packet);
    SN_InfoPrintf("packet transmission returned %d\n", ret);

    if(ret != 11 + (packet->MCPS_DATA_request.SrcAddrMode == mac_extended_address ? 8 : 2) + (packet->MCPS_DATA_request.DstAddrMode == mac_extended_address ? 8 : 2) + packet->MCPS_DATA_request.msduLength) { //27 if both address formats are extended
        SN_ErrPrintf("packet transmission failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    //TODO: queueing behaviour: queue MCPS_DATA.indication while waiting for MCPS_DATA.confirm

    SN_InfoPrintf("waiting for transmission status report from radio...\n");
    //TODO: actual transmission status handling, including interpreting both MCPS_DATA.confirm and MLME_COMM_STATUS.indication
    //      (hint: that also means retransmission logic)
    const uint8_t tx_confirm[] = { mac_mcps_data_confirm, packet_handle, mac_success };
    packet_handle++;
    ret = mac_receive_primitive_exactly(session->mac_session, (mac_primitive_t*)tx_confirm);
    if(ret <= 0) {
        SN_ErrPrintf("wait for transmission status report failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }
    SN_InfoPrintf("received transmission status report\n");

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

//transmit packet, containing one or more messages
int SN_Transmit(SN_Session_t* session, SN_Address_t* dst_addr, uint8_t* buffer_size, SN_Message_t* buffer) {
    //initial NULL-checks
    if(session == NULL || dst_addr == NULL || buffer_size == NULL || (buffer == NULL && *buffer_size != 0)) {
        SN_ErrPrintf("session, dst_addr, buffer, and buffer_size must all be valid");
        return -SN_ERR_NULL;
    }

    //loop trackers for size-calculation and packet-generation loops
    uint8_t payload_position = sizeof(network_header_t);
    uint8_t buffer_position = 0;

    //constraint trackers
    uint8_t restricted = 0; //switches off acknowledgements and encryption, but only permits addressing and association messages
    uint8_t src_address_constraint = mac_no_address;
    uint8_t dst_address_constraint = mac_no_address;

    //actual packet buffer
    mac_primitive_t primitive;

    //validity check on address
    mac_address_t null_address = {};
    if(
            (dst_addr->type == mac_short_address && dst_addr->address.ShortAddress == SN_NO_SHORT_ADDRESS)
            ||
            (dst_addr->type == mac_extended_address && memcmp(dst_addr->address.ExtendedAddress, null_address.ExtendedAddress, sizeof(null_address)) == 0)
      ) {
        SN_ErrPrintf("attempting to send to null address. aborting\n");
        return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("we have %d messages to send\n", *buffer_size);
    SN_InfoPrintf("calculating size of packet to transmit...\n");
    for(int i = 0; i < *buffer_size; i++) {
        SN_Message_t* message = (SN_Message_t*)(((uint8_t*)buffer) + buffer_position);
        int message_memory_size = SN_Message_memory_size(message);
        int message_network_size = SN_Message_network_size(message);

        if(message_memory_size < 0) {
            SN_ErrPrintf("packet size calculation failed on message %d, with error %d\n", i, -message_memory_size);
            return message_memory_size;
        }

        assert(message_network_size >= 0);
        SN_InfoPrintf("message %d (of type %d) is of size %d\n", i, message->type, message_memory_size);
        payload_position += message_network_size;
        buffer_position += message_memory_size;

        if(payload_position > aMaxMACPayloadSize) {
            //this is here in order to interrupt processing before we hit any dangerous conditions
            SN_ErrPrintf("tripped way-too-long trigger at %d in size calculation. aborting.\n", payload_position);
            return -SN_ERR_RESOURCES;
        }
    }
    SN_InfoPrintf("packet is %d bytes long\n", payload_position);

    primitive.MCPS_DATA_request.msduLength = payload_position;
    payload_position                       = sizeof(network_header_t);
    buffer_position                        = 0;

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
        .session       = session,
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    int ret = SN_Table_lookup_by_address(dst_addr, &table_entry, NULL);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(dst_addr->type == mac_short_address)
            table_entry.short_address = dst_addr->address.ShortAddress;
        else
            table_entry.long_address  = dst_addr->address;

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table, aborting.\n");
            return -SN_ERR_RESOURCES;
        }
    }

    //sanity check: zero-message packets are a way of causing an associate_finalise transmission.
    // therefore, they're not allowed to nodes that haven't reached the SN_Send_finalise state
    if(buffer == NULL && table_entry.state < SN_Send_finalise) {
        SN_ErrPrintf("zero-length transmission to unassociated node is not permitted\n");
        return -SN_ERR_DISALLOWED;
    }

    //First things first, check the association state, and impose requirements based thereon.
    switch(table_entry.state) {
        case SN_Unassociated: {
            SN_InfoPrintf("no relationship. generating ECDH keypair\n");

            //generate ephemeral keypair
            int ret = SN_Crypto_generate_keypair(&table_entry.ephemeral_keypair);
            if(ret != SN_OK) {
                SN_ErrPrintf("error %d during key generation, aborting send\n", -ret);
                return ret;
            }

            //update state
            table_entry.state = SN_Awaiting_reply;
            }; //fallthrough
        case SN_Awaiting_reply: {
            //this case is a retransmission
            SN_InfoPrintf("generating associate request\n");

            restricted = 1;

            if(buffer->type == SN_Dissociate_request) {
                SN_InfoPrintf("dissociate detected; allowing normal dissociation processing\n");
                break;
            }

            if(buffer->type != SN_Associate_request) {
                SN_ErrPrintf("SN_Associate_request must be first message between two unassociated nodes\n");
                return -SN_ERR_DISALLOWED;
            }

            //generate associate-request message
            SN_Message_internal_t* out = (SN_Message_internal_t*)(primitive.MCPS_DATA_request.msdu + payload_position);
            out->type = SN_Associate_request;
            out->associate_request.public_key = table_entry.ephemeral_keypair.public_key;
            int message_memory_size = SN_Message_memory_size(buffer);
            int message_network_size = SN_Message_internal_size(out);
            SN_InfoPrintf("generating association message (whose type is %x, memory size is %d, and network size is %d)\n", out->type, message_memory_size, message_network_size);
            assert(message_memory_size > 0 && message_network_size > 0);
            buffer_position += message_memory_size;
            payload_position += message_network_size;
            (*buffer_size)--;
            } break;

        case SN_Associate_received: {
            SN_InfoPrintf("received association request, finishing ECDH\n");

            //generate ephemeral keypair
            int ret = SN_Crypto_generate_keypair(&table_entry.ephemeral_keypair);
            if(ret != SN_OK) {
                SN_ErrPrintf("error %d during key generation, aborting send\n", -ret);
                return ret;
            }

            //do ECDH math
            ret = SN_Crypto_key_agreement(&table_entry.key_agreement_key, &table_entry.ephemeral_keypair.private_key, &table_entry.link_key);
            if(ret != SN_OK) {
                SN_ErrPrintf("error %d during key agreement, aborting send\n", -ret);
                return ret;
            }

            //update state
            table_entry.state = SN_Awaiting_finalise;
            }; //fallthrough
        case SN_Awaiting_finalise: {
            //this case is a retransmission
            SN_InfoPrintf("generating associate reply\n");

            restricted = 1;

            if(buffer->type == SN_Dissociate_request) {
                SN_InfoPrintf("dissociate detected; allowing normal dissociation processing\n");
                break;
            }

            if(buffer->type != SN_Associate_reply) {
                SN_ErrPrintf("SN_Associate_reply must be first message back to associator\n");
                return -SN_ERR_DISALLOWED;
            }

            //generate associate-reply message here
            SN_Message_internal_t* out = (SN_Message_internal_t*)(primitive.MCPS_DATA_request.msdu + payload_position);
            out->type = SN_Associate_reply;
            out->associate_reply.public_key = table_entry.ephemeral_keypair.public_key;
            sha1(table_entry.link_key.key_id.data, sizeof(table_entry.link_key.key_id.data), out->associate_reply.challenge1.data);
            int message_memory_size = SN_Message_memory_size(buffer);
            int message_network_size = SN_Message_internal_size(out);
            SN_InfoPrintf("generating association message (whose type is %x, memory size is %d, and network size is %d)\n", out->type, message_memory_size, message_network_size);
            assert(message_memory_size > 0 && message_network_size > 0);
            buffer_position += message_memory_size;
            payload_position += message_network_size;
            (*buffer_size)--;
            } break;

        case SN_Send_finalise: {
            //generate finalise here
            SN_InfoPrintf("prefixing finalise message to packet\n");

            SN_Message_internal_t* finalise_message = (SN_Message_internal_t*)(primitive.MCPS_DATA_request.msdu + payload_position);
            finalise_message->type                          = SN_Associate_finalise;
            finalise_message->associate_finalise.challenge2 = table_entry.link_key.key_id;

            ret = SN_Message_internal_size(finalise_message);
            assert(ret > 0);
            payload_position += ret;
            primitive.MCPS_DATA_request.msduLength += ret;
            }; //fallthrough
        case SN_Associated:
            break;

        default:
            assert(0); //something horrible has happened
            SN_ErrPrintf("how did table_entry.state become %d?!?\n", table_entry.state);
            return -SN_ERR_UNEXPECTED;
    }

    //length check
    if(primitive.MCPS_DATA_request.msduLength > aMaxMACPayloadSize) {
        SN_ErrPrintf("%u-byte payload too big for 802.15.4's %u-byte limit\n", primitive.MCPS_DATA_request.msduLength, aMaxMACPayloadSize);
        return -SN_ERR_RESOURCES;
    }


    //network header
    network_header_t* header = (network_header_t*)primitive.MCPS_DATA_request.msdu;
    header->data.protocol_id  = STARFISHNET_PROTOCOL_ID;
    header->data.protocol_ver = STARFISHNET_PROTOCOL_VERSION;
    header->data.attributes   = 0;
    header->crypto.counter = table_entry.packet_tx_count++;

    //lots of things that could have affected the node table entry. update it
    ret = SN_Table_update(&table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("node table update failed with %d, aborting.\n", -ret);
        return ret;
    }

    //that's all the metadata, now we generate the payload
    SN_InfoPrintf("generating packet payload...\n");

    //some markers to indicate management tasks to be performed post-transmission
    int dissociate_was_sent = 0;
    int short_address_was_released = 0;

    SN_InfoPrintf("%d messages remain.\n", *buffer_size);
    for(int i = 0; i < *buffer_size; i++) {
        assert(payload_position < primitive.MCPS_DATA_request.msduLength);

        SN_Message_t* message = (SN_Message_t*)(((uint8_t*)buffer) + buffer_position);

        int message_memory_size = SN_Message_memory_size(message);
        int message_network_size = SN_Message_network_size(message);
        SN_InfoPrintf("generating message %d (whose type is %x, memory size is %d, and network size is %d)\n", i, message->type, message_memory_size, message_network_size);

        if(restricted) {
            //restricted mode check
            switch(message->type) {
                case SN_Associate_request:
                case SN_Associate_reply:
                case SN_Dissociate_request:
                case SN_Address_request:
                case SN_Address_grant:
                case SN_Node_details:
                case SN_Evidence_message:
                case SN_Authentication_message:
                    SN_DebugPrintf("message generation permitted...\n");
                    break;

                default:
                    SN_ErrPrintf("without a security association, only security/association, addressing, and evidence messages allowed.\n");
                    return -SN_ERR_DISALLOWED;
            }
        }

        SN_DebugPrintf("doing message generation...\n");

        assert(message_memory_size >= 0);
        assert(message_network_size >= 0);
        //XXX: no error-checking here, because we did this before, so it's guaranteed to succeed

        //actually do the message encoding
        SN_Message_internal_t* out = (SN_Message_internal_t*)(primitive.MCPS_DATA_request.msdu + payload_position);
        out->type = message->type;
        switch(out->type) {
            case SN_Address_release: {
                //look up our short address
                uint16_t short_address = session->mib.macShortAddress;

                //make sure it's not NO_SHORT_ADDRESS
                if(short_address == SN_NO_SHORT_ADDRESS) {
                    SN_ErrPrintf("no short address to release\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //make sure destination is our parent
                if(
                        (session->nib.parent_address.type == mac_short_address && session->nib.parent_address.address.ShortAddress != table_entry.short_address)
                        ||
                        (session->nib.parent_address.type == mac_extended_address && memcmp(session->nib.parent_address.address.ExtendedAddress, table_entry.long_address.ExtendedAddress, sizeof(session->nib.parent_address.address)) != 0)
                  ) {
                    SN_ErrPrintf("address-release must be sent to parent\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //set short address to NO_SHORT_ADDRESS (and update radio)
                short_address_was_released = 1;

                //send old short address to parent
                out->address_message.address = short_address;
                } break;

            case SN_Associate_request:
            case SN_Associate_reply:
            case SN_Associate_finalise:
                //this is an error
                SN_ErrPrintf("association message occurred out of order\n");
                return -SN_ERR_UNEXPECTED;

            case SN_Address_grant:
                //for the moment, this is an error
                SN_ErrPrintf("I can't do address grants yet\n");
                return -SN_ERR_UNIMPLEMENTED;

            case SN_Address_change_notify:
                out->address_message.address = session->mib.macShortAddress;
                if(src_address_constraint == mac_short_address) {
                    SN_ErrPrintf("attempting to send address change notify with short-address-only constraint. this is an error\n");
                    return -SN_ERR_INVALID;
                } else {
                    src_address_constraint = mac_extended_address;
                }
                break;

            case SN_Node_details:
                out->node_details.long_address  = session->mib.macIEEEAddress;
                out->node_details.short_address = session->mib.macShortAddress;
                out->node_details.public_key    = session->device_root_key.public_key;
                break;

            case SN_Authentication_message:
                if(table_entry.state <= SN_Associate_received) {
                    SN_ErrPrintf("attempting to authenticate a nonexistent key-exchange key\n");
                    return -SN_ERR_INVALID;
                }
                ret = SN_Crypto_sign(&session->device_root_key.private_key, table_entry.ephemeral_keypair.public_key.data, sizeof(table_entry.ephemeral_keypair.public_key.data), &out->authentication_message.signature);
                if(ret != SN_OK) {
                    SN_ErrPrintf("signature generation failed with %d\n", -ret);
                    return ret;
                }
                break;

            case SN_Address_request: {
                //look up our short address
                uint16_t short_address = session->mib.macShortAddress;

                //make sure it's NO_SHORT_ADDRESS
                if(short_address != SN_NO_SHORT_ADDRESS) {
                    SN_ErrPrintf("no short address to release\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //make sure destination is our parent
                if(
                        (session->nib.parent_address.type == mac_short_address && session->nib.parent_address.address.ShortAddress != table_entry.short_address)
                        ||
                        (session->nib.parent_address.type == mac_extended_address && memcmp(session->nib.parent_address.address.ExtendedAddress, table_entry.long_address.ExtendedAddress, sizeof(session->nib.parent_address.address)) != 0)
                  ) {
                    SN_ErrPrintf("address-release must be sent to parent\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //set is_block_request if we're a router
                out->address_request.is_block_request = session->nib.enable_routing;
                }; break;

            case SN_Dissociate_request:
                short_address_was_released = 1;
                dissociate_was_sent = 1;
                if(restricted) {
                    struct __attribute__((packed)) {
                        uint16_t     counter;
                        SN_Address_t remote_node;
                        uint8_t      message_type;
                    } signature_data = {
                        .remote_node = {
                            .type    = dst_addr->type,
                            .address = dst_addr->address,
                        },
                        .message_type = message->type,
                        .counter      = header->crypto.counter,
                    };
                    if(signature_data.remote_node.type == mac_short_address) {
                        //protect against there being garbage in the other bytes if we're using a short address
                        memset(signature_data.remote_node.address.ExtendedAddress + 2, 0, sizeof(signature_data.remote_node.address.ExtendedAddress) - 2);
                    }
                    ret = SN_Crypto_sign(&session->device_root_key.private_key, (uint8_t*)&signature_data, sizeof(signature_data), &out->dissociate_request.signature);
                }
                break;

            default:
                assert(message_memory_size == message_network_size);
                memcpy(out, message, message_memory_size);
                break;
        }

        //loop upkeep
        payload_position += message_network_size;
        buffer_position += message_memory_size;
    }

    SN_InfoPrintf("payload generation complete\n");

    //TODO: routing/addressing
    header->data.src_addr = SN_NO_SHORT_ADDRESS;
    header->data.dst_addr = SN_NO_SHORT_ADDRESS;

    /*Packet encryption:
     * The payload will be encrypted in-place, followed by
     * the tag (16 bytes) and a counter (2 bytes).
     * This counter is updated on each packet transmission, and held in the node table.
     * When the counter reaches 0xFFFF, we trigger a rekey.
     */
    if(!restricted) {
        SN_InfoPrintf("encrypting payload...\n");

        header->data.encrypt = 1;

        ret = SN_Crypto_encrypt(&table_entry.link_key.key, &table_entry.link_key.key_id, header->crypto.counter,
            (uint8_t*)&header->data, sizeof(header->data),
            primitive.MCPS_DATA_request.msdu + sizeof(*header), primitive.MCPS_DATA_request.msduLength - sizeof(*header),
            header->crypto.tag);
        if(ret != SN_OK) {
            SN_ErrPrintf("Packet encryption failed with %d, aborting\n", -ret);
            return -SN_ERR_SECURITY;
        }

        SN_InfoPrintf("payload encryption complete\n");

        //TODO: rekeying
    } else {
        //if we're not encrypting, fill tag with a hash instead (truncating if necessary)
        SN_Hash_t hashbuf;
        sha1_context hashctx;

        sha1_init(&hashctx);
        sha1_starts(&hashctx);
        sha1_update(&hashctx, (uint8_t*)&header->data, sizeof(header->data));
        sha1_update(&hashctx, (uint8_t*)&header->crypto.counter, sizeof(header->crypto.counter));
        sha1_update(&hashctx, primitive.MCPS_DATA_request.msdu + sizeof(*header), primitive.MCPS_DATA_request.msduLength - sizeof(*header));
        sha1_finish(&hashctx, hashbuf.data);
        sha1_free(&hashctx);

        memcpy(header->crypto.tag, hashbuf.data, sizeof(header->crypto.tag));
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = do_packet_transmission(session, &table_entry, !restricted, src_address_constraint, dst_address_constraint, &primitive);

    if(ret == SN_OK) {
        *buffer_size = primitive.MCPS_DATA_request.msduLength;
    } else {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
    }

    SN_InfoPrintf("exit\n");
    return ret;
}

