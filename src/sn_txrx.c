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
#include <mac802154.h>

#include "sn_txrx.h"

#include <string.h>
#include <assert.h>

#include "polarssl/sha1.h"

#ifndef NDEBUG
#include <stdio.h>
#define MAC_CALL(call, x...) { int ret = call(x); if(ret <= 0) { SN_ErrPrintf(#call"("#x") = %d (failure)\n", ret); return -SN_ERR_RADIO; } else { SN_DebugPrintf(#call"("#x") = %d (success)\n", ret); } }
#else //NDEBUG
#define MAC_CALL(call, x...) { if(call(x) <= 0) { return -SN_ERR_RADIO; } }
#endif //NDEBUG

//some templates for mac_receive_primitive
#define MAC_SET_CONFIRM(primitive) const uint8_t primitive##_set_confirm[] = {mac_mlme_set_confirm, mac_success, primitive}
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

typedef enum {
    //continues on from SN_Message_type_t
    SN_Associate_finalise          //respond to the challenge with a challenge of our own
        = SN_End_of_message_types,
    SN_Address_grant,              //used by a router to assign a short address to its child
    SN_Address_revoke,             //used by a router to revoke a short address from its child
    SN_Address_change_notify,      //inform a StarfishNet node that our short address has changed

    SN_End_of_internal_message_types
} SN_Message_internal_type_t;

typedef union SN_Message_internal {
    //XXX: if you change this, check that SN_Message_network_size is still safe
    uint8_t type;                //SN_Message_type_t

    struct __attribute__((packed)) SN_Data_message data;

    struct __attribute__((packed)) SN_Evidence_message evidence;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Public_key_t public_key;
    } associate_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint8_t         finalise_now;
        SN_Public_key_t public_key;
        SN_Hash_t       challenge1;
    } associate_reply;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_AES_key_id_t challenge2;
    } associate_finalise;

    struct __attribute__((packed)) {
        uint8_t type;             //SN_Message_type_t
        uint8_t is_block_request; //1 if it's a request for an address block, 0 if it's for a single address
    } address_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint8_t         block_size; //size of address block being granted. power of 2
        uint16_t        address;
    } address_grant;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint16_t        address;
    } address_message; //used for Address_release and Address_change

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint16_t        short_address;
        mac_address_t   long_address;
        SN_Public_key_t public_key;
    } node_details; //used for Node_details

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Signature_t  signature; //TODO: what does this signature cover?
    } dissociate_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Signature_t  signature;
    } authentication_message;
} SN_Message_internal_t;

static int SN_Message_internal_size(SN_Message_internal_t* message) {
    assert(message != NULL);
    //XXX: if you change this, check that SN_Message_network_size is still safe

    if(message == NULL)
        return -SN_ERR_NULL;

    switch(message->type) {
        case SN_Data_message:
            return sizeof(message->data)                    + message->data.payload_length;

        case SN_Evidence_message:
            return sizeof(message->evidence);

        case SN_Associate_request:
            return sizeof(message->associate_request);

        case SN_Associate_reply:
            return sizeof(message->associate_reply);

        case SN_Associate_finalise:
            return sizeof(message->associate_finalise);

        case SN_Address_request:
            return sizeof(message->address_request);

        case SN_Address_grant:
            return sizeof(message->address_grant);

        case SN_Address_release:
        case SN_Address_change_notify:
            return sizeof(message->address_message);

        case SN_Node_details:
            return sizeof(message->node_details);

        case SN_Dissociate_request:
            return sizeof(message->dissociate_request);

        case SN_Authentication_message:
            return sizeof(message->authentication_message);

        default:
            return 1;
    }
}

int SN_Message_network_size(SN_Message_t* message) {
    //XXX: this is currently safe by inspection
    return SN_Message_internal_size((SN_Message_internal_t*)message);
}

//StarfishNet packet header
typedef struct __attribute__((packed)) network_header {
    struct __attribute__((packed)) {
        uint8_t protocol_id;
        uint8_t protocol_ver;
        uint16_t src_addr;
        uint16_t dst_addr;
        union {
            struct {
                uint8_t encrypt :1;
                uint8_t         :7;
            };
            uint8_t attributes;
        };
    } data;

    struct __attribute__((packed)) {
        uint16_t counter;
        uint8_t  tag[SN_Tag_size];
    } crypto;
} network_header_t;

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

            //update node table
            ret = SN_Table_update(&table_entry);
            if(ret != SN_OK) {
                SN_ErrPrintf("error %d during table update, aborting send\n", -ret);
                return ret;
            }
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

            //update node table
            ret = SN_Table_update(&table_entry);
            if(ret != SN_OK) {
                SN_ErrPrintf("error %d during table update, aborting send\n", -ret);
                return ret;
            }
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
                    SN_ErrPrintf("without a security association, only association, addressing, and evidence messages allowed.\n");
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
                        SN_Address_t remote_node;
                        uint8_t      message_type;
                    } signature_data = {
                        .remote_node = {
                            .type = dst_addr->type,
                            .address = dst_addr->address,
                        },
                        .message_type = message->type,
                    };
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

    //network header
    network_header_t* header = (network_header_t*)primitive.MCPS_DATA_request.msdu;
    header->data.protocol_id  = STARFISHNET_PROTOCOL_ID;
    header->data.protocol_ver = STARFISHNET_PROTOCOL_VERSION;
    header->data.attributes   = 0;

    //TODO: routing/addressing
    header->data.src_addr = SN_NO_SHORT_ADDRESS;
    header->data.dst_addr = SN_NO_SHORT_ADDRESS;

    /*Packet encryption:
     * The payload will be encrypted in-place, followed by
     * the tag (16 bytes) and a counter (2 bytes).
     * This counter is updated on each packet transmission, and held in the node table.
     * When the counter reaches 0xFFF0, we trigger a rekey. (Message transmissions are
     * permitted to continue during the rekey, until the counter reaches 0xFFFF.)
     */
    if(!restricted) {
        SN_InfoPrintf("encrypting payload...\n");

        ret = SN_Crypto_encrypt(&table_entry.link_key.key, &table_entry.link_key.key_id, table_entry.packet_tx_count,
            (uint8_t*)&header->data, sizeof(header->data),
            primitive.MCPS_DATA_request.msdu + sizeof(*header), primitive.MCPS_DATA_request.msduLength - sizeof(*header),
            header->crypto.tag);
        if(ret != SN_OK) {
            SN_ErrPrintf("Packet encryption failed with %d, aborting\n", -ret);
            return -SN_ERR_SECURITY;
        }

        header->data.encrypt = 1;
        header->crypto.counter = table_entry.packet_tx_count++;
        SN_Table_update(&table_entry);

        SN_InfoPrintf("payload encryption complete\n");

        //TODO: rekeying
    } else {
        //if we're not encrypting, fill tag with a hash instead (truncating if necessary)
        SN_Hash_t hashbuf;
        sha1_context hashctx;

        sha1_init(&hashctx);
        sha1_starts(&hashctx);
        sha1_update(&hashctx, (uint8_t*)&header->data, sizeof(header->data));
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

//receive packet, decoding into one or more messages
int SN_Receive(SN_Session_t* session, SN_Address_t* src_addr, uint8_t* buffer_size, SN_Message_t* buffer) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || src_addr == NULL || buffer == NULL || buffer_size == NULL) {
        SN_ErrPrintf("session, src_addr, buffer, and buffer_size must all be valid");
        return -SN_ERR_NULL;
    }

    SN_InfoPrintf("output buffer size is %d\n", *buffer_size);

    //TODO: presumably there's some kind of queue-check here

    mac_primitive_t packet;
    SN_InfoPrintf("beginning packet reception\n");
    //TODO: switch to a raw mac_receive() and do network-layer housekeeping (including retransmission)
    int ret = mac_receive_primitive_type(session->mac_session, &packet, mac_mcps_data_indication);
    SN_InfoPrintf("packet reception returned %d\n", ret);

    if (!(ret > 0)) {
        SN_ErrPrintf("packet received failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    //print some debugging information
    if(packet.MCPS_DATA_indication.DstAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet to %#018lx\n", *(uint64_t*)packet.MCPS_DATA_indication.DstAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet to %#06x\n", packet.MCPS_DATA_indication.DstAddr.ShortAddress);
    }
    if(packet.MCPS_DATA_indication.SrcAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet from %#018lx\n", *(uint64_t*)packet.MCPS_DATA_indication.SrcAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet from %#06x\n", packet.MCPS_DATA_indication.SrcAddr.ShortAddress);
    }
    SN_InfoPrintf("received packet containing %d-byte payload\n", packet.MCPS_DATA_indication.msduLength);

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet.MCPS_DATA_indication.msduLength; i += 4) {
        SN_DebugPrintf("%2x %2x %2x %2x\n", packet.MCPS_DATA_indication.msdu[i], packet.MCPS_DATA_indication.msdu[i + 1], packet.MCPS_DATA_indication.msdu[i + 2], packet.MCPS_DATA_indication.msdu[i + 3]);
    }
    SN_DebugPrintf("end packet data\n");

    //network header checks
    network_header_t* header = (network_header_t*)packet.MCPS_DATA_indication.msdu;
    if(!(header->data.protocol_id == STARFISHNET_PROTOCOL_ID && header->data.protocol_ver == STARFISHNET_PROTOCOL_VERSION)) {
        SN_ErrPrintf("packet has invalid protocol ID bytes. protocol is %x (should be %x), version is %x (should be %x)\n", header->data.protocol_id, STARFISHNET_PROTOCOL_ID, header->data.protocol_ver, STARFISHNET_PROTOCOL_VERSION);
        return -SN_ERR_OLD_VERSION;
    }

    //TODO: routing happens here

    src_addr->type    = packet.MCPS_DATA_indication.SrcAddrMode;
    src_addr->address = packet.MCPS_DATA_indication.SrcAddr;

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
        .session       = session,
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    SN_Certificate_storage_t* cert_storage = NULL;
    ret = SN_Table_lookup_by_address(src_addr, &table_entry, &cert_storage);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(src_addr->type == mac_short_address)
            table_entry.short_address = src_addr->address.ShortAddress;
        else
            table_entry.long_address  = src_addr->address;

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return -SN_ERR_RESOURCES;
        }
    }

    //extract data
    SN_InfoPrintf("decoding packet payload...\n");
    uint8_t was_encrypted = 0;
    if(packet.MCPS_DATA_indication.msduLength > *buffer_size + sizeof(network_header_t)) {
        SN_ErrPrintf("buffer size %d is too small for a %d-byte packet\n", *buffer_size, packet.MCPS_DATA_indication.msduLength);
        return -SN_ERR_RESOURCES;
    }

    //Packet decryption. See comment in SN_Transmit for more detail.
    if(header->data.encrypt) {
        SN_InfoPrintf("decrypting payload...\n");

        ret = SN_Crypto_decrypt(&table_entry.link_key.key, &table_entry.link_key.key_id, header->crypto.counter,
            (uint8_t*)&header->data, sizeof(header->data),
            packet.MCPS_DATA_indication.msdu + sizeof(*header), packet.MCPS_DATA_indication.msduLength - sizeof(*header),
            header->crypto.tag);
        if(ret != SN_OK) {
            SN_ErrPrintf("Packet decryption failed with %d, aborting\n", -ret);
            return -SN_ERR_SECURITY;
        }

        SN_InfoPrintf("payload decryption complete. %u bytes remaining to process\n", packet.MCPS_DATA_indication.msduLength);
        was_encrypted = 1;

        //TODO: rekeying
    } else {
        //if unencrypted, do a hash check
        SN_Hash_t hashbuf;
        sha1_context hashctx;

        sha1_init(&hashctx);
        sha1_starts(&hashctx);
        sha1_update(&hashctx, (uint8_t*)&header->data, sizeof(header->data));
        sha1_update(&hashctx, packet.MCPS_DATA_indication.msdu + sizeof(*header), packet.MCPS_DATA_indication.msduLength - sizeof(*header));
        sha1_finish(&hashctx, hashbuf.data);
        sha1_free(&hashctx);

        if(memcmp(header->crypto.tag, hashbuf.data, sizeof(header->crypto.tag)) != 0) {
            SN_ErrPrintf("Packet integrity check failed, aborting\n");
            return -SN_ERR_SECURITY;
        }
    }

    uint8_t payload_position = sizeof(network_header_t);
    uint8_t buffer_position = 0;
    uint8_t should_be_last_message = 0;
    uint8_t message_count;
    uint8_t restricted = 0;

    mac_primitive_t response_buffer;
    uint8_t response_messages = 0;
    uint8_t send_explicit_finalise = 0;

    //state check / association protocol
    { //this is in a block so that message gets scoped out
    SN_Message_internal_t* message = (SN_Message_internal_t*)(packet.MCPS_DATA_indication.msdu + payload_position);
    switch(table_entry.state) {

        case SN_Unassociated: {
            //if we have no relationship, first message must be an associate_request
            SN_InfoPrintf("received packet from node with no relation to us...\n");
            if(message->type != SN_Associate_request) {
                SN_ErrPrintf("first message from node with no relation to us should have been an associate. it was a %d. dropping.\n", message->type);
                return -SN_ERR_INVALID;
            }
            SN_InfoPrintf("first message is an Associate_request. informing higher layer\n");

            //record state change in node table
            table_entry.state = SN_Associate_received;
            table_entry.key_agreement_key = message->associate_request.public_key;
            SN_Table_update(&table_entry);

            //generate message for higher layer
            buffer->type = SN_Associate_request;

            //advance counters and configure message processing
            int message_memory_size = SN_Message_memory_size(buffer);
            int message_network_size = SN_Message_internal_size(message);
            SN_InfoPrintf("decoding association message (whose type is %x, memory size is %d, and network size is %d)\n", message->type, message_memory_size, message_network_size);
            buffer_position += message_memory_size;
            payload_position += message_network_size;
            restricted = 1;
            } break;

        case SN_Associate_received:
            //shouldn't happen at all
            SN_WarnPrintf("received packet from node in Associate_received state. dropping.\n");
            return -SN_ERR_UNEXPECTED;

        case SN_Awaiting_reply:
            //in this state, first message should be an associate_reply, but we also accept dissociate_request
            SN_InfoPrintf("received packet from node from whom we're expecting an Associate_reply...\n");

            switch(message->type) {
                case SN_Associate_reply: {
                    SN_InfoPrintf("first message is an Associate_reply. informing higher layer\n");

                    //key agreement
                    table_entry.key_agreement_key = message->associate_reply.public_key;
                    int ret = SN_Crypto_key_agreement(&table_entry.key_agreement_key, &table_entry.ephemeral_keypair.private_key, &table_entry.link_key);
                    if(ret != SN_OK) {
                        SN_ErrPrintf("key agreement failed with %d\n", -ret);
                        return -SN_ERR_KEYGEN;
                    }

                    //check challenge1
                    SN_Hash_t hashbuf;
                    sha1(table_entry.link_key.key_id.data, sizeof(table_entry.link_key.key_id.data), hashbuf.data);
                    if(memcmp(hashbuf.data, message->associate_reply.challenge1.data, sizeof(hashbuf.data)) != 0) {
                        SN_ErrPrintf("challenge1 check failed, aborting handshake\n");
                        table_entry.state = SN_Unassociated;
                        //TODO: send a dissociate
                    } else {
                        SN_InfoPrintf("challenge1 check succeeded\n");
                        table_entry.state = SN_Send_finalise;
                    }

                    //update node table
                    SN_Table_update(&table_entry);

                    if(table_entry.state != SN_Send_finalise) {
                        return -SN_ERR_SECURITY;
                    }

                    //generate message for higher layer
                    buffer->type = SN_Associate_reply;

                    //advance counters and configure message processing
                    int message_memory_size = SN_Message_memory_size(buffer);
                    int message_network_size = SN_Message_internal_size(message);
                    SN_InfoPrintf("decoding association message (whose type is %x, memory size is %d, and network size is %d)\n", message->type, message_memory_size, message_network_size);
                    buffer_position += message_memory_size;
                    payload_position += message_network_size;
                    restricted = 1;
                    send_explicit_finalise = message->associate_reply.finalise_now;
                    }; break;

                case SN_Dissociate_request:
                    //do nothing, and allow this to be processed normally
                    SN_WarnPrintf("node has aborted association. falling through to dissociate processing in restricted mode\n");
                    restricted = 1; //this is an aborted key-exhange, so we shouldn't allow anything interesting to happen at the application-layer
                    break;

                default:
                    SN_ErrPrintf("first message from node we've tried to associate with should be a reply. it was a %d. dropping.\n", message->type);
                    return -SN_ERR_INVALID;
            }
            break;

        case SN_Awaiting_finalise:
            //in this state, first message should be an associate_finalise, but we also accept dissociate_request
            SN_InfoPrintf("received packet from node from whom we're expecting an Associate_finalise...\n");

            switch(message->type) {
                case SN_Associate_finalise: {
                    //check challenge2
                    if(!was_encrypted) {
                        SN_ErrPrintf("received unencrypted challenge2, aborting handshake\n");
                        table_entry.state = SN_Unassociated;
                        //TODO: send a dissociate
                    } else if(memcmp(table_entry.link_key.key_id.data, message->associate_finalise.challenge2.data, sizeof(table_entry.link_key.key_id.data))) {
                        SN_ErrPrintf("challenge2 check failed, aborting handshake\n");
                        table_entry.state = SN_Unassociated;
                        //TODO: send a dissociate
                    } else {
                        SN_InfoPrintf("challenge2 check succeeded\n");
                        table_entry.state = SN_Associated;
                    }

                    //update node table
                    SN_Table_update(&table_entry);

                    if(table_entry.state != SN_Associated) {
                        return -SN_ERR_SECURITY;
                    }

                    //higher layer doesn't hear about finalise messages

                    //make sure this message doesn't get processed again
                    payload_position += SN_Message_internal_size(message);
                }
                break;

                case SN_Dissociate_request:
                    //do nothing, and allow this to be processed normally
                    SN_WarnPrintf("node has aborted association. falling through to dissociate processing in restricted mode\n");
                    restricted = 1; //this is an aborted key-exhange, so we shouldn't allow anything interesting to happen at the application-layer
                    break;

                default:
                    SN_ErrPrintf("first message from node in Awaiting_finalise state should be a finalise. it was a %d. dropping.\n", message->type);
                    return -SN_ERR_INVALID;
            }
            break;

        case SN_Send_finalise:
            //be permissive and treat Send_finalise as Associated. we have the key, after all
        case SN_Associated:
            break;

        default:
            assert(0); //something horrible has happened
            SN_ErrPrintf("how did table_entry.state become %d?!?\n", table_entry.state);
            return -SN_ERR_UNEXPECTED;
    }} //there are two of these because of the brace opened earlier. pay attention

    /* if we receive an unencrypted packet from an associated communications
     * partner, it must be processed in restricted mode
     */
    if(!was_encrypted && !restricted) {
        SN_WarnPrintf("received unencrypted message. performing only restricted processing.\n");
        restricted = 1;
    }

    for(message_count = 0; payload_position < packet.MCPS_DATA_indication.msduLength; message_count++) {
        SN_Message_internal_t* message = (SN_Message_internal_t*)(packet.MCPS_DATA_indication.msdu + payload_position);

        int message_network_size = SN_Message_internal_size(message);
        int message_memory_size  = SN_Message_memory_size((SN_Message_t*)message); //XXX: safe by inspection
        if(message_network_size < 0) {
            SN_ErrPrintf("size calculation of message %d failed with %d\n", message_count, -message_network_size);
            return message_network_size;
        }
        assert(message_memory_size > 0);

        SN_InfoPrintf("decoding message %d (whose type is %x, memory size is %d, and network size is %d)\n", message_count, message->type, message_memory_size, message_network_size);
        if(payload_position + message_network_size > packet.MCPS_DATA_indication.msduLength) {
            SN_ErrPrintf("message %d size %d would overflow the %d-length packet\n", message_count, message_network_size, packet.MCPS_DATA_indication.msduLength);
            return -SN_ERR_END_OF_DATA;
        }
        if(buffer_position + message_memory_size > *buffer_size) {
            SN_ErrPrintf("message %d size %d would overflow the %d-length buffer\n", message_count, message_network_size, *buffer_size);
            return -SN_ERR_RESOURCES;
        }

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
                    break;

                default:
                    SN_ErrPrintf("without a security association, only association, addressing, and evidence messages allowed.\n");
                    return -SN_ERR_DISALLOWED;
            }
        }

        SN_Message_t* decoded_message = (SN_Message_t*)(((char*)buffer) + buffer_position);
        int generated_upwards_message = 0;
        switch(message->type) {
            case SN_Associate_request:
            case SN_Associate_reply:
            case SN_Associate_finalise:
                //this is an error
                SN_ErrPrintf("association message occurred out of order\n");
                return -SN_ERR_INVALID;

            case SN_Dissociate_request: {
                //if it wasn't encrypted, do a signature check
                struct __attribute__((packed)) {
                    SN_Address_t remote_node;
                    uint8_t      message_type;
                } signature_data = {
                    .remote_node = {
                        .type = packet.MCPS_DATA_indication.DstAddrMode,
                        .address = packet.MCPS_DATA_indication.DstAddr,
                    },
                    .message_type = message->type,
                };
                if(SN_Crypto_verify(&table_entry.public_key, (uint8_t*)&signature_data, sizeof(signature_data), &message->dissociate_request.signature) != SN_OK) {
                    //signature verification failed, abort
                    SN_ErrPrintf("signature verification failed on out-of-tunnel disconnect message\n");
                    return -SN_ERR_SIGNATURE;
                }

                //clear relationship state from node table
                table_entry.relationship = 0;
                SN_Table_update(&table_entry);

                //notify higher layer
                decoded_message->type = SN_Dissociate_request;
                generated_upwards_message = 1;
                } break;

            case SN_Address_request:
                //mark requestor as adjacent
                table_entry.is_neighbor = 1;

                //TODO: SN_Address_request

                //update neighbor table
                SN_Table_update(&table_entry);
                break;

            case SN_Address_release:
                //TODO: SN_Address_release
                break;

            case SN_Address_grant:
                //error-check: src_addr is our parent
                if(
                        (session->nib.parent_address.type == mac_short_address && session->nib.parent_address.address.ShortAddress != table_entry.short_address)
                        ||
                        (session->nib.parent_address.type == mac_extended_address && memcmp(session->nib.parent_address.address.ExtendedAddress, table_entry.long_address.ExtendedAddress, sizeof(session->nib.parent_address.address)) != 0)
                  ) {
                    SN_ErrPrintf("address-grant received from non-parent. aborting\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //error-check: we don't have a short address
                if(session->mib.macShortAddress != SN_NO_SHORT_ADDRESS) {
                    //we already have an address; error
                    SN_ErrPrintf("received address grant when we already have an address\n");
                    //TODO: should this be an error? should we just send a release of the old address in response?
                    return -SN_ERR_INVALID;
                } else {
                    //incoming valid grant, treat appropriately
                    SN_InfoPrintf("we've been granted address %#06x\n", message->address_grant.address);

                    //warning-check: if it's a block, and we're not routing
                    if(!session->nib.enable_routing && message->address_grant.block_size > 0) {
                        SN_WarnPrintf("non-routing node has received address block. strange...\n");
                    }

                    //set our short address
                    session->mib.macShortAddress = message->address_grant.address;
                    mac_primitive_t primitive;
                    primitive.type = mac_mlme_set_request;
                    primitive.MLME_SET_request.PIBAttribute         = macShortAddress;
                    primitive.MLME_SET_request.PIBAttributeSize     = 2;
                    memcpy(primitive.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
                    MAC_CALL(mac_transmit, session->mac_session, &primitive);
                    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

                    //TODO: do something with block size
                }
                break;

            case SN_Address_revoke:
                //error-check: src_addr is our parent
                if(
                        (session->nib.parent_address.type == mac_short_address && session->nib.parent_address.address.ShortAddress != table_entry.short_address)
                        ||
                        (session->nib.parent_address.type == mac_extended_address && memcmp(session->nib.parent_address.address.ExtendedAddress, table_entry.long_address.ExtendedAddress, sizeof(session->nib.parent_address.address)) != 0)
                  ) {
                    SN_ErrPrintf("address-grant received from non-parent. aborting\n");
                    return -SN_ERR_UNEXPECTED;
                }

                //error-check: we have a short address
                if(session->mib.macShortAddress == SN_NO_SHORT_ADDRESS) {
                    //we already have an address; error. might be a retransmission
                    SN_WarnPrintf("received address revoke when we don't have an address\n");
                } else {
                    //incoming valid revoke, treat appropriately
                    SN_InfoPrintf("we're having address %#06x revoked\n", session->mib.macShortAddress);

                    //set our short address
                    session->mib.macShortAddress = SN_NO_SHORT_ADDRESS;
                    mac_primitive_t primitive;
                    primitive.type = mac_mlme_set_request;
                    primitive.MLME_SET_request.PIBAttribute         = macShortAddress;
                    primitive.MLME_SET_request.PIBAttributeSize     = 2;
                    memcpy(primitive.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
                    MAC_CALL(mac_transmit, session->mac_session, &primitive);
                    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

                    //TODO: revoke children, and change their neighbor table entries
                }
                break;

            case SN_Address_change_notify:
                //error-check: src_addr should be long-form
                if(!src_addr->type == mac_extended_address) {
                    SN_ErrPrintf("received address_inform from short address, which is invalid. aborting.\n");
                    return -SN_ERR_INVALID;
                }

                //update neighbor table
                table_entry.short_address = message->address_message.address;
                SN_Table_update(&table_entry);
                break;

            case SN_Node_details: {
                //check: one of the addresses in the message should match the source address
                if(src_addr->type == mac_short_address) {
                    if(memcmp(&src_addr->address.ShortAddress, &message->node_details.short_address, 2)) {
                        SN_ErrPrintf("received node_details message about someone else...\n");
                        return -SN_ERR_DISALLOWED;
                    }
                } else {
                    if(memcmp(src_addr->address.ExtendedAddress, message->node_details.long_address.ExtendedAddress, 8)) {
                        SN_ErrPrintf("received node_details message about someone else...\n");
                        return -SN_ERR_DISALLOWED;
                    }
                }

                //check: if we already know the remote node's public key, only accept a new one if it was integrity-checked
                SN_Public_key_t null_key = {};
                if(!was_encrypted && memcmp(&table_entry.public_key, &null_key, sizeof(null_key)) && memcmp(&table_entry.public_key, &message->node_details.public_key, sizeof(message->node_details.public_key))) {
                    SN_ErrPrintf("received unprotected node_details message attempting to install new public key. this seems suspect...\n");
                    return -SN_ERR_DISALLOWED;
                }

                //update neighbor table
                table_entry.short_address = message->node_details.short_address;
                table_entry.long_address  = message->node_details.long_address;
                table_entry.public_key    = message->node_details.public_key;
                SN_Table_update(&table_entry);
                } break;

            case SN_Authentication_message: {
                //check: do we know remote node's signing key?
                SN_Public_key_t null_key = {};
                if(!memcpy(&null_key, &table_entry.public_key, sizeof(null_key))) {
                    SN_WarnPrintf("remote node's public key is unknown. ignoring authentication message...\n");
                } else {
                    //do authentication check
                    if(SN_Crypto_verify(&table_entry.public_key, table_entry.key_agreement_key.data, sizeof(table_entry.key_agreement_key.data), &message->authentication_message.signature) == SN_OK) {
                        //update neighbor table
                        table_entry.authenticated = 1;
                        SN_Table_update(&table_entry);
                    } else {
                        SN_WarnPrintf("signature verification failed. node is still unauthenticated.\n");
                    }
                }
                decoded_message->type = SN_Authentication_message;
                generated_upwards_message = 1;
                } break;

            case SN_Evidence_message:
                //copy certificate into node storage
                SN_Crypto_add_certificate(cert_storage, &message->evidence.evidence);
                //ignoring any errors thrown by add_certificate, because we're passing the certificate up anyway
            default:
                //necessarily, message_network_size == message_memory_size
                memcpy(decoded_message, message, message_network_size);
                generated_upwards_message = 1;
                break;
        }

        if(generated_upwards_message) {
            int sz = SN_Message_memory_size(decoded_message);
            SN_InfoPrintf("generated upwards message of size %d\n", sz);
            assert(sz > 0);
            buffer_position += sz;
        } else {
            SN_InfoPrintf("not generating upwards message\n");
        }
        payload_position += message_network_size;
    }

    assert(payload_position == packet.MCPS_DATA_indication.msduLength);

    *buffer_size = message_count;

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
