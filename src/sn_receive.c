//StarfishNet message transmission rules are in sn_transmit.c

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
        sha1_update(&hashctx, (uint8_t*)&header->crypto.counter, sizeof(header->crypto.counter));
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
                if(!was_encrypted) {
                    struct __attribute__((packed)) {
                        uint16_t     counter;
                        SN_Address_t remote_node;
                        uint8_t      message_type;
                    } signature_data = {
                            .remote_node = {
                                    .type    = packet.MCPS_DATA_indication.DstAddrMode,
                                    .address = packet.MCPS_DATA_indication.DstAddr,
                            },
                            .message_type = message->type,
                            .counter      = header->crypto.counter,
                    };
                    if(SN_Crypto_verify(&table_entry.public_key, (uint8_t*)&signature_data, sizeof(signature_data), &message->dissociate_request.signature) != SN_OK) {
                        //signature verification failed, abort
                        SN_ErrPrintf("signature verification failed on out-of-tunnel disconnect message\n");
                        return -SN_ERR_SIGNATURE;
                    }
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
