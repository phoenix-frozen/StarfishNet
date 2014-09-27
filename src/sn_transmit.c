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

#include <polarssl/sha1.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_txrx.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

//send out a datagram
//packet should only have msduLength and msdu filled; everything else is my problem
static int do_packet_transmission(SN_Session_t* session, SN_Table_entry_t* table_entry, bool acknowledged, mac_primitive_t* packet) {
    SN_InfoPrintf("enter\n");

    static uint8_t packet_handle = 1;

    if(packet_handle == 0) {
        packet_handle++;
    }

    uint8_t max_payload_size = aMaxMACPayloadSize - 2;
    /* aMaxMACPayloadSize is for a packet with a short destination address, and no source addressing
     * information. we always send a source address, which is at least 2 byte long
     */

    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    packet->type                         = mac_mcps_data_request;
    packet->MCPS_DATA_request.SrcPANId   = session->mib.macPANId;
    //packet->MCPS_DATA_request.SrcAddr     is filled below
    //packet->MCPS_DATA_request.SrcAddrMode is filled below
    packet->MCPS_DATA_request.DstPANId   = session->mib.macPANId;
    //packet->MCPS_DATA_request.DstAddr     is filled below
    //packet->MCPS_DATA_request.DstAddrMode is filled below
    packet->MCPS_DATA_request.msduHandle = packet_handle;
    packet->MCPS_DATA_request.TxOptions  = (uint8_t)(acknowledged ? MAC_TX_OPTION_ACKNOWLEDGED : 0);
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
        SN_DebugPrintf("sending from our long address, %#018lx\n", *(uint64_t*)session->mib.macIEEEAddress.ExtendedAddress);
        packet->MCPS_DATA_request.SrcAddrMode = mac_extended_address;
        packet->MCPS_DATA_request.SrcAddr     = session->mib.macIEEEAddress;
        max_payload_size -= 6; //header size increases by 6 bytes if we're using a long address
    }

    //DstAddr
    if(table_entry->short_address != SN_NO_SHORT_ADDRESS) {
        SN_DebugPrintf("sending to short address %#06x\n", table_entry->short_address);
        packet->MCPS_DATA_request.DstAddrMode          = mac_short_address;
        packet->MCPS_DATA_request.DstAddr.ShortAddress = table_entry->short_address;
    } else {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("sending to long address %#018lx\n", *(uint64_t*)table_entry->long_address.ExtendedAddress);
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
    //      (hint: that also means retransmission logic)
    const uint8_t tx_confirm[] = {mac_mcps_data_confirm, packet_handle, mac_success};
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

//argument note: margin means the amount of data to skip (after the network header, before the payload) for encryption
static int encrypt_authenticate_packet(SN_Table_entry_t* table_entry, uint8_t margin, mac_primitive_t* packet) {
    SN_DebugPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header_t* encryption_header = (encryption_header_t*)(packet->MCPS_DATA_request.msdu + margin);
    const size_t skip_size = margin + sizeof(encryption_header_t);
    if(packet->MCPS_DATA_request.msduLength < skip_size) {
        SN_ErrPrintf("cannot encrypt packet of length %d with a margin of %d\n", packet->MCPS_DATA_request.msduLength, margin);
        return -SN_ERR_END_OF_DATA;
    }

    int ret = SN_Crypto_encrypt(&table_entry->link_key.key, &table_entry->link_key.key_id, encryption_header->counter,
        packet->MCPS_DATA_request.msdu, margin,
        packet->MCPS_DATA_request.msdu + skip_size,
        packet->MCPS_DATA_request.msduLength - skip_size,
        encryption_header->tag);
    if(ret != SN_OK) {
        SN_ErrPrintf("Packet encryption failed with %d, aborting\n", -ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("payload encryption complete\n");

    //TODO: rekeying

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int generate_packet_headers(SN_Session_t* session, SN_Table_entry_t* table_entry, uint8_t* crypto_margin, mac_primitive_t* packet) {
    SN_DebugPrintf("enter\n");

    if(session == NULL || table_entry == NULL || packet == NULL || crypto_margin == NULL) {
        SN_ErrPrintf("session, table_entry, crypto_margin, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    *crypto_margin = 0;

    network_header_t* header = (network_header_t*)packet->MCPS_DATA_request.msdu;
    if(packet->MCPS_DATA_request.msduLength != sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header, aborting\n");
        return -SN_ERR_END_OF_DATA;
    }
    *crypto_margin += sizeof(network_header_t);

    //node_details_header_t
    if(header->details) {
        SN_InfoPrintf("generating node details header\n");
        if(packet->MCPS_DATA_request.msduLength + sizeof(node_details_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        node_details_header_t* node_details =
                                 (node_details_header_t*)(packet->MCPS_DATA_request.msdu +
                                                          packet->MCPS_DATA_request.msduLength
                                 );
        packet->MCPS_DATA_request.msduLength += sizeof(node_details_header_t);
        *crypto_margin += sizeof(node_details_header_t);

        node_details->signing_key = session->device_root_key.public_key;
    }

    //association_request_header_t
    if(header->associate) {
        SN_InfoPrintf("generating association header\n");
        if(packet->MCPS_DATA_request.msduLength + sizeof(association_request_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        association_request_header_t* association_header =
                                        (association_request_header_t*)(packet->MCPS_DATA_request.msdu +
                                                                        packet->MCPS_DATA_request.msduLength
                                        );
        packet->MCPS_DATA_request.msduLength += sizeof(association_request_header_t);
        *crypto_margin += sizeof(association_request_header_t);

        association_header->flags             = 0;
        association_header->key_agreement_key = table_entry->local_key_agreement_keypair.public_key;
        association_header->router            = session->nib.enable_routing;
        association_header->child =
            memcmp(
                session->nib.parent_public_key.data,
                table_entry->public_key.data,
                sizeof(session->nib.parent_public_key.data)
            ) == 0 ? (uint8_t)1 : (uint8_t)0;
    }

    //key_confirmation_header_t
    if(header->key_confirm) {
        SN_InfoPrintf("generating key confirmation header (challenge%d)\n", header->associate ? 1 : 2);
        if(packet->MCPS_DATA_request.msduLength + sizeof(key_confirmation_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        key_confirmation_header_t* key_confirmation_header =
                                     (key_confirmation_header_t*)(packet->MCPS_DATA_request.msdu +
                                                                  packet->MCPS_DATA_request.msduLength
                                     );
        packet->MCPS_DATA_request.msduLength += sizeof(key_confirmation_header_t);
        *crypto_margin += sizeof(key_confirmation_header_t);

        if(header->associate) {
            //this is a reply; do challenge1 (double-hash)
            SN_Hash_t hashbuf;
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), hashbuf.data);
            sha1(hashbuf.data, sizeof(hashbuf.data), key_confirmation_header->challenge.data);
            SN_DebugPrintf("challenge1 = %#18llx%16llx%08lx\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        } else {
            //this is a finalise; do challenge2 (single-hash)
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), key_confirmation_header->challenge.data);
            SN_DebugPrintf("challenge2 = %#18llx%16llx%08lx\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        }
    }

    //TODO: address_allocation_header_t

    if(header->encrypt) {
        SN_InfoPrintf("generating encryption header\n");
        if(packet->MCPS_DATA_request.msduLength + sizeof(encryption_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        encryption_header_t* encryption_header =
                               (encryption_header_t*)(packet->MCPS_DATA_request.msdu +
                                                      packet->MCPS_DATA_request.msduLength
                               );
        packet->MCPS_DATA_request.msduLength += sizeof(encryption_header_t);

        encryption_header->counter = table_entry->packet_tx_count++;
    } else {
        SN_InfoPrintf("generating signature header\n");

        if(packet->MCPS_DATA_request.msduLength + sizeof(signature_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        signature_header_t* signature_header =
                              (signature_header_t*)(packet->MCPS_DATA_request.msdu +
                                                    packet->MCPS_DATA_request.msduLength
                              );
        packet->MCPS_DATA_request.msduLength += sizeof(signature_header_t);

        /*XXX: warning, assumes signature header is at the end of the header block
         */
        if(SN_Crypto_sign(
            &session->device_root_key.private_key,
            packet->MCPS_DATA_request.msdu,
            packet->MCPS_DATA_request.msduLength - sizeof(signature_header_t),
            &signature_header->signature) != SN_OK) {
            SN_ErrPrintf("could not sign packet\n");
            return -SN_ERR_SIGNATURE;
        }
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int generate_payload(SN_Message_t* message, mac_primitive_t* packet) {
    switch(message->type) {
        case SN_Data_message:
            if(packet->MCPS_DATA_request.msduLength + message->data_message.payload_length > aMaxMACPayloadSize) {
                SN_ErrPrintf("data packet is too large, at %d bytes (maximum length is %d bytes)\n",
                    packet->MCPS_DATA_request.msduLength + message->data_message.payload_length, aMaxMACPayloadSize);
                return -SN_ERR_RESOURCES;
            }
            memcpy(
                packet->MCPS_DATA_request.msdu + packet->MCPS_DATA_request.msduLength,
                message->data_message.payload,
                message->data_message.payload_length
            );
            packet->MCPS_DATA_request.msduLength += message->data_message.payload_length;
            break;

        case SN_Evidence_message:
            if(packet->MCPS_DATA_request.msduLength + sizeof(SN_Certificate_t) > aMaxMACPayloadSize) {
                SN_ErrPrintf("evidence packet is too large, at %zu bytes (maximum length is %d bytes)\n",
                    packet->MCPS_DATA_request.msduLength + sizeof(SN_Certificate_t), aMaxMACPayloadSize);
                return -SN_ERR_RESOURCES;
            }
            *(SN_Certificate_t*)(packet->MCPS_DATA_request.msdu + packet->MCPS_DATA_request.msduLength) =
                message->evidence_message.evidence;
            packet->MCPS_DATA_request.msduLength += sizeof(SN_Certificate_t);
            break;

        default:
            SN_ErrPrintf("invalid message type %d, aborting\n", message->type);
            return -SN_ERR_INVALID;
    }

    return SN_OK;
}

//transmit packet, containing one or more messages
int SN_Send(SN_Session_t* session, SN_Address_t* dst_addr, SN_Message_t* message) {
    //initial NULL-checks
    if(session == NULL || dst_addr == NULL) {
        SN_ErrPrintf("session, dst_addr, and buffer must all be valid\n");
        return -SN_ERR_NULL;
    }

    //validity check on address
    mac_address_t null_address = {.ExtendedAddress = {}};
    if((dst_addr->type == mac_short_address && dst_addr->address.ShortAddress == SN_NO_SHORT_ADDRESS) ||
       (dst_addr->type == mac_extended_address && memcmp(
           dst_addr->address.ExtendedAddress,
           null_address.ExtendedAddress,
           sizeof(null_address)) == 0
       )) {
        SN_ErrPrintf("attempting to send to null address. aborting\n");
        return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
        .session       = session,
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    int              ret         = SN_Table_lookup_by_address(dst_addr, &table_entry, NULL);
    if(ret != SN_OK || table_entry.state < SN_Send_finalise) { //node isn't in node table, abort
        SN_ErrPrintf("no relationship with remote node. aborting\n");
        return -SN_ERR_SECURITY;
    }

    //actual packet buffer
    mac_primitive_t primitive;

    //network header
    SN_InfoPrintf("generating network header...\n");
    network_header_t* header = (network_header_t*)primitive.MCPS_DATA_request.msdu;
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    //TODO: routing/addressing
    header->src_addr                       = SN_NO_SHORT_ADDRESS;
    header->dst_addr                       = SN_NO_SHORT_ADDRESS;
    //attributes
    header->attributes                     = 0;
    header->encrypt                        = 1;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Send_finalise);
    header->evidence                       = (uint8_t)(message != NULL && message->type == SN_Evidence_message);
    //update packet
    primitive.MCPS_DATA_request.msduLength = sizeof(network_header_t);

    if(header->key_confirm) {
        table_entry.state = SN_Associated;
    }
    if(header->details) {
        table_entry.knows_details = 1;
    }

    SN_InfoPrintf("generating subheaders...\n");
    uint8_t crypto_margin = 0;
    ret = generate_packet_headers(session, &table_entry, &crypto_margin, &primitive);
    if(ret != SN_OK) {
        SN_ErrPrintf("header generation failed with %d\n", -ret);
        return ret;
    }

    if(message != NULL) {
        SN_InfoPrintf("generating payload...\n");
        ret = generate_payload(message, &primitive);
        if(ret != SN_OK) {
            SN_ErrPrintf("payload generation failed with %d\n", -ret);
            return ret;
        }
        SN_InfoPrintf("packet data generation complete\n");
    } else {
        SN_WarnPrintf("no payload to generate\n");
    }

    SN_InfoPrintf("beginning packet crypto...\n");
    ret = encrypt_authenticate_packet(&table_entry, crypto_margin, &primitive);
    if(ret != SN_OK) {
        SN_ErrPrintf("packet crypto failed with %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = do_packet_transmission(session, &table_entry, 0, &primitive);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    //we've changed the table entry. update it
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Associate(SN_Session_t* session, SN_Address_t* dst_addr, SN_Message_t* message) {
    //initial NULL-checks
    if(session == NULL || dst_addr == NULL) {
        SN_ErrPrintf("session, dst_addr, and buffer must all be valid\n");
        return -SN_ERR_NULL;
    }

    //validity check on address
    mac_address_t null_address = {.ExtendedAddress = {}};
    if((dst_addr->type == mac_short_address && dst_addr->address.ShortAddress == SN_NO_SHORT_ADDRESS) ||
       (dst_addr->type == mac_extended_address && memcmp(
           dst_addr->address.ExtendedAddress,
           null_address.ExtendedAddress,
           sizeof(null_address)) == 0
       )) {
        SN_ErrPrintf("attempting to send to null address. aborting\n");
        return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
        .session       = session,
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    int              ret         = SN_Table_lookup_by_address(dst_addr, &table_entry, NULL);
    if(ret != SN_OK) {
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(dst_addr->type == mac_short_address) {
            table_entry.short_address = dst_addr->address.ShortAddress;
        } else {
            table_entry.long_address = dst_addr->address;
        }

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table, aborting.\n");
            return -SN_ERR_RESOURCES;
        }
    }

    //actual packet buffer
    mac_primitive_t primitive;

    //network header
    SN_InfoPrintf("generating network header...\n");
    network_header_t* header = (network_header_t*)primitive.MCPS_DATA_request.msdu;
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    //TODO: routing/addressing
    header->src_addr                       = SN_NO_SHORT_ADDRESS;
    header->dst_addr                       = SN_NO_SHORT_ADDRESS;
    //attributes
    header->attributes                     = 0;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->associate                      = 1;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Associate_received);
    header->encrypt                        = 0;
    header->evidence                       = 1;
    //update packet
    primitive.MCPS_DATA_request.msduLength = sizeof(network_header_t);

    //we've now sent our details; record this fact
    if(header->details) {
        table_entry.knows_details = 1;
    }

    //check the association state, and do appropriate crypto work
    switch(table_entry.state) {
        case SN_Unassociated:
            SN_InfoPrintf("no relationship. generating ECDH keypair\n");

            //generate ephemeral keypair
            if(SN_Crypto_generate_keypair(&table_entry.local_key_agreement_keypair) != SN_OK) {
                SN_ErrPrintf("error during key generation, aborting send\n");
                return -SN_ERR_KEYGEN;
            }

            //advance state
            table_entry.state = SN_Awaiting_reply;
            break;

        case SN_Associate_received:
            SN_InfoPrintf("received association request, finishing ECDH\n");

            //generate ephemeral keypair
            if(SN_Crypto_generate_keypair(&table_entry.local_key_agreement_keypair) != SN_OK) {
                SN_ErrPrintf("error during key generation, aborting send\n");
                return -SN_ERR_KEYGEN;
            }

            //do ECDH math
            if(SN_Crypto_key_agreement(
                &table_entry.remote_key_agreement_key,
                &table_entry.local_key_agreement_keypair.private_key,
                &table_entry.link_key
            ) != SN_OK) {
                SN_ErrPrintf("error during key agreement, aborting send\n");
                return -SN_ERR_KEYGEN;
            }

            //advance state
            table_entry.state = SN_Awaiting_finalise;
            break;

        default:
            SN_ErrPrintf("association requests are only valid in state SN_Associated or SN_Association_received. we are in %d\n", table_entry.state);
            return -SN_ERR_UNEXPECTED;
    }

    //generate subheaders
    SN_InfoPrintf("generating subheaders...\n");
    uint8_t crypto_margin = 0;
    ret = generate_packet_headers(session, &table_entry, &crypto_margin, &primitive);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in header generation\n", -ret);
        return ret;
    }

    //do data stapling
    if(message != NULL) {
        SN_InfoPrintf("generating stapled data...\n");

        if(message->type == SN_Data_message) {
            SN_ErrPrintf("cannot staple plain data to associate message\n");
            return -SN_ERR_INVALID;
        }

        ret = generate_payload(message, &primitive);
        if(ret != SN_OK) {
            SN_ErrPrintf("payload generation failed with %d\n", -ret);
            return ret;
        }

        SN_InfoPrintf("stapled data generation complete\n");
    } else {
        SN_InfoPrintf("no data to staple\n");
    }

    if(header->encrypt) {
        SN_InfoPrintf("encrypting packet...\n");
        ret = encrypt_authenticate_packet(&table_entry, crypto_margin, &primitive);
        if(ret != SN_OK) {
            SN_ErrPrintf("packet crypto failed with %d\n", -ret);
            return ret;
        }
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = do_packet_transmission(session, &table_entry, 0, &primitive);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    //update node table
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
