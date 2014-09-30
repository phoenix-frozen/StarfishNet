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
#include <assert.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_txrx.h"
#include "sn_delayed_tx.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

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

static int generate_packet_headers(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet) {
    SN_DebugPrintf("enter\n");

    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, crypto_margin, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    packet->packet_layout.crypto_margin = 0;

    network_header_t* network_header = PACKET_HEADER(*packet, network, request);
    if(PACKET_SIZE(*packet, request) != sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header, aborting\n");
        return -SN_ERR_END_OF_DATA;
    }
    packet->packet_layout.crypto_margin += sizeof(network_header_t);

    //node_details_header_t
    if(network_header->details) {
        SN_InfoPrintf("generating node details header\n");
        if(PACKET_SIZE(*packet, request) + sizeof(node_details_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        node_details_header_t* node_details_header =
                                 (node_details_header_t*)(packet->packet_data.MCPS_DATA_request.msdu +
                                                          PACKET_SIZE(*packet, request)
                                 );
        PACKET_HEADER(*packet, node_details, request) = node_details_header;
        PACKET_SIZE(*packet, request) += sizeof(node_details_header_t);

        packet->packet_layout.crypto_margin += sizeof(node_details_header_t);

        node_details_header->signing_key = session->device_root_key.public_key;
    }

    //association_header_t
    if(network_header->associate) {
        SN_InfoPrintf("generating association header\n");
        if(PACKET_SIZE(*packet, request) + sizeof(association_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        association_header_t* association_header =
                                        (association_header_t*)(packet->packet_data.MCPS_DATA_request.msdu +
                                                                        PACKET_SIZE(*packet, request)
                                        );
        PACKET_HEADER(*packet, association, request) = association_header;
        PACKET_SIZE(*packet, request) += sizeof(association_header_t);

        packet->packet_layout.crypto_margin += sizeof(association_header_t);

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
    if(network_header->key_confirm) {
        SN_InfoPrintf("generating key confirmation header (challenge%d)\n", network_header->associate ? 1 : 2);
        if(PACKET_SIZE(*packet, request) + sizeof(key_confirmation_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        key_confirmation_header_t* key_confirmation_header =
                                     (key_confirmation_header_t*)(packet->packet_data.MCPS_DATA_request.msdu +
                                                                  PACKET_SIZE(*packet, request)
                                     );
        PACKET_HEADER(*packet, key_confirmation, request) = key_confirmation_header;
        PACKET_SIZE(*packet, request) += sizeof(key_confirmation_header_t);
        packet->packet_layout.crypto_margin += sizeof(key_confirmation_header_t);

        if(network_header->associate) {
            //this is a reply; do challenge1 (double-hash)
            SN_Hash_t hashbuf;
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), hashbuf.data);
            sha1(hashbuf.data, sizeof(hashbuf.data), key_confirmation_header->challenge.data);
            SN_DebugPrintf("challenge1 = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        } else {
            //this is a finalise; do challenge2 (single-hash)
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), key_confirmation_header->challenge.data);
            SN_DebugPrintf("challenge2 = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        }
    }

    //TODO: address_allocation[_block]_header_t
    //TODO: {encrypted,signed}_ack_header_t

    if(network_header->encrypt) {
        SN_InfoPrintf("generating encryption header\n");
        if(PACKET_SIZE(*packet, request) + sizeof(encryption_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        encryption_header_t* encryption_header =
                               (encryption_header_t*)(packet->packet_data.MCPS_DATA_request.msdu +
                                                      PACKET_SIZE(*packet, request)
                               );
        PACKET_HEADER(*packet, encryption, request) = encryption_header;
        PACKET_SIZE(*packet, request) += sizeof(encryption_header_t);

        encryption_header->counter = table_entry->packet_tx_count++;
    } else {
        SN_InfoPrintf("generating signature header\n");

        if(PACKET_SIZE(*packet, request) + sizeof(signature_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        signature_header_t* signature_header =
                              (signature_header_t*)(packet->packet_data.MCPS_DATA_request.msdu +
                                                    PACKET_SIZE(*packet, request)
                              );
        PACKET_HEADER(*packet, signature, request) = signature_header;
        PACKET_SIZE(*packet, request) += sizeof(signature_header_t);

        /*XXX: warning, assumes signature header is at the end of the header block
         */
        if(SN_Crypto_sign(
            &session->device_root_key.private_key,
            packet->packet_data.MCPS_DATA_request.msdu,
            PACKET_SIZE(*packet, request) - sizeof(signature_header_t),
            &signature_header->signature) != SN_OK) {
            SN_ErrPrintf("could not sign packet\n");
            return -SN_ERR_SIGNATURE;
        }
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int generate_payload(SN_Message_t* message, packet_t* packet) {
    assert(message != NULL);

    uint8_t* packet_data = packet->packet_data.MCPS_DATA_request.msdu + PACKET_SIZE(*packet, request);
    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

    switch(message->type) {
        case SN_Data_message:
            SN_InfoPrintf("generating data payload\n");
            payload = message->data_message.payload;
            payload_length = message->data_message.payload_length;
            break;

        case SN_Evidence_message:
            SN_InfoPrintf("generating evidence payload\n");
            payload = (uint8_t*)&message->evidence_message.evidence;
            payload_length = sizeof(SN_Certificate_t);
            break;

        default:
            SN_ErrPrintf("invalid message type %d, aborting\n", message->type);
            return -SN_ERR_INVALID;
    }

    if(PACKET_SIZE(*packet, request) + payload_length > aMaxMACPayloadSize) {
        SN_ErrPrintf("packet is too large, at %d bytes (maximum length is %d bytes)\n",
            PACKET_SIZE(*packet, request) + payload_length, aMaxMACPayloadSize);
        return -SN_ERR_RESOURCES;
    }

    assert(payload != NULL);

    packet->packet_layout.payload_length = payload_length;
    if(payload_length > 0) {
        PACKET_DATA(*packet, request) = packet->packet_data.MCPS_DATA_request.msdu + PACKET_SIZE(*packet, request);
        PACKET_SIZE(*packet, request) += payload_length;
        memcpy(packet_data, payload, payload_length);
    } else {
        SN_WarnPrintf("no payload to generate\n");
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
    packet_t packet;
    memset(&packet.packet_layout, 0, sizeof(packet.packet_layout));

    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.packet_layout.network_header    = (network_header_t*)packet.packet_data.MCPS_DATA_request.msdu;
    network_header_t* header               = PACKET_HEADER(packet, network, request);
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
    PACKET_SIZE(packet, request) = sizeof(network_header_t);

    if(header->key_confirm) {
        table_entry.state = SN_Associated;
    }
    if(header->details) {
        table_entry.knows_details = 1;
    }

    SN_InfoPrintf("generating subheaders...\n");
    ret = generate_packet_headers(session, &table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("header generation failed with %d\n", -ret);
        return ret;
    }

    if(message != NULL) {
        SN_InfoPrintf("generating payload...\n");
        ret = generate_payload(message, &packet);
        if(ret != SN_OK) {
            SN_ErrPrintf("payload generation failed with %d\n", -ret);
            return ret;
        }
        SN_InfoPrintf("packet data generation complete\n");
    } else {
        SN_WarnPrintf("no payload to generate\n");
    }

    SN_InfoPrintf("beginning packet crypto...\n");
    ret = encrypt_authenticate_packet(&table_entry, packet.packet_layout.crypto_margin, &packet.packet_data);
    if(ret != SN_OK) {
        SN_ErrPrintf("packet crypto failed with %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = SN_Delayed_transmit(session, &table_entry, &packet);
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
    packet_t packet;
    memset(&packet.packet_layout, 0, sizeof(packet.packet_layout));

    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.packet_layout.network_header    = (network_header_t*)packet.packet_data.MCPS_DATA_request.msdu;
    network_header_t* header               = PACKET_HEADER(packet, network, request);
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
    PACKET_SIZE(packet, request) = sizeof(network_header_t);

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
    ret = generate_packet_headers(session, &table_entry, &packet);
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

        ret = generate_payload(message, &packet);
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
        ret = encrypt_authenticate_packet(&table_entry, packet.packet_layout.crypto_margin, &packet.packet_data);
        if(ret != SN_OK) {
            SN_ErrPrintf("packet crypto failed with %d\n", -ret);
            return ret;
        }
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = SN_Delayed_transmit(session, &table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    //update node table
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
