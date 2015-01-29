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
#include <inttypes.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_packet.h"
#include "sn_delayed_tx.h"
#include "sn_routing_tree.h"
#include "sn_beacons.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

//argument note: margin means the amount of data to skip (after the network header, before the payload) for encryption
static int encrypt_authenticate_packet(SN_AES_key_t* link_key, SN_Public_key_t* key_agreement_key, uint32_t encryption_counter, packet_t* packet, bool pure_ack) {
    SN_DebugPrintf("enter\n");

    if(link_key == NULL || key_agreement_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, key_agreement_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header_t* encryption_header = PACKET_ENTRY(*packet, encryption_header, request);
    assert(encryption_header != NULL);
    const size_t skip_size = packet->layout.encryption_header + sizeof(encryption_header_t);
    if(PACKET_SIZE(*packet, request) < skip_size) {
        SN_ErrPrintf("cannot encrypt packet of length %d with an encryption header at %d\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header);
        return -SN_ERR_END_OF_DATA;
    }

    SN_InfoPrintf("encrypting packet of length %d with an encryption header at %d (counter = %x)\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header, encryption_counter);

    int ret = SN_Crypto_encrypt(link_key, key_agreement_key,
        encryption_counter,
        packet->contents.MCPS_DATA_request.msdu, packet->layout.encryption_header,
        packet->contents.MCPS_DATA_request.msdu + skip_size,
        packet->contents.MCPS_DATA_request.msduLength - skip_size,
        encryption_header->tag, pure_ack);
    if(ret != SN_OK) {
        SN_ErrPrintf("Packet encryption failed with %d, aborting\n", -ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("payload encryption complete\n");

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int generate_packet_headers(SN_Session_t* session, SN_Table_entry_t* table_entry, bool dissociate, packet_t* packet) {
    SN_DebugPrintf("enter\n");

    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, crypto_margin, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    network_header_t* network_header = PACKET_ENTRY(*packet, network_header, request);
    if(PACKET_SIZE(*packet, request) != sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header, aborting\n");
        return -SN_ERR_END_OF_DATA;
    }

    //node_details_header_t
    if(network_header->details) {
        SN_InfoPrintf("generating node details header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(node_details_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.node_details_header = PACKET_SIZE(*packet, request);
        packet->layout.present.node_details_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(node_details_header_t);
        node_details_header_t* node_details_header = PACKET_ENTRY(*packet, node_details_header, request);
        assert(node_details_header != NULL);

        node_details_header->signing_key = session->device_root_key.public_key;
    }

    //association_header_t
    if(network_header->associate) {
        SN_InfoPrintf("generating association header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(association_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.association_header = PACKET_SIZE(*packet, request);
        packet->layout.present.association_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(association_header_t);
        association_header_t* association_header = PACKET_ENTRY(*packet, association_header, request);
        assert(association_header != NULL);

        association_header->flags             = 0;
        association_header->dissociate        = (uint8_t)(dissociate ? 1 : 0);

        //key_agreement_header_t
        if(!association_header->dissociate) {
            packet->layout.key_agreement_header = PACKET_SIZE(*packet, request);
            packet->layout.present.key_agreement_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(key_agreement_header_t);
            key_agreement_header_t* key_agreement_header = PACKET_ENTRY(*packet, key_agreement_header, request);
            assert(key_agreement_header != NULL);

            key_agreement_header->key_agreement_key = table_entry->local_key_agreement_keypair.public_key;
        }

        //parent/child handling
        if(!association_header->dissociate) {
            if(network_header->key_confirm) {
                //this is a reply

                //address bits
                association_header->child  = (uint8_t)table_entry->child;
                association_header->router = (uint8_t)table_entry->router;

                //address allocation
                if(association_header->child) {
                    SN_InfoPrintf("node is our child; allocating it an address...\n");

                    bool     block = association_header->router;
                    uint16_t address;

                    int ret = SN_Tree_allocate_address(session, &address, &block);

                    if(ret == SN_OK) {
                        network_header->dst_addr   = address;
                        association_header->router = (uint8_t)(block ? 1 : 0);

                        SN_InfoPrintf("allocated %s address %#06x\n", block ? "router" : "leaf", address);

                        table_entry->short_address = address;
                        ret = SN_Beacon_update(session);
                    } else {
                        SN_WarnPrintf("address allocation failed; proceeding without\n");

                        association_header->child  = 0;
                        association_header->router = 0;
                    }

                    if(ret != SN_OK) {
                        SN_ErrPrintf("address allocation failed: %d\n", -ret);
                        return ret;
                    }
                }
            } else {
                //this is a request
                association_header->router = session->nib.enable_routing;
                association_header->child =
                    memcmp(
                        session->nib.parent_public_key.data,
                        table_entry->public_key.data,
                        sizeof(session->nib.parent_public_key.data)
                    ) == 0 ? (uint8_t)1 : (uint8_t)0;
            }
        }
    }

    //key_confirmation_header_t
    if(network_header->key_confirm) {
        SN_InfoPrintf("generating key confirmation header (challenge%d) at %d\n", network_header->associate ? 1 : 2, PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(key_confirmation_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.key_confirmation_header = PACKET_SIZE(*packet, request);
        packet->layout.present.key_confirmation_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(key_confirmation_header_t);
        key_confirmation_header_t* key_confirmation_header = PACKET_ENTRY(*packet, key_confirmation_header, request);
        assert(key_confirmation_header != NULL);

        if(network_header->associate) {
            //this is a reply; do challenge1 (double-hash)
            SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &key_confirmation_header->challenge, 1);
            SN_DebugPrintf("challenge1 = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        } else {
            //this is a finalise; do challenge2 (single-hash)
            SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &key_confirmation_header->challenge, 0);
            SN_DebugPrintf("challenge2 = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)key_confirmation_header->challenge.data,
                *((uint64_t*)key_confirmation_header->challenge.data + 1),
                *((uint32_t*)key_confirmation_header->challenge.data + 4));
        }
    }

    //{encrypted,signed}_ack_header_t
    if(network_header->ack) {
        if(network_header->encrypt) {
            //encrypted_ack_header_t
            SN_InfoPrintf("generating encrypted-ack header at %d\n", PACKET_SIZE(*packet, request));
            if(PACKET_SIZE(*packet, request) + sizeof(encrypted_ack_header_t) > aMaxMACPayloadSize) {
                SN_ErrPrintf("adding encrypted_ack header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet->layout.encrypted_ack_header = PACKET_SIZE(*packet, request);
            packet->layout.present.encrypted_ack_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(encrypted_ack_header_t);
            encrypted_ack_header_t* encrypted_ack_header = PACKET_ENTRY(*packet, encrypted_ack_header, request);
            assert(encrypted_ack_header != NULL);

            encrypted_ack_header->counter = table_entry->packet_rx_counter - 1;
        } else {
            //signed_ack_header_t
            SN_InfoPrintf("generating signed-ack header at %d\n", PACKET_SIZE(*packet, request));
            if(PACKET_SIZE(*packet, request) + sizeof(signed_ack_header_t) > aMaxMACPayloadSize) {
                SN_ErrPrintf("adding signed_ack header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet->layout.signed_ack_header = PACKET_SIZE(*packet, request);
            packet->layout.present.signed_ack_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(signed_ack_header_t);
            signed_ack_header_t* signed_ack_header = PACKET_ENTRY(*packet, signed_ack_header, request);
            assert(signed_ack_header != NULL);

            (void)signed_ack_header; //shut up CLion

            //TODO: signed_ack_header_t
            SN_ErrPrintf("signed_ack headers not implemented yet\n");
            return -SN_ERR_UNIMPLEMENTED;
        }
    }

    //{encryption,signature}_header_t
    if(network_header->encrypt) {
        SN_InfoPrintf("generating encryption header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(encryption_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.encryption_header = PACKET_SIZE(*packet, request);
        packet->layout.present.encryption_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(encryption_header_t);
        encryption_header_t* encryption_header = PACKET_ENTRY(*packet, encryption_header, request);
        assert(encryption_header != NULL);

        (void)encryption_header; //shut up CLion
    } else {
        SN_InfoPrintf("generating signature header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(signature_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.signature_header = PACKET_SIZE(*packet, request);
        packet->layout.present.signature_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(signature_header_t);
        signature_header_t* signature_header = PACKET_ENTRY(*packet, signature_header, request);
        assert(signature_header != NULL);

        //signs everything before the signature header occurs
        if(SN_Crypto_sign(
            &session->device_root_key.private_key,
            packet->contents.MCPS_DATA_request.msdu,
            packet->layout.signature_header,
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

    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

    switch(message->type) {
        case SN_Data_message:
            payload = message->data_message.payload;
            payload_length = message->data_message.payload_length;
            break;

        case SN_Evidence_message:
            payload = (uint8_t*)&message->evidence_message.evidence;
            payload_length = sizeof(SN_Certificate_t);
            break;

        default:
            SN_ErrPrintf("invalid message type %d, aborting\n", message->type);
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("generating %s payload at %d (%d bytes)\n", message->type == SN_Data_message ? "data" : "evidence", PACKET_SIZE(*packet, request), payload_length);

    if(PACKET_SIZE(*packet, request) + payload_length > aMaxMACPayloadSize) {
        SN_ErrPrintf("packet is too large, at %d bytes (maximum length is %d bytes)\n",
            PACKET_SIZE(*packet, request) + payload_length, aMaxMACPayloadSize);
        return -SN_ERR_RESOURCES;
    }

    assert(payload != NULL);

    packet->layout.payload_length = payload_length;
    if(payload_length > 0) {
        packet->layout.payload_data = PACKET_SIZE(*packet, request);
        packet->layout.present.payload_data = 1;
        PACKET_SIZE(*packet, request) += payload_length;

        uint8_t* packet_data = PACKET_ENTRY(*packet, payload_data, request);
        assert(packet_data != NULL);

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
    mac_address_t null_address;
    memset(&null_address, 0, sizeof(null_address));
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

    if(table_entry.unavailable) {
        SN_ErrPrintf("contact with remote node has been lost. aborting\n");
        return -SN_ERR_DISCONNECTED;
    }

    //actual packet buffer
    packet_t packet;
    memset(&packet.layout, 0, sizeof(packet.layout));

    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.layout.network_header    = 0; //redundant, but useful to demonstrate the point
    packet.layout.present.network_header   = 1;
    network_header_t* header               = PACKET_ENTRY(packet, network_header, request);
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    header->src_addr                       = session->mib.macShortAddress;
    header->dst_addr                       = table_entry.short_address;
    //attributes
    header->attributes                     = 0;
    header->encrypt                        = 1;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Send_finalise);
    if(message != NULL) {
        header->evidence                   = (uint8_t)(message->type == SN_Evidence_message);
    }
    header->ack                            = (uint8_t)((table_entry.ack && header->encrypt) || message == NULL);
    //update packet
    PACKET_SIZE(packet, request) = sizeof(network_header_t);

    if(header->key_confirm) {
        table_entry.state = SN_Associated;
    }
    if(header->details) {
        table_entry.knows_details = 1;
    }
    table_entry.ack = 0;

    SN_InfoPrintf("generating subheaders...\n");
    ret = generate_packet_headers(session, &table_entry, 0, &packet);
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
    uint32_t encryption_counter = table_entry.packet_tx_counter;
    bool pure_ack = 0;

    if(PACKET_ENTRY(packet, key_confirmation_header, request) == NULL && PACKET_ENTRY(packet, encrypted_ack_header, request) != NULL && PACKET_ENTRY(packet, payload_data, request) == NULL) {
        //this is a pure-acknowledgement packet; don't change the counter
        pure_ack = 1;
    } else {
        table_entry.packet_tx_counter++;
    }

    if(pure_ack) {
        assert(PACKET_ENTRY(packet, encrypted_ack_header, request)->counter + 1 == table_entry.packet_rx_counter);
        ret = encrypt_authenticate_packet(&table_entry.link_key, &table_entry.remote_key_agreement_key, PACKET_ENTRY(packet, encrypted_ack_header, request)->counter, &packet, 1);
    } else {
        ret = encrypt_authenticate_packet(&table_entry.link_key, &table_entry.local_key_agreement_keypair.public_key, encryption_counter, &packet, 0);
    }

    if(ret != SN_OK) {
        SN_ErrPrintf("packet crypto failed with %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = SN_Delayed_transmit(session, &table_entry, &packet, encryption_counter);
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

    if(dst_addr->type == mac_short_address) {
        SN_DebugPrintf("attempting to associate with %#06x\n", dst_addr->address.ShortAddress);
    } else {
        SN_DebugPrintf("attempting to associate with %#018"PRIx64"\n", *(uint64_t*)dst_addr->address.ExtendedAddress);
    }

    //validity check on address
    mac_address_t null_address;
    memset(&null_address, 0, sizeof(null_address));
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
    int ret = SN_Table_lookup_by_address(dst_addr, &table_entry, NULL);
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
    memset(&packet.layout, 0, sizeof(packet.layout));

    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.layout.network_header    = 0;
    packet.layout.present.network_header   = 1;
    network_header_t* header               = PACKET_ENTRY(packet, network_header, request);
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    header->src_addr                       = session->mib.macShortAddress;
    header->dst_addr                       = table_entry.short_address;
    //attributes
    header->attributes                     = 0;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->associate                      = 1;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Associate_received);
    header->evidence                       = (uint8_t)(message != NULL); //association packets are unencrypted. so if there's a payload, it must be evidence
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
            SN_Kex_result_t kex_result;
            if(SN_Crypto_key_agreement(
                &table_entry.public_key,
                &session->device_root_key.public_key,
                &table_entry.remote_key_agreement_key,
                &table_entry.local_key_agreement_keypair.private_key,
                &kex_result
            ) != SN_OK) {
                SN_ErrPrintf("error during key agreement, aborting send\n");
                return -SN_ERR_KEYGEN;
            }
            table_entry.link_key = kex_result.key;
            table_entry.packet_rx_counter = table_entry.packet_tx_counter = 0;

            //advance state
            table_entry.state = SN_Awaiting_finalise;
            break;

        default:
            SN_ErrPrintf("association requests are only valid in state SN_Associated or SN_Association_received. we are in %d\n", table_entry.state);
            return -SN_ERR_UNEXPECTED;
    }

    //generate subheaders
    SN_InfoPrintf("generating subheaders...\n");
    ret = generate_packet_headers(session, &table_entry, 0, &packet);
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

    uint32_t encryption_counter = 0;

    if(header->encrypt) {
        //XXX: header->encrypt is always false here, so this never gets executed. it's worth leaving in tho, in case rekeying is ever implemented
        SN_InfoPrintf("encrypting packet...\n");
        encryption_counter = table_entry.packet_tx_counter++;
        //XXX: also, an association packet is never a pure-ack
        ret = encrypt_authenticate_packet(&table_entry.link_key, &table_entry.local_key_agreement_keypair.public_key, encryption_counter, &packet, 0);
        if(ret != SN_OK) {
            SN_ErrPrintf("packet crypto failed with %d\n", -ret);
            return ret;
        }
    }

    //update node table
    SN_Table_update(&table_entry);

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = SN_Delayed_transmit(session, &table_entry, &packet, encryption_counter);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
