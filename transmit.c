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

#include "crypto.h"
#include "node_table.h"
#include "logging.h"
#include "status.h"
#include "constants.h"
#include "packet.h"
#include "retransmission_queue.h"
#include "util.h"
#include "config.h"

#include "net/packetbuf.h"

#include <string.h>
#include <assert.h>

//transmit packet, containing one or more messages
int SN_Send(SN_Endpoint_t *dst_addr, SN_Message_t *message) {
    SN_Table_entry_t table_entry;
    int ret;
    packet_t packet;
    uint32_t encryption_counter;
    network_header_t* header;
    bool pure_ack = 0;

    //initial NULL-checks
    if(dst_addr == NULL) {
        SN_ErrPrintf("dst_addr must be valid\n");
        return -SN_ERR_NULL;
    }

    //validity check on address
    switch(dst_addr->type) {
        case SN_ENDPOINT_SHORT_ADDRESS:
            if(dst_addr->short_address == SN_NO_SHORT_ADDRESS) {
                SN_ErrPrintf("attempting to send to null short address. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        case SN_ENDPOINT_LONG_ADDRESS:
            if(!memcmp(dst_addr->long_address, null_address, sizeof(null_address))) {
                SN_ErrPrintf("attempting to send to null long address. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        case SN_ENDPOINT_PUBLIC_KEY:
            if(!memcmp(&dst_addr->public_key, &null_key, sizeof(null_key))) {
                SN_ErrPrintf("attempting to send to null public key. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        default:
            SN_ErrPrintf("invalid address type. aborting\n");
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    ret = SN_Table_lookup(dst_addr, &table_entry);
    if(ret != SN_OK || table_entry.state < SN_Send_finalise) { //node isn't in node table, abort
        SN_ErrPrintf("no relationship with remote node. aborting\n");
        return -SN_ERR_SECURITY;
    }

    if(table_entry.unavailable) {
        SN_ErrPrintf("contact with remote node has been lost. aborting\n");
        return -SN_ERR_DISCONNECTED;
    }

    //initialise the packet data structure...
    memset(&packet, 0, sizeof(packet));
    //... and the packetbuf, setting up pointers as necessary
    packetbuf_clear();
    packet.data = packetbuf_dataptr();


    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.layout.network_header           = 0; //redundant, but useful to demonstrate the point
    packet.layout.present.network_header   = 1;
    header                                 = PACKET_ENTRY(packet, network_header, request);
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    header->src_addr                       = starfishnet_config.mib.macShortAddress;
    header->dst_addr                       = table_entry.short_address;
    //attributes
    header->attributes                     = 0;
    header->encrypt                        = 1;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Send_finalise);
    if(message != NULL) {
        header->evidence                   = (uint8_t)(message->type != SN_Data_message);
    }
    header->alt_stream                     = (uint8_t)(table_entry.altstream.stream_idx_length > 0);
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
    ret = generate_packet_headers(&table_entry, 0, &packet);
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
    encryption_counter = table_entry.packet_tx_counter;

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
    ret = SN_Retransmission_send(&table_entry, &packet, encryption_counter);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    //we've changed the table entry. update it
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Associate(SN_Endpoint_t *dst_addr) {
    SN_Table_entry_t table_entry;
    int ret;
    packet_t packet;
    uint32_t sequence_number = 0;
    SN_Kex_result_t kex_result;
    network_header_t* header;

    //initial NULL-checks
    if(dst_addr == NULL) {
        SN_ErrPrintf("dst_addr must be valid\n");
        return -SN_ERR_NULL;
    }

    //validity check on address
    switch(dst_addr->type) {
        case SN_ENDPOINT_SHORT_ADDRESS:
            if(dst_addr->short_address == SN_NO_SHORT_ADDRESS) {
                SN_ErrPrintf("attempting to send to null short address. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        case SN_ENDPOINT_LONG_ADDRESS:
            if(!memcmp(dst_addr->long_address, null_address, sizeof(null_address))) {
                SN_ErrPrintf("attempting to send to null long address. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        case SN_ENDPOINT_PUBLIC_KEY:
            if(!memcmp(&dst_addr->public_key, &null_key, sizeof(null_key))) {
                SN_ErrPrintf("attempting to send to null public key. aborting\n");
                return -SN_ERR_INVALID;
            }
            break;

        default:
            SN_ErrPrintf("invalid address type. aborting\n");
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    ret = SN_Table_lookup(dst_addr, &table_entry);
    if(ret != SN_OK) {
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        switch(dst_addr->type) {
            case SN_ENDPOINT_SHORT_ADDRESS:
                table_entry.short_address = dst_addr->short_address;
                break;

            case SN_ENDPOINT_LONG_ADDRESS:
                memcpy(table_entry.long_address, dst_addr->long_address, 8);
                break;

            case SN_ENDPOINT_PUBLIC_KEY:
                memcpy(&table_entry.public_key, &dst_addr->public_key, sizeof(dst_addr->public_key));
                break;
        }
        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table, aborting.\n");
            return -SN_ERR_RESOURCES;
        }
    }

    //initialise the packet data structure...
    memset(&packet.layout, 0, sizeof(packet.layout));
    //... and the packetbuf, setting up pointers as necessary
    packetbuf_clear();
    packet.length = 0;
    packet.data = packetbuf_dataptr();

    //network header
    SN_InfoPrintf("generating network header...\n");
    packet.layout.network_header    = 0;
    packet.layout.present.network_header   = 1;
    header                                 = PACKET_ENTRY(packet, network_header, request);
    header->protocol_id                    = STARFISHNET_PROTOCOL_ID;
    header->protocol_ver                   = STARFISHNET_PROTOCOL_VERSION;
    header->src_addr                       = starfishnet_config.mib.macShortAddress;
    header->dst_addr                       = table_entry.short_address;
    //attributes
    header->attributes                     = 0;
    header->req_details                    = (uint8_t)!table_entry.details_known;
    header->details                        = (uint8_t)!table_entry.knows_details;
    header->associate                      = 1;
    header->key_confirm                    = (uint8_t)(table_entry.state == SN_Associate_received);
    header->evidence                       = 0;
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
                &table_entry.public_key,
                &starfishnet_config.device_root_key.public_key,
                &table_entry.remote_key_agreement_key,
                &table_entry.local_key_agreement_keypair.private_key,
                &kex_result
            ) != SN_OK) {
                SN_ErrPrintf("error during key agreement, aborting send\n");
                return -SN_ERR_KEYGEN;
            }
            memcpy(table_entry.link_key.data, kex_result.key.data, sizeof(kex_result.key.data));
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
    ret = generate_packet_headers(&table_entry, 0, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in header generation\n", -ret);
        return ret;
    }

    if(header->encrypt) {
        //XXX: header->encrypt is always false here, so this never gets executed. it's worth leaving in tho, in case rekeying is ever implemented
        SN_InfoPrintf("encrypting packet...\n");
        sequence_number = table_entry.packet_tx_counter++;
        //XXX: also, an association packet is never a pure-ack
        ret = encrypt_authenticate_packet(&table_entry.link_key, &table_entry.local_key_agreement_keypair.public_key, sequence_number, &packet, 0);
        if(ret != SN_OK) {
            SN_ErrPrintf("packet crypto failed with %d\n", -ret);
            return ret;
        }
    }

    //update node table
    SN_Table_update(&table_entry);

    SN_InfoPrintf("beginning packet transmission...\n");
    ret = SN_Retransmission_send(&table_entry, &packet, sequence_number);
    if(ret != SN_OK) {
        SN_ErrPrintf("transmission failed with %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
