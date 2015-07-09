#include "packet.h"
#include "discovery.h"
#ifdef SN_DEBUG
#undef SN_DEBUG_LEVEL
#define SN_DEBUG_LEVEL 2
#endif
#include "logging.h"
#include "status.h"
#include "crypto.h"
#include "config.h"
#include "routing_tree.h"
#include "constants.h"

#include <assert.h>

//argument note: margin means the amount of data to skip (after the network header, before the payload) for encryption
int packet_encrypt_authenticate(packet_t* packet, const SN_Public_key_t* key_agreement_key, const SN_AES_key_t* link_key,
                                uint32_t encryption_counter, bool pure_ack) {
    encryption_header_t* encryption_header;
    uint8_t skip_size;
    int ret;

    SN_DebugPrintf("enter\n");

    if(link_key == NULL || key_agreement_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, key_agreement_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header = PACKET_ENTRY(*packet, encryption_header, request);
    if(encryption_header == NULL) {
        SN_ErrPrintf("Packet needs an encryption header before being encrypted.\n");
        return -SN_ERR_INVALID;
    }

    skip_size = packet->layout.encryption_header + (uint8_t)sizeof(encryption_header_t);
    if(PACKET_SIZE(*packet, request) < skip_size) {
        SN_ErrPrintf("cannot encrypt packet of length %d with an encryption header at %d\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header);
        return -SN_ERR_END_OF_DATA;
    }

    SN_InfoPrintf("encrypting packet of length %d with an encryption header at %d (counter = %x)\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header, encryption_counter);

    ret = SN_Crypto_encrypt(link_key, key_agreement_key,
                                encryption_counter,
                                packet->data, packet->layout.encryption_header,
                                packet->data + skip_size,
                                packet->length - skip_size,
                                encryption_header->tag, pure_ack);
    if(ret != SN_OK) {
        SN_ErrPrintf("Packet encryption failed with %d, aborting\n", -ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("payload encryption complete\n");

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static void allocate_address(packet_t* packet, SN_Table_entry_t* table_entry) {
    uint8_t block = PACKET_ENTRY(*packet, association_header, request)->router;
    uint16_t address;
    int ret = SN_Tree_allocate_address(&address, &block);

    if(ret == SN_OK) {
        PACKET_ENTRY(*packet, network_header, request)->dst_addr   = address;
        PACKET_ENTRY(*packet, association_header, request)->router = (uint8_t)(block ? 1 : 0);

        SN_InfoPrintf("allocated %s address 0x%04x\n", block ? "router" : "leaf", address);

        table_entry->short_address = address;
        SN_Beacon_update();
    } else {
        SN_WarnPrintf("address allocation failed; proceeding without\n");

        PACKET_ENTRY(*packet, association_header, request)->child  = 0;
        PACKET_ENTRY(*packet, association_header, request)->router = 0;
    }
}

int packet_generate_headers(packet_t* packet, SN_Table_entry_t* table_entry, const SN_Message_t* message) {
    SN_InfoPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //network_header_t
    packet->layout.network_header         = 0;
    packet->layout.present.network_header = 1;
#define NETWORK_HEADER PACKET_ENTRY(*packet, network_header, request)
    assert(NETWORK_HEADER != NULL);
    NETWORK_HEADER->protocol_id  = STARFISHNET_PROTOCOL_ID;
    NETWORK_HEADER->protocol_ver = STARFISHNET_PROTOCOL_VERSION;
    NETWORK_HEADER->src_addr     = starfishnet_config.short_address;
    NETWORK_HEADER->dst_addr     = table_entry->short_address;
    NETWORK_HEADER->attributes   = 0;
    NETWORK_HEADER->alt_stream   = (uint8_t)(table_entry->altstream.stream_idx_length > 0);
    if(message == NULL || (message->type != SN_Association_request && message->type != SN_Dissociation_request)) { //data packet
        NETWORK_HEADER->data = 1;
        NETWORK_HEADER->data_attributes.ack      = (uint8_t)((table_entry->ack && NETWORK_HEADER->data) || message == NULL);
        NETWORK_HEADER->data_attributes.evidence = (uint8_t)(message != NULL && message->type > SN_Data_message);

        if(table_entry->state == SN_Send_finalise) {
            NETWORK_HEADER->data_attributes.key_confirm = 1;
            table_entry->state = SN_Associated;
        }

        table_entry->ack = 0;
    } else { //control packet
        NETWORK_HEADER->data = 0;
        NETWORK_HEADER->control_attributes.associate   = (uint8_t)(uint8_t)(message->type == SN_Association_request || message->type == SN_Dissociation_request);
        NETWORK_HEADER->control_attributes.req_details = (uint8_t)!table_entry->details_known;
        NETWORK_HEADER->control_attributes.details     = (uint8_t)!table_entry->knows_details;

        if(NETWORK_HEADER->control_attributes.associate && table_entry->state == SN_Associate_received) {
            NETWORK_HEADER->data_attributes.key_confirm = 1;
            table_entry->state = SN_Awaiting_finalise;
        }

        if(NETWORK_HEADER->control_attributes.details) {
            table_entry->knows_details = 1;
        }
    }
    PACKET_SIZE(*packet, request) = sizeof(network_header_t);

    //alt_stream_header_t
    if(ATTRIBUTE(NETWORK_HEADER, alt_stream)) {
        SN_InfoPrintf("generating alternate stream header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length >
           SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.alt_stream_header = PACKET_SIZE(*packet, request);
        packet->layout.present.alt_stream_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length;

        PACKET_ENTRY(*packet, alt_stream_header, request)->length = table_entry->altstream.stream_idx_length;
        memcpy(PACKET_ENTRY(*packet, alt_stream_header, request)->stream_idx, table_entry->altstream.stream_idx, table_entry->altstream.stream_idx_length);
    }

    //node_details_header_t
    if(CONTROL_ATTRIBUTE(NETWORK_HEADER, details)) {
        SN_InfoPrintf("generating node details header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(node_details_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.node_details_header = PACKET_SIZE(*packet, request);
        packet->layout.present.node_details_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(node_details_header_t);

        memcpy(&PACKET_ENTRY(*packet, node_details_header, request)->signing_key, &starfishnet_config.device_root_key.public_key, sizeof(starfishnet_config.device_root_key.public_key));
    }

    //association_header_t
    if(CONTROL_ATTRIBUTE(NETWORK_HEADER, associate)) {
        SN_InfoPrintf("generating association header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(association_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.association_header = PACKET_SIZE(*packet, request);
        packet->layout.present.association_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(association_header_t);
#define ASSOCIATION_HEADER PACKET_ENTRY(*packet, association_header, request)
        assert(ASSOCIATION_HEADER != NULL);
        assert(message != NULL);

        ASSOCIATION_HEADER->flags             = 0;
        ASSOCIATION_HEADER->dissociate        = (uint8_t)(message->type == SN_Dissociation_request ? 1 : 0);

        if(!ASSOCIATION_HEADER->dissociate) {
            //key_agreement_header_t
            packet->layout.key_agreement_header = PACKET_SIZE(*packet, request);
            packet->layout.present.key_agreement_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(key_agreement_header_t);

            memcpy(&PACKET_ENTRY(*packet, key_agreement_header, request)->key_agreement_key, &table_entry->local_key_agreement_keypair.public_key, sizeof(table_entry->local_key_agreement_keypair.public_key));

            //parent/child handling
            if(CONTROL_ATTRIBUTE(NETWORK_HEADER, key_confirm)) {
                //this is a reply

                //address bits
                ASSOCIATION_HEADER->child  = (uint8_t)table_entry->child;
                ASSOCIATION_HEADER->router = (uint8_t)table_entry->router;

                //address allocation
                if(ASSOCIATION_HEADER->child) {
                    SN_InfoPrintf("node is our child; allocating it an address...\n");
                    allocate_address(packet, table_entry);
                }
            } else {
                //this is a request
                ASSOCIATION_HEADER->router = starfishnet_config.enable_routing;
                ASSOCIATION_HEADER->child =
                    memcmp(
                        starfishnet_config.parent_public_key.data,
                        table_entry->public_key.data,
                        sizeof(starfishnet_config.parent_public_key.data)
                    ) == 0 ? (uint8_t)1 : (uint8_t)0;
            }
        }
#undef ASSOCIATION_HEADER
    }

    //key_confirmation_header_t
    if(ATTRIBUTE(NETWORK_HEADER, key_confirm)) {
        SN_InfoPrintf("generating key confirmation header (challenge%d) at %d\n", CONTROL_ATTRIBUTE(NETWORK_HEADER, associate) ? 1 : 2, PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(key_confirmation_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.key_confirmation_header = PACKET_SIZE(*packet, request);
        packet->layout.present.key_confirmation_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(key_confirmation_header_t);

        SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &PACKET_ENTRY(*packet, key_confirmation_header, request)->challenge);
        if(CONTROL_ATTRIBUTE(NETWORK_HEADER, associate)) {
            //this is a reply; do challenge1 (double-hash)
            SN_Crypto_hash(PACKET_ENTRY(*packet, key_confirmation_header, request)->challenge.data, SN_Hash_size, &PACKET_ENTRY(*packet, key_confirmation_header, request)->challenge);
        }
    }

    //encrypted_ack_header_t
    if(DATA_ATTRIBUTE(NETWORK_HEADER, ack)) {
        SN_InfoPrintf("generating encrypted-ack header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(encrypted_ack_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encrypted_ack header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.encrypted_ack_header         = PACKET_SIZE(*packet, request);
        packet->layout.present.encrypted_ack_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(encrypted_ack_header_t);

        PACKET_ENTRY(*packet, encrypted_ack_header, request)->counter = table_entry->packet_rx_counter - 1;
    }

    //evidence_header_t
    if(DATA_ATTRIBUTE(NETWORK_HEADER, evidence)) {
        SN_InfoPrintf("generating evidence header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(evidence_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding evidence header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.evidence_header = PACKET_SIZE(*packet, request);
        packet->layout.present.evidence_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(evidence_header_t);

        PACKET_ENTRY(*packet, evidence_header, request)->flags = 0;
    }

    //{encryption,signature}_header_t
    if(ATTRIBUTE(NETWORK_HEADER, data)) {
        SN_InfoPrintf("generating encryption header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(encryption_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.encryption_header = PACKET_SIZE(*packet, request);
        packet->layout.present.encryption_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(encryption_header_t);
    } else {
        SN_InfoPrintf("generating signature header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(signature_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.signature_header = PACKET_SIZE(*packet, request);
        packet->layout.present.signature_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(signature_header_t);

        //signs everything before the signature header occurs
        if(SN_Crypto_sign(
            &starfishnet_config.device_root_key.private_key,
            packet->data,
            packet->layout.signature_header,
            &PACKET_ENTRY(*packet, signature_header, request)->signature) != SN_OK) {
            SN_ErrPrintf("could not sign packet\n");
            return -SN_ERR_SIGNATURE;
        }
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
#undef NETWORK_HEADER
}

int packet_generate_payload(packet_t* packet, const SN_Message_t* message) {
    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

    if(message == NULL) {
        return -SN_ERR_NULL;
    }

    switch(message->type) {
        case SN_Data_message:
            payload = message->data_message.payload;
            payload_length = message->data_message.payload_length;
            break;

        case SN_Explicit_Evidence_message:
            payload = (uint8_t*)&message->explicit_evidence_message.evidence;
            payload_length = sizeof(SN_Certificate_t);
            assert(PACKET_ENTRY(*packet, evidence_header, request) != NULL);
            PACKET_ENTRY(*packet, evidence_header, request)->certificate = 1;
            break;

        case SN_Implicit_Evidence_message:
            //TODO: WRITEME (implicit evidence message)

        default:
            SN_ErrPrintf("invalid message type %d, aborting\n", message->type);
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("generating %s payload at %d (%d bytes)\n", message->type == SN_Data_message ? "data" : "evidence", PACKET_SIZE(*packet, request), payload_length);

    if(PACKET_SIZE(*packet, request) + payload_length > SN_MAXIMUM_PACKET_SIZE) {
        SN_ErrPrintf("packet is too large, at %d bytes (maximum length is %d bytes)\n",
                     PACKET_SIZE(*packet, request) + payload_length, SN_MAXIMUM_PACKET_SIZE);
        return -SN_ERR_RESOURCES;
    }

    packet->layout.payload_length = payload_length;
    if(payload_length > 0) {
        assert(payload != NULL);

        packet->layout.payload_data = PACKET_SIZE(*packet, request);
        packet->layout.present.payload_data = 1;
        PACKET_SIZE(*packet, request) += payload_length;

        memcpy(PACKET_ENTRY(*packet, payload_data, request), payload, payload_length);
    } else {
        SN_WarnPrintf("no payload to generate\n");
    }

    return SN_OK;
}
