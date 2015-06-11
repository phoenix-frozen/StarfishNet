#include "packet.h"
#include "sn_beacons.h"
#include "logging.h"
#include "status.h"
#include "crypto.h"
#include "config.h"
#include "routing_tree.h"

#include <assert.h>

//argument note: margin means the amount of data to skip (after the network header, before the payload) for encryption
int encrypt_authenticate_packet(SN_AES_key_t* link_key, SN_Public_key_t* key_agreement_key, uint32_t encryption_counter, packet_t* packet, bool pure_ack) {
    SN_DebugPrintf("enter\n");

    if(link_key == NULL || key_agreement_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, key_agreement_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header_t* encryption_header = PACKET_ENTRY(*packet, encryption_header, request);
    if(encryption_header == NULL) {
        SN_ErrPrintf("Packet needs an encryption header before being encrypted.\n");
        return -SN_ERR_INVALID;
    }

    const size_t skip_size = packet->layout.encryption_header + sizeof(encryption_header_t);
    if(PACKET_SIZE(*packet, request) < skip_size) {
        SN_ErrPrintf("cannot encrypt packet of length %d with an encryption header at %d\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header);
        return -SN_ERR_END_OF_DATA;
    }

    SN_InfoPrintf("encrypting packet of length %d with an encryption header at %d (counter = %x)\n", PACKET_SIZE(*packet, request), packet->layout.encryption_header, encryption_counter);

    int ret = SN_Crypto_encrypt(link_key, key_agreement_key,
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

int generate_packet_headers(SN_Table_entry_t *table_entry, bool dissociate, packet_t *packet) {
    SN_DebugPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry, crypto_margin, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    network_header_t* network_header = PACKET_ENTRY(*packet, network_header, request);
    if(PACKET_SIZE(*packet, request) != sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header, aborting\n");
        return -SN_ERR_END_OF_DATA;
    }

    //alt_stream_header_t
    if(network_header->alt_stream) {
        SN_InfoPrintf("generating alternate stream header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.alt_stream_header = PACKET_SIZE(*packet, request);
        packet->layout.present.alt_stream_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length;
        alt_stream_header_t* alt_stream_header = PACKET_ENTRY(*packet, alt_stream_header, request);
        assert(alt_stream_header != NULL);

        alt_stream_header->length = table_entry->altstream.stream_idx_length;
        memcpy(alt_stream_header->stream_idx, table_entry->altstream.stream_idx, alt_stream_header->length);
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

        node_details_header->signing_key = starfishnet_config.device_root_key.public_key;
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

                    int ret = SN_Tree_allocate_address(&address, &block);

                    if(ret == SN_OK) {
                        network_header->dst_addr   = address;
                        association_header->router = (uint8_t)(block ? 1 : 0);

                        SN_InfoPrintf("allocated %s address %#06x\n", block ? "router" : "leaf", address);

                        table_entry->short_address = address;
                        ret = SN_Beacon_update();
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
                association_header->router = starfishnet_config.nib.enable_routing;
                association_header->child =
                    memcmp(
                        starfishnet_config.nib.parent_public_key.data,
                        table_entry->public_key.data,
                        sizeof(starfishnet_config.nib.parent_public_key.data)
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

    //encrypted_ack_header_t
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
            SN_ErrPrintf("acknowledgements can only be sent for encrypted packets\n");
            return -SN_ERR_INVALID;
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
            &starfishnet_config.device_root_key.private_key,
            packet->data,
            packet->layout.signature_header,
            &signature_header->signature) != SN_OK) {
            SN_ErrPrintf("could not sign packet\n");
            return -SN_ERR_SIGNATURE;
        }
    }

    //evidence_header_t
    if(network_header->evidence) {
        SN_InfoPrintf("generating evidence header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(evidence_header_t) > aMaxMACPayloadSize) {
            SN_ErrPrintf("adding evidence header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.evidence_header = PACKET_SIZE(*packet, request);
        packet->layout.present.evidence_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(evidence_header_t);
        evidence_header_t* evidence_header = PACKET_ENTRY(*packet, evidence_header, request);
        assert(evidence_header != NULL);

        evidence_header->flags = 0;
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

int generate_payload(SN_Message_t* message, packet_t* packet) {
    assert(message != NULL);

    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

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
            //TODO: WRITEME

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

