#include "packet.h"
#include "sn_beacons.h"
#include "logging.h"
#include "status.h"
#include "crypto.h"
#include "config.h"
#include "routing_tree.h"
#include "retransmission_queue.h"
#include "constants.h"

#include <assert.h>

//argument note: margin means the amount of data to skip (after the network header, before the payload) for encryption
int encrypt_authenticate_packet(SN_AES_key_t* link_key, SN_Public_key_t* key_agreement_key, uint32_t encryption_counter, packet_t* packet, bool pure_ack) {
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

    skip_size = packet->layout.encryption_header + sizeof(encryption_header_t);
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

int generate_packet_headers(SN_Table_entry_t *table_entry, bool dissociate, packet_t *packet) {
    network_header_t* network_header;

    SN_DebugPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry, crypto_margin, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    network_header = PACKET_ENTRY(*packet, network_header, request);
    if(PACKET_SIZE(*packet, request) != sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header, aborting\n");
        return -SN_ERR_END_OF_DATA;
    }

    //alt_stream_header_t
    if(network_header->alt_stream) {
        alt_stream_header_t* alt_stream_header;

        SN_InfoPrintf("generating alternate stream header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length >
           SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.alt_stream_header = PACKET_SIZE(*packet, request);
        packet->layout.present.alt_stream_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length;
        alt_stream_header = PACKET_ENTRY(*packet, alt_stream_header, request);
        assert(alt_stream_header != NULL);

        alt_stream_header->length = table_entry->altstream.stream_idx_length;
        memcpy(alt_stream_header->stream_idx, table_entry->altstream.stream_idx, alt_stream_header->length);
    }

    //node_details_header_t
    if(network_header->details) {
        node_details_header_t* node_details_header;

        SN_InfoPrintf("generating node details header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(node_details_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.node_details_header = PACKET_SIZE(*packet, request);
        packet->layout.present.node_details_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(node_details_header_t);
        node_details_header = PACKET_ENTRY(*packet, node_details_header, request);
        assert(node_details_header != NULL);

        memcpy(&node_details_header->signing_key, &starfishnet_config.device_root_key.public_key, sizeof(starfishnet_config.device_root_key.public_key));
    }

    //association_header_t
    if(network_header->associate) {
        association_header_t* association_header;

        SN_InfoPrintf("generating association header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(association_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.association_header = PACKET_SIZE(*packet, request);
        packet->layout.present.association_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(association_header_t);
        association_header = PACKET_ENTRY(*packet, association_header, request);
        assert(association_header != NULL);

        association_header->flags             = 0;
        association_header->dissociate        = (uint8_t)(dissociate ? 1 : 0);

        //key_agreement_header_t
        if(!association_header->dissociate) {
            key_agreement_header_t* key_agreement_header;

            packet->layout.key_agreement_header = PACKET_SIZE(*packet, request);
            packet->layout.present.key_agreement_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(key_agreement_header_t);
            key_agreement_header = PACKET_ENTRY(*packet, key_agreement_header, request);
            assert(key_agreement_header != NULL);

            memcpy(&key_agreement_header->key_agreement_key, &table_entry->local_key_agreement_keypair.public_key, sizeof(table_entry->local_key_agreement_keypair.public_key));
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
                    uint8_t block = association_header->router;
                    uint16_t address;
                    int ret = SN_Tree_allocate_address(&address, &block);

                    SN_InfoPrintf("node is our child; allocating it an address...\n");

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
        key_confirmation_header_t* key_confirmation_header;

        SN_InfoPrintf("generating key confirmation header (challenge%d) at %d\n", network_header->associate ? 1 : 2, PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(key_confirmation_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.key_confirmation_header = PACKET_SIZE(*packet, request);
        packet->layout.present.key_confirmation_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(key_confirmation_header_t);
        key_confirmation_header = PACKET_ENTRY(*packet, key_confirmation_header, request);
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
            encrypted_ack_header_t* encrypted_ack_header;

            //encrypted_ack_header_t
            SN_InfoPrintf("generating encrypted-ack header at %d\n", PACKET_SIZE(*packet, request));
            if(PACKET_SIZE(*packet, request) + sizeof(encrypted_ack_header_t) > SN_MAXIMUM_PACKET_SIZE) {
                SN_ErrPrintf("adding encrypted_ack header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet->layout.encrypted_ack_header = PACKET_SIZE(*packet, request);
            packet->layout.present.encrypted_ack_header = 1;
            PACKET_SIZE(*packet, request) += sizeof(encrypted_ack_header_t);
            encrypted_ack_header = PACKET_ENTRY(*packet, encrypted_ack_header, request);
            assert(encrypted_ack_header != NULL);

            encrypted_ack_header->counter = table_entry->packet_rx_counter - 1;
        } else {
            SN_ErrPrintf("acknowledgements can only be sent for encrypted packets\n");
            return -SN_ERR_INVALID;
        }
    }

    //{encryption,signature}_header_t
    if(network_header->encrypt) {
        encryption_header_t* encryption_header;

        SN_InfoPrintf("generating encryption header at %d\n", PACKET_SIZE(*packet, request));
        if(PACKET_SIZE(*packet, request) + sizeof(encryption_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.encryption_header = PACKET_SIZE(*packet, request);
        packet->layout.present.encryption_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(encryption_header_t);
        encryption_header = PACKET_ENTRY(*packet, encryption_header, request);
        assert(encryption_header != NULL);

        (void)encryption_header; //shut up CLion
    } else {
        signature_header_t* signature_header;

        SN_InfoPrintf("generating signature header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(signature_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.signature_header = PACKET_SIZE(*packet, request);
        packet->layout.present.signature_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(signature_header_t);
        signature_header = PACKET_ENTRY(*packet, signature_header, request);
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
        evidence_header_t* evidence_header;

        SN_InfoPrintf("generating evidence header at %d\n", PACKET_SIZE(*packet, request));

        if(PACKET_SIZE(*packet, request) + sizeof(evidence_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding evidence header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.evidence_header = PACKET_SIZE(*packet, request);
        packet->layout.present.evidence_header = 1;
        PACKET_SIZE(*packet, request) += sizeof(evidence_header_t);
        evidence_header = PACKET_ENTRY(*packet, evidence_header, request);
        assert(evidence_header != NULL);

        evidence_header->flags = 0;
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

int generate_payload(SN_Message_t* message, packet_t* packet) {
    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

    assert(message != NULL);

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

    if(PACKET_SIZE(*packet, request) + payload_length > SN_MAXIMUM_PACKET_SIZE) {
        SN_ErrPrintf("packet is too large, at %d bytes (maximum length is %d bytes)\n",
                     PACKET_SIZE(*packet, request) + payload_length, SN_MAXIMUM_PACKET_SIZE);
        return -SN_ERR_RESOURCES;
    }

    assert(payload != NULL);

    packet->layout.payload_length = payload_length;
    if(payload_length > 0) {
        uint8_t* packet_data;

        packet->layout.payload_data = PACKET_SIZE(*packet, request);
        packet->layout.present.payload_data = 1;
        PACKET_SIZE(*packet, request) += payload_length;

        packet_data = PACKET_ENTRY(*packet, payload_data, request);
        assert(packet_data != NULL);

        memcpy(packet_data, payload, payload_length);
    } else {
        SN_WarnPrintf("no payload to generate\n");
    }

    return SN_OK;
}

//outputs crypto margin, and pointers to the key agreement header and payload data
//also detects basic protocol failures
int detect_packet_layout(packet_t* packet) {
    uint8_t current_position = 0;
    network_header_t* network_header;

    SN_DebugPrintf("enter\n");

    if(packet == NULL) {
        SN_ErrPrintf("packet must be valid\n");
        return -SN_ERR_NULL;
    }

    memset(&packet->layout, 0, sizeof(packet->layout));

    //network_header_t is always present
    packet->layout.network_header = 0;
    packet->layout.present.network_header = 1;
    network_header = PACKET_ENTRY(*packet, network_header, indication);
    assert(network_header != NULL);
    if(PACKET_SIZE(*packet, indication) < sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header. aborting\n");
        return -SN_ERR_END_OF_DATA;
    }
    if(!(network_header->protocol_id == STARFISHNET_PROTOCOL_ID &&
         network_header->protocol_ver == STARFISHNET_PROTOCOL_VERSION
    )) {
        SN_ErrPrintf("packet has invalid protocol ID bytes. protocol is %x (should be %x), version is %x (should be %x)\n", network_header->protocol_id, STARFISHNET_PROTOCOL_ID, network_header->protocol_ver, STARFISHNET_PROTOCOL_VERSION);
        return -SN_ERR_OLD_VERSION;
    }
    current_position += sizeof(network_header_t);

    //alt_stream_header_t
    if(network_header->alt_stream) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(alt_stream_header_t)) {
            SN_ErrPrintf("packet indicates an alternate stream header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found alternate stream header at %d\n", current_position);
        packet->layout.alt_stream_header = current_position;
        packet->layout.present.alt_stream_header = 1;
        current_position += sizeof(alt_stream_header_t);
        if(PACKET_ENTRY(*packet, alt_stream_header, indication)->length > SN_MAX_ALT_STREAM_IDX_SIZE) {
            SN_ErrPrintf("alternate stream header cannot be longer than %d (is %d). aborting\n", SN_MAX_ALT_STREAM_IDX_SIZE, PACKET_ENTRY(*packet, alt_stream_header, indication)->length);
            return -SN_ERR_END_OF_DATA;
        }
        if(PACKET_SIZE(*packet, indication) < current_position + PACKET_ENTRY(*packet, alt_stream_header, indication)->length) {
            SN_ErrPrintf("alternate stream header indicate stream index longer than remaining packet data. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
    }

    //node_details_header_t
    if(network_header->details) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(node_details_header_t)) {
            SN_ErrPrintf("packet indicates a node details header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found node details header at %d\n", current_position);
        packet->layout.node_details_header = current_position;
        packet->layout.present.node_details_header = 1;
        current_position += sizeof(node_details_header_t);
    }

    //association_header_t
    if(network_header->associate) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(association_header_t)) {
            SN_ErrPrintf("packet indicates an association header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found association header at %d\n", current_position);
        packet->layout.association_header = current_position;
        packet->layout.present.association_header = 1;
        current_position += sizeof(association_header_t);

        //key_agreement_header_t
        if(!PACKET_ENTRY(*packet, association_header, indication)->dissociate) {
            if(PACKET_SIZE(*packet, indication) < current_position + sizeof(key_agreement_header_t)) {
                SN_ErrPrintf("packet indicates a key agreement header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            SN_InfoPrintf("found key agreement header at %d\n", current_position);
            packet->layout.key_agreement_header = current_position;
            packet->layout.present.key_agreement_header = 1;
            current_position += sizeof(key_agreement_header_t);
        }
    }

    //key_confirmation_header_t
    if(network_header->key_confirm) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(key_confirmation_header_t)) {
            SN_ErrPrintf("packet indicates a key confirmation header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found key confirmation header at %d\n", current_position);
        packet->layout.key_confirmation_header = current_position;
        packet->layout.present.key_confirmation_header = 1;
        current_position += sizeof(key_confirmation_header_t);
    }

    //encrypted_ack_header_t
    if(network_header->ack && !network_header->associate) {
        if(network_header->encrypt) {
            //encrypted ack
            if(PACKET_SIZE(*packet, indication) < current_position + sizeof(encrypted_ack_header_t)) {
                SN_ErrPrintf("packet indicates an acknowledgement (encrypted) header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            SN_InfoPrintf("found acknowledgement (encrypted) header at %d\n", current_position);
            packet->layout.encrypted_ack_header = current_position;
            packet->layout.present.encrypted_ack_header = 1;
            current_position += sizeof(encrypted_ack_header_t);
        } else {
            SN_ErrPrintf("acknowledgements only work for encrypted packets");
            return -SN_ERR_INVALID;
        }
    }

    //encryption_header_t / signature_header_t
    if(network_header->encrypt) {
        //encrypted packet
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(encryption_header_t)) {
            SN_ErrPrintf("packet indicates an encryption header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found encryption header at %d\n", current_position);
        packet->layout.encryption_header = current_position;
        packet->layout.present.encryption_header = 1;
        current_position += sizeof(encryption_header_t);
    } else {
        //signed packet
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(signature_header_t)) {
            SN_ErrPrintf("packet indicates a signature header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found signature header at %d\n", current_position);
        packet->layout.signature_header = current_position;
        packet->layout.present.signature_header = 1;
        current_position += sizeof(signature_header_t);
    }

    //evidence_header
    if(network_header->evidence) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(evidence_header_t)) {
            SN_ErrPrintf("packet indicates an evidence header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found evidence header at %d\n", current_position);
        packet->layout.evidence_header = current_position;
        packet->layout.present.evidence_header = 1;
        current_position += sizeof(evidence_header_t);
    }

    //payload
    packet->layout.payload_length = PACKET_SIZE(*packet, indication) - current_position;
    if(packet->layout.payload_length > 0) {
        SN_InfoPrintf("found payload at %d (%d bytes)\n", current_position, packet->layout.payload_length);
        packet->layout.payload_data = current_position;
        packet->layout.present.payload_data = 1;
    }

    //some logic-checking assertions
    assert(current_position <= PACKET_SIZE(*packet, indication));
    assert(packet->layout.payload_length == PACKET_SIZE(*packet, indication) - current_position);

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

int packet_security_checks(SN_Table_entry_t *table_entry, packet_t *packet) {
    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //alt-stream check: alt streams are only allowed for nodes using their short address
    if(PACKET_ENTRY(*packet, network_header, indication)->src_addr == SN_NO_SHORT_ADDRESS &&
       PACKET_ENTRY(*packet, alt_stream_header, indication) != NULL &&
       PACKET_ENTRY(*packet, alt_stream_header, indication)->length > 0) {
        SN_ErrPrintf("received association header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }

    //relationship-state check: make sure the headers we see match the state the relationship is in
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL &&
       (table_entry->state == SN_Associate_received || table_entry->state >= SN_Awaiting_finalise) &&
       !PACKET_ENTRY(*packet, association_header, indication)->dissociate) {
        SN_ErrPrintf("received association header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }
    if(PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL && table_entry->state != SN_Awaiting_reply &&
       table_entry->state != SN_Awaiting_finalise) {
        SN_ErrPrintf("received key confirmation header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }

    //assertions to double-check my logic.
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL && !PACKET_ENTRY(*packet, association_header, indication)->dissociate) {
        if(PACKET_ENTRY(*packet, key_confirmation_header, indication) == NULL) {
            assert(table_entry->state == SN_Unassociated);
        }
        if(PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL) {
            assert(table_entry->state == SN_Awaiting_reply);
        }
    }
    if(PACKET_ENTRY(*packet, association_header, indication) == NULL && PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL) {
        assert(table_entry->state == SN_Awaiting_finalise);
    }

    //packet security checks:
    // 1. packets with plain data payloads must be encrypted
    // 2. unencrypted packets must be signed
    // 3. association (but not dissociation) packets must be signed
    // 4. dissociation packets must be signed or encrypted
    if(PACKET_ENTRY(*packet, encryption_header, indication) == NULL) {
        //1.
        if(PACKET_ENTRY(*packet, payload_data, indication) != NULL && !PACKET_ENTRY(*packet, network_header, indication)->evidence) {
            SN_ErrPrintf("received unencrypted packet with plain data payload. this is an error.\n");
            return -SN_ERR_SECURITY;
        }

        //2.
        if(PACKET_ENTRY(*packet, signature_header, indication) == NULL) {
            SN_ErrPrintf("received unencrypted, unsigned packet. this is an error.\n");
            return -SN_ERR_SECURITY;
        }
    }
    //3.
    if(PACKET_ENTRY(*packet, signature_header, indication) == NULL &&
       PACKET_ENTRY(*packet, association_header, indication) != NULL &&
       !PACKET_ENTRY(*packet, association_header, indication)->dissociate) {
        SN_ErrPrintf("received unsigned association packet. this is an error.\n");
        return -SN_ERR_SECURITY;
    }
    //4.
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL &&
       PACKET_ENTRY(*packet, association_header, indication)->dissociate &&
       PACKET_ENTRY(*packet, encryption_header , indication) == NULL &&
       PACKET_ENTRY(*packet, signature_header  , indication) == NULL) {
        SN_ErrPrintf("received non-integrity-checked dissociation packet. this is an error.\n");
        return -SN_ERR_SECURITY;
    }

    return SN_OK;
}

int packet_public_key_operations(SN_Public_key_t *self, SN_Table_entry_t *table_entry, packet_t *packet) {
    int ret;
    SN_Public_key_t* remote_public_key = NULL;

    /* at this point, security checks have passed, but no integrity-checking has happened.
     * if this packet is signed, we check the signature, and thus integrity-checking is done.
     * if not, it must be encrypted. we must therefore finish key-agreement so that we can
     * do integrity-checking at decrypt time.
     */

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //get the signing key from node_details_header, if we need it
    if(table_entry->details_known) {
        remote_public_key = &table_entry->public_key;
    } else if(PACKET_ENTRY(*packet, node_details_header, indication) != NULL) {
        //if we don't know the remote node's signing key, we use the one in the message
        remote_public_key = &PACKET_ENTRY(*packet, node_details_header, indication)->signing_key;
    }

    //verify packet signature
    if(PACKET_ENTRY(*packet, signature_header, indication) != NULL) {
        SN_InfoPrintf("checking packet signature...\n");

        if(remote_public_key == NULL) {
            SN_ErrPrintf("we don't know their public key, and they haven't told us. aborting\n");
            return -SN_ERR_SECURITY;
        }

        //signature covers everything before the signature header occurs
        ret = SN_Crypto_verify(
            remote_public_key,
            packet->data,
            packet->layout.signature_header,
            &PACKET_ENTRY(*packet, signature_header, indication)->signature
        );
        if(ret != SN_OK) {
            SN_ErrPrintf("packet signature verification failed.\n");
            return -SN_ERR_SIGNATURE;
        }

        SN_InfoPrintf("packet signature check successful\n");
    } else {
        assert(PACKET_ENTRY(*packet, encryption_header, indication) != NULL);
        /* if the packet isn't signed, it's encrypted, which means integrity-checking
         * during decrypt_and_verify will catch any problems
         */
    }

    //if this is an associate_reply, finish the key agreement, so we can use the link key in decrypt_and_verify
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL &&
       !PACKET_ENTRY(*packet, association_header, indication)->dissociate &&
       PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL) {
        SN_Kex_result_t kex_result;

        //associate_reply
        assert(table_entry->state == SN_Awaiting_reply);
        assert(PACKET_ENTRY(*packet, key_agreement_header, indication) != NULL);

        //finish the key agreement
        ret = SN_Crypto_key_agreement(
            self,
            &table_entry->public_key,
            &PACKET_ENTRY(*packet, key_agreement_header, indication)->key_agreement_key,
            &table_entry->local_key_agreement_keypair.private_key,
            &kex_result
        );
        if(ret != SN_OK) {
            SN_ErrPrintf("key agreement failed with %d.\n", -ret);
            return ret;
        }
        memcpy(&table_entry->link_key, &kex_result.key, sizeof(kex_result.key));
        table_entry->packet_rx_counter = table_entry->packet_tx_counter = 0;
    }

    return SN_OK;
}

int process_packet_headers(SN_Table_entry_t *table_entry, packet_t *packet) {
    network_header_t* network_header;

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //at this point, security and integrity checks are guaranteed to have passed

    //network_header
    network_header = PACKET_ENTRY(*packet, network_header, indication);
    assert(network_header != NULL);
    if(network_header->req_details) {
        SN_InfoPrintf("partner has requested our details\n");
    }
    table_entry->knows_details = (uint8_t)!PACKET_ENTRY(*packet, network_header, indication)->req_details;
    if(network_header->src_addr != SN_NO_SHORT_ADDRESS) {
        //if the remote node has a short address, we can erase its MAC address from memory
        SN_InfoPrintf("short address is known; erasing long address\n");
        memset(table_entry->long_address, 0, 8);
    }


    //node_details_header
    if(PACKET_ENTRY(*packet, node_details_header, indication) != NULL) {
        SN_InfoPrintf("processing node details header...\n");
        if(!table_entry->details_known) {
            SN_InfoPrintf("storing public key...\n");
            table_entry->details_known = 1;
            memcpy(&table_entry->public_key, &PACKET_ENTRY(*packet, node_details_header, indication)->signing_key, sizeof(table_entry->public_key));
        }
    }

    //association_header
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL) {
        association_header_t* association_header = PACKET_ENTRY(*packet, association_header, indication);

        SN_InfoPrintf("processing association header...\n");

        //relationship state is checked in packet_public_key_operations
        //signature is checked in packet_public_key_operations
        if(!association_header->dissociate) {
            //association processing
            assert(PACKET_ENTRY(*packet, key_agreement_header, indication) != NULL);
            SN_InfoPrintf("detected key agreement header\n");
            memcpy(&table_entry->remote_key_agreement_key, &PACKET_ENTRY(*packet, key_agreement_header, indication)->key_agreement_key, sizeof(table_entry->remote_key_agreement_key));

            if(PACKET_ENTRY(*packet, key_confirmation_header, indication) == NULL) {
                //associate_request
                assert(table_entry->state == SN_Unassociated);

                table_entry->child  = association_header->child;
                table_entry->router = association_header->router;

                SN_InfoPrintf("node is%s a %s child\n", (association_header->child ? "" : " not"), (association_header->router ? "router" : "leaf"));

                table_entry->state = SN_Associate_received;
            } else {
                //associate_reply
                assert(table_entry->state == SN_Awaiting_reply);
                //key agreement processing in packet_public_key_operations

                //parent/child handling
                if(association_header->child) {
                    if(network_header->src_addr != starfishnet_config.nib.parent_address) {
                        SN_ErrPrintf("received address delegation packet from someone not our parent\n");
                        return -SN_ERR_SECURITY;
                    }

                    if(starfishnet_config.mib.macShortAddress != SN_NO_SHORT_ADDRESS) {
                        SN_ErrPrintf("received address delegation when we already have a short address\n");
                        return -SN_ERR_UNEXPECTED;
                    }

                    if(starfishnet_config.nib.enable_routing) {
                        starfishnet_config.nib.enable_routing = association_header->router;
                    }

                    //set our short address to the one we were just given
                    SN_InfoPrintf("setting our short address to %#06x...\n", network_header->dst_addr);
                    starfishnet_config.mib.macShortAddress             = network_header->dst_addr;

                    if(starfishnet_config.nib.enable_routing) {
                        int ret = SN_Beacon_update();
                        if(ret != SN_OK) {
                            SN_ErrPrintf("beacon update failed: %d\n", -ret);
                            return ret;
                        }
                    }
                }
            }
        } else {
            //TODO: dissociation processing
        }
    }

    //key_confirmation_header
    if(PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL) {
        SN_Hash_t hashbuf;
        int challengenumber = PACKET_ENTRY(*packet, association_header, indication) == NULL ? 2 : 1;

        SN_InfoPrintf("processing key confirmation header...\n");

        //associate_reply
        assert(table_entry->state == SN_Awaiting_reply);

        //do the challenge1 check (double-hash)
        SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &hashbuf, challengenumber == 2 ? 0 : 1);
        SN_DebugPrintf("challenge%d (received)   = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n", challengenumber,
                       *(uint64_t *) PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data,
                       *((uint64_t *)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 1),
                       *((uint32_t *)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 4));
        SN_DebugPrintf("challenge%d (calculated) = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n", challengenumber,
                       *(uint64_t *) hashbuf.data,
                       *((uint64_t *)hashbuf.data + 1),
                       *((uint32_t *)hashbuf.data + 4));
        if(memcmp(hashbuf.data, PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
            SN_ErrPrintf("key confirmation (challenge%d) failed.\n", challengenumber);
            return -SN_ERR_KEYGEN;
        }

        //advance the relationship's state
        table_entry->state = challengenumber == 2 ? SN_Associated : SN_Send_finalise;

        SN_Transmission_acknowledge_special(table_entry, packet);
    }

    //encrypted_ack_header
    if(PACKET_ENTRY(*packet, encrypted_ack_header, indication) != NULL) {
        SN_InfoPrintf("processing encrypted acknowledgement header...\n");
        SN_Transmission_acknowledge(table_entry, PACKET_ENTRY(*packet, encrypted_ack_header, indication)->counter);
    }

    return SN_OK;
}

/*argument notes:
 * margin: how much data to skip (after the network header, before the payload) for encryption
 * safe  : if true, arrange so that the original data is untouched on a decryption failure
 */
int decrypt_verify_packet(SN_AES_key_t* link_key, SN_Public_key_t* key_agreement_key, uint32_t encryption_counter, packet_t* packet, bool pure_ack) {
    encryption_header_t* encryption_header;
    uint8_t skip_size;
    int ret;

    SN_DebugPrintf("enter\n");

    if(link_key == NULL || key_agreement_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, key_agreement_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header = PACKET_ENTRY(*packet, encryption_header, indication);
    assert(encryption_header != NULL);
    skip_size = packet->layout.encryption_header + sizeof(encryption_header_t);
    SN_InfoPrintf("attempting to decrypt packet of length %d with an encryption header at %d (counter = %x)\n", PACKET_SIZE(*packet, indication), packet->layout.encryption_header, encryption_counter);
    if(PACKET_SIZE(*packet, indication) < skip_size) {
        SN_ErrPrintf("packet is too small\n");
        return -SN_ERR_END_OF_DATA;
    }

    ret = SN_Crypto_decrypt(link_key, key_agreement_key,
                                encryption_counter,
                                packet->data, packet->layout.encryption_header,
                                packet->data + skip_size,
                                packet->length - skip_size,
                                encryption_header->tag, pure_ack);
    if(ret != SN_OK) {
        SN_ErrPrintf("Packet decryption failed with %d, aborting\n", -ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("payload decryption complete\n");

    SN_DebugPrintf("exit\n");
    return SN_OK;
}
