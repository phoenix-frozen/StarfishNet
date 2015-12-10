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

#include "starfishnet.h"
#include "crypto.h"
#include "node_table.h"
#include "logging.h"
#include "status.h"
#include "packet.h"
#include "reliable_tx.h"
#include "util.h"
#include "config.h"
#include "discovery.h"
#include "routing_tree.h"
#include "constants.h"
#include "dmem.h"
#include "raw_tx.h"
#include "types.h"

#include "net/packetbuf.h"

#include <string.h>
#include <assert.h>

static void allocate_address(packet_t* packet, SN_Table_entry_t* table_entry) {
    uint8_t block = PACKET_ENTRY(*packet, association_header)->router;
    uint16_t address;
    int8_t ret = SN_Tree_allocate_address(&address, &block);

    if(ret == SN_OK) {
        PACKET_ENTRY(*packet, network_header)->dst_addr   = address;
        PACKET_ENTRY(*packet, association_header)->router = block;

        SN_InfoPrintf("allocated %s address 0x%04x\n", block ? "router" : "leaf", address);

        table_entry->short_address = address;
        SN_Beacon_update();
    } else {
        SN_WarnPrintf("address allocation failed; proceeding without\n");

        PACKET_ENTRY(*packet, association_header)->child  = 0;
        PACKET_ENTRY(*packet, association_header)->router = 0;
    }
}

#define NETWORK_HEADER PACKET_ENTRY(*packet, network_header)
static void generate_network_header(packet_t* packet, SN_Table_entry_t* table_entry, const SN_Message_t* message) {
    SN_InfoPrintf("enter\n");

    //network_header_t
    packet->layout.network_header         = 0;
    packet->layout.present.network_header = 1;
    assert(NETWORK_HEADER != NULL);
    NETWORK_HEADER->protocol_id  = STARFISHNET_PROTOCOL_ID;
    NETWORK_HEADER->protocol_ver = STARFISHNET_PROTOCOL_VERSION;
    NETWORK_HEADER->src_addr     = starfishnet_config.short_address;
    NETWORK_HEADER->dst_addr     = table_entry->short_address;
    NETWORK_HEADER->attributes   = 0;
    NETWORK_HEADER->alt_stream   = (uint8_t)(table_entry->altstream.stream_idx_length > 0);
    if(message == NULL || (message->type != SN_Association_request && message->type != SN_Dissociation_request)) { //data packet
        NETWORK_HEADER->data = 1;

        if(message == NULL) {
            NETWORK_HEADER->data_attributes.evidence = 0;
            NETWORK_HEADER->data_attributes.ack = 1;
        } else {
            NETWORK_HEADER->data_attributes.evidence = (uint8_t)(message->type > SN_Data_message);
            if(message->type == SN_Data_message && message->data_message.payload_length <= (SN_MAX_DATA_MESSAGE_LENGTH - sizeof(encrypted_ack_header_t))) {
                NETWORK_HEADER->data_attributes.ack = (uint8_t) table_entry->ack;
                table_entry->ack = 0;
            } else {
                //evidence messages are too big to include acknowledgement headers
                NETWORK_HEADER->data_attributes.ack = 0;
            }
        }

        if(table_entry->state == SN_Send_finalise) {
            NETWORK_HEADER->data_attributes.key_confirm = 1;
            table_entry->state = SN_Associated;
        }
    } else { //control packet
        NETWORK_HEADER->data = 0;
        NETWORK_HEADER->control_attributes.associate   = (uint8_t)(uint8_t)(message->type == SN_Association_request || message->type == SN_Dissociation_request);
        NETWORK_HEADER->control_attributes.req_details = (uint8_t)!table_entry->details_known;
        NETWORK_HEADER->control_attributes.details     = (uint8_t)!table_entry->knows_details;

        if(NETWORK_HEADER->control_attributes.associate && table_entry->state == SN_Associate_received) {
            NETWORK_HEADER->control_attributes.key_confirm = 1;
            table_entry->state = SN_Awaiting_finalise;
        } else if(NETWORK_HEADER->control_attributes.associate) {
            table_entry->state = SN_Awaiting_reply;
        }

        if(NETWORK_HEADER->control_attributes.details) {
            table_entry->knows_details = 1;
        }
    }
    PACKET_SIZE(*packet) = sizeof(network_header_t);

    SN_InfoPrintf("exit\n");
}

static int8_t generate_subheaders(packet_t *packet, SN_Table_entry_t *table_entry, const SN_Message_t *message) {
    SN_InfoPrintf("enter\n");

    //alt_stream_header_t
    if(ATTRIBUTE(NETWORK_HEADER, alt_stream)) {
        SN_InfoPrintf("generating alternate stream header at %d\n", PACKET_SIZE(*packet));
        if(PACKET_SIZE(*packet) + sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length >
           SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }

        packet->layout.alt_stream_header = PACKET_SIZE(*packet);
        packet->layout.present.alt_stream_header = 1;
        PACKET_SIZE(*packet) += sizeof(alt_stream_header_t) + table_entry->altstream.stream_idx_length;

        PACKET_ENTRY(*packet, alt_stream_header)->length = table_entry->altstream.stream_idx_length;
        memcpy(PACKET_ENTRY(*packet, alt_stream_header)->stream_idx, table_entry->altstream.stream_idx, table_entry->altstream.stream_idx_length);
    }

    if(!ATTRIBUTE(NETWORK_HEADER, data)) {
        //node_details_header_t
        if (CONTROL_ATTRIBUTE(NETWORK_HEADER, details)) {
            SN_InfoPrintf("generating node details header at %d\n", PACKET_SIZE(*packet));
            if (PACKET_SIZE(*packet) + sizeof(node_details_header_t) > SN_MAXIMUM_PACKET_SIZE) {
                SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }

            packet->layout.node_details_header = PACKET_SIZE(*packet);
            packet->layout.present.node_details_header = 1;
            PACKET_SIZE(*packet) += sizeof(node_details_header_t);

            memcpy(&PACKET_ENTRY(*packet, node_details_header)->signing_key,
                   &starfishnet_config.device_root_key.public_key,
                   sizeof(starfishnet_config.device_root_key.public_key));
        }

        //association_header_t
        if (CONTROL_ATTRIBUTE(NETWORK_HEADER, associate)) {
            SN_InfoPrintf("generating association header at %d\n", PACKET_SIZE(*packet));
            if (PACKET_SIZE(*packet) + sizeof(association_header_t) > SN_MAXIMUM_PACKET_SIZE) {
                SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }

            packet->layout.association_header = PACKET_SIZE(*packet);
            packet->layout.present.association_header = 1;
            PACKET_SIZE(*packet) += sizeof(association_header_t);
#define ASSOCIATION_HEADER PACKET_ENTRY(*packet, association_header)
            assert(ASSOCIATION_HEADER != NULL);
            assert(message != NULL);

            ASSOCIATION_HEADER->flags = 0;
            ASSOCIATION_HEADER->dissociate = (uint8_t) (message->type == SN_Dissociation_request ? 1 : 0);

            if (!ASSOCIATION_HEADER->dissociate) {
                //key_agreement_header_t
                packet->layout.key_agreement_header = PACKET_SIZE(*packet);
                packet->layout.present.key_agreement_header = 1;
                PACKET_SIZE(*packet) += sizeof(key_agreement_header_t);

                memcpy(&PACKET_ENTRY(*packet, key_agreement_header)->key_agreement_key,
                       &table_entry->local_key_agreement_keypair.public_key,
                       sizeof(table_entry->local_key_agreement_keypair.public_key));

                //parent/child handling
                if (CONTROL_ATTRIBUTE(NETWORK_HEADER, key_confirm)) {
                    //this is a reply

                    //address bits
                    ASSOCIATION_HEADER->child = (uint8_t) table_entry->child;
                    ASSOCIATION_HEADER->router = (uint8_t) table_entry->router;

                    //address allocation
                    if (ASSOCIATION_HEADER->child) {
                        SN_InfoPrintf("node is our child; allocating it an address...\n");
                        allocate_address(packet, table_entry);
                    }
                } else {
                    //this is a request
                    ASSOCIATION_HEADER->router = starfishnet_config.enable_routing;
                    ASSOCIATION_HEADER->child = starfishnet_config.parent_address == table_entry->short_address ? (uint8_t)1 : (uint8_t)0;
                }
            }
#undef ASSOCIATION_HEADER
        }
    }

    //key_confirmation_header_t
    if(ATTRIBUTE(NETWORK_HEADER, key_confirm)) {
        SN_InfoPrintf("generating key confirmation header (challenge%d) at %d\n", CONTROL_ATTRIBUTE(NETWORK_HEADER, associate) ? 1 : 2, PACKET_SIZE(*packet));
        if(PACKET_SIZE(*packet) + sizeof(key_confirmation_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding node details header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.key_confirmation_header = PACKET_SIZE(*packet);
        packet->layout.present.key_confirmation_header = 1;
        PACKET_SIZE(*packet) += sizeof(key_confirmation_header_t);

        SN_Crypto_hash(table_entry->link_key.key.data, sizeof(table_entry->link_key.key.data), &PACKET_ENTRY(*packet, key_confirmation_header)->challenge);
        if(CONTROL_ATTRIBUTE(NETWORK_HEADER, associate)) {
            //this is a reply; do challenge1 (double-hash)
            SN_Crypto_hash(PACKET_ENTRY(*packet, key_confirmation_header)->challenge.data, SN_Hash_size, &PACKET_ENTRY(*packet, key_confirmation_header)->challenge);
        }
    }

    if(ATTRIBUTE(NETWORK_HEADER, data)) {
        //encrypted_ack_header_t
        if (DATA_ATTRIBUTE(NETWORK_HEADER, ack)) {
            SN_InfoPrintf("generating encrypted-ack header at %d\n", PACKET_SIZE(*packet));
            if (PACKET_SIZE(*packet) + sizeof(encrypted_ack_header_t) > SN_MAXIMUM_PACKET_SIZE) {
                SN_ErrPrintf("adding encrypted_ack header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet->layout.encrypted_ack_header = PACKET_SIZE(*packet);
            packet->layout.present.encrypted_ack_header = 1;
            PACKET_SIZE(*packet) += sizeof(encrypted_ack_header_t);

            PACKET_ENTRY(*packet, encrypted_ack_header)->counter = table_entry->packet_rx_counter - 1;
        }

        //evidence_header_t
        if (DATA_ATTRIBUTE(NETWORK_HEADER, evidence)) {
            SN_InfoPrintf("generating evidence header at %d\n", PACKET_SIZE(*packet));

            if (PACKET_SIZE(*packet) + sizeof(evidence_header_t) > SN_MAXIMUM_PACKET_SIZE) {
                SN_ErrPrintf("adding evidence header would make packet too large, aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet->layout.evidence_header = PACKET_SIZE(*packet);
            packet->layout.present.evidence_header = 1;
            PACKET_SIZE(*packet) += sizeof(evidence_header_t);

            PACKET_ENTRY(*packet, evidence_header)->flags = 0;
        }

        //{encryption,signature}_header_t
        SN_InfoPrintf("generating encryption header at %d\n", PACKET_SIZE(*packet));
        if (PACKET_SIZE(*packet) + sizeof(encryption_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.encryption_header = PACKET_SIZE(*packet);
        packet->layout.present.encryption_header = 1;
        PACKET_SIZE(*packet) += sizeof(encryption_header_t);
    } else {
        SN_InfoPrintf("generating signature header at %d\n", PACKET_SIZE(*packet));

        if(PACKET_SIZE(*packet) + sizeof(signature_header_t) > SN_MAXIMUM_PACKET_SIZE) {
            SN_ErrPrintf("adding encryption header would make packet too large, aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet->layout.signature_header = PACKET_SIZE(*packet);
        packet->layout.present.signature_header = 1;
        PACKET_SIZE(*packet) += sizeof(signature_header_t);
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
#undef NETWORK_HEADER
}

static int8_t packet_generate_payload(packet_t* packet, const SN_Message_t* message) {
    uint8_t* payload = NULL;
    uint8_t payload_length = 0;

    if(message == NULL) {
        return -SN_ERR_NULL;
    }

    if(!ATTRIBUTE(PACKET_ENTRY(*packet, network_header), data)) {
        return -SN_ERR_INVALID;
    }

    switch(message->type) {
        case SN_Data_message:
            if(packet->layout.present.evidence_header) {
                return -SN_ERR_INVALID;
            }
            payload = message->data_message.payload;
            payload_length = message->data_message.payload_length;
            break;

        case SN_Explicit_Evidence_message:
            if(!packet->layout.present.evidence_header) {
                return -SN_ERR_INVALID;
            }
            payload = (uint8_t*)&message->explicit_evidence_message.evidence;
            payload_length = sizeof(SN_Certificate_t);
            PACKET_ENTRY(*packet, evidence_header)->certificate = 1;
            break;

        case SN_Implicit_Evidence_message:
            //TODO: WRITEME (implicit evidence message)

        default:
            SN_ErrPrintf("invalid message type %d, aborting\n", message->type);
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("generating %s payload at %d (%d bytes)\n", message->type == SN_Data_message ? "data" : "evidence", PACKET_SIZE(*packet), payload_length);

    if(PACKET_SIZE(*packet) + payload_length > SN_MAXIMUM_PACKET_SIZE) {
        SN_ErrPrintf("packet is too large, at %d bytes (maximum length is %d bytes)\n",
                     PACKET_SIZE(*packet) + payload_length, SN_MAXIMUM_PACKET_SIZE);
        return -SN_ERR_RESOURCES;
    }

    packet->layout.payload_length = payload_length;
    if(payload_length > 0) {
        assert(payload != NULL);

        packet->layout.payload_data = PACKET_SIZE(*packet);
        packet->layout.present.payload_data = 1;
        PACKET_SIZE(*packet) += payload_length;

        memcpy(PACKET_ENTRY(*packet, payload_data), payload, payload_length);
    } else {
        SN_WarnPrintf("no payload to generate\n");
    }

    return SN_OK;
}

static SN_Table_entry_t table_entry;
static packet_t packet;

static int8_t transmission_preamble(const SN_Endpoint_t *dst_addr) {
    if (dst_addr != NULL) {
        //basic address validity checking
        switch (dst_addr->type) {
            case SN_ENDPOINT_SHORT_ADDRESS:
                if (dst_addr->short_address == FRAME802154_INVALIDADDR) {
                    SN_ErrPrintf("attempting to send to null short address. aborting\n");
                    return -SN_ERR_INVALID;
                }
                break;

            case SN_ENDPOINT_LONG_ADDRESS:
                if ((uint8_t) memcmp(dst_addr->long_address, null_address, sizeof(null_address)) == 0) {
                    SN_ErrPrintf("attempting to send to null long address. aborting\n");
                    return -SN_ERR_INVALID;
                }
                break;

            case SN_ENDPOINT_PUBLIC_KEY:
                if ((uint8_t) memcmp(dst_addr->public_key.data, null_key.data, sizeof(null_key.data)) == 0) {
                    SN_ErrPrintf("attempting to send to null public key. aborting\n");
                    return -SN_ERR_INVALID;
                }
                break;

            default:
                SN_ErrPrintf("invalid address type. aborting\n");
                return -SN_ERR_INVALID;
        }
    }

    //initialise common data structures: packet structure buffer and packetbuf
    memset(&packet, 0, sizeof(packet));
    packetbuf_clear();
    packet.data = packetbuf_dataptr();

    return SN_OK;
}

int8_t SN_Send_acknowledgements(SN_Table_entry_t* table_entry) {
    int8_t ret;

    SN_InfoPrintf("enter\n");

    //initial NULL-checks
    ret = transmission_preamble(NULL);
    if(ret != SN_OK) {
        return ret;
    }

    if (table_entry->short_address == FRAME802154_INVALIDADDR) {
        SN_ErrPrintf("remote node doesn't have a short address\n");
        return -SN_ERR_DISCONNECTED;
    }

    generate_network_header(&packet, table_entry, NULL);
    ret = generate_subheaders(&packet, table_entry, NULL);
    if (ret != SN_OK) {
        SN_ErrPrintf("header generation error: %d\n", -ret);
        return ret;
    }

    if(!packet.layout.present.encrypted_ack_header || table_entry->packet_rx_counter == 0) {
        SN_WarnPrintf("acknowledgements aren't required\n");
        return -SN_ERR_UNEXPECTED;
    }

    assert(packet.layout.present.encryption_header);
    assert(!packet.layout.present.signature_header);
    assert(!packet.layout.present.association_header);
    assert(!packet.layout.present.key_confirmation_header);
    assert(PACKET_ENTRY(packet, encrypted_ack_header)->counter + 1 == table_entry->packet_rx_counter);
    assert(packet.layout.encryption_header + (uint8_t)sizeof(encryption_header_t) == packet.length);

    //this is a pure-acknowledgement packet; don't change the counter
    ret = SN_Crypto_encrypt(&table_entry->link_key.key, &table_entry->local_key_agreement_keypair.public_key,
                            table_entry->packet_rx_counter - 1,
                            packet.data, packet.layout.encryption_header,
                            NULL, 0,
                            PACKET_ENTRY(packet, encryption_header)->tag, 1);

    if (ret != SN_OK) {
        SN_ErrPrintf("crypto error: %d\n", -ret);
        return ret;
    }

    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
    packetbuf_set_attr(PACKETBUF_ATTR_NETWORK_ID, starfishnet_config.pan_id);
    packetbuf_set_datalen(PACKET_SIZE(packet));
    ret = SN_Forward_Packetbuf(starfishnet_config.short_address, table_entry->short_address);
    if (ret != SN_OK) {
        SN_ErrPrintf("transmission error: %d\n", -ret);
        return ret;
    }

    //we've changed the table entry. update it
    SN_Table_update(table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int8_t SN_Send(const SN_Endpoint_t *dst_addr, const SN_Message_t *message) {
    int8_t ret;

    SN_InfoPrintf("enter\n");

    //initial NULL-checks
    if(dst_addr == NULL) {
        return -SN_ERR_NULL;
    }

    ret = transmission_preamble(NULL);
    if(ret != SN_OK) {
        return ret;
    }

    if(message == NULL || (message->type != SN_Data_message && message->type != SN_Explicit_Evidence_message)) {
        return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    ret = SN_Table_lookup(dst_addr, &table_entry);
    if (ret != SN_OK || table_entry.state < SN_Send_finalise) { //node isn't in node table, abort
        SN_ErrPrintf("no relationship with remote node\n");
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("sending to 0x%04x (state %d)\n", table_entry.short_address, table_entry.state);

    if (table_entry.unavailable) {
        SN_ErrPrintf("contact with remote node has been lost\n");
        return -SN_ERR_DISCONNECTED;
    }

    generate_network_header(&packet, &table_entry, message);
    ret = generate_subheaders(&packet, &table_entry, message);
    if (ret != SN_OK) {
        SN_ErrPrintf("header generation error: %d\n", -ret);
        return ret;
    }

    ret = packet_generate_payload(&packet, message);
    if (!(ret == SN_OK || ret == -SN_ERR_NULL || ret == -SN_ERR_INVALID)) {
        SN_ErrPrintf("payload generation error: %d\n", -ret);
        return ret;
    }

    assert(packet.layout.present.encryption_header);
    assert(!packet.layout.present.signature_header);
    ret = SN_Crypto_encrypt(&table_entry.link_key.key, &table_entry.local_key_agreement_keypair.public_key,
                            table_entry.packet_tx_counter++,
                            packet.data, packet.layout.encryption_header,
                            packet.data + (packet.layout.encryption_header + (uint8_t) sizeof(encryption_header_t)),
                            packet.length -
                            (packet.layout.encryption_header + (uint8_t) sizeof(encryption_header_t)),
                            PACKET_ENTRY(packet, encryption_header)->tag, 0);
    if (ret != SN_OK) {
        SN_ErrPrintf("crypto error: %d\n", -ret);
        return ret;
    }

    ret = SN_Retransmission_send(&packet, &table_entry);
    if (ret != SN_OK) {
        SN_ErrPrintf("transmission error: %d\n", -ret);
        return ret;
    }

    //we've changed the table entry. update it
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

static const SN_Message_t associate_message = {
    .type = SN_Association_request
};

int8_t SN_Associate(const SN_Endpoint_t *dst_addr) {
    int8_t ret;

    SN_InfoPrintf("enter\n");

    //initial NULL-checks
    if(dst_addr == NULL) {
        return -SN_ERR_NULL;
    }

    ret = transmission_preamble(dst_addr);
    if (ret != SN_OK) {
        return ret;
    }

    SN_InfoPrintf("consulting neighbor table...\n");
    ret = SN_Table_lookup(dst_addr, &table_entry);
    if (ret != SN_OK) {
        memset(&table_entry, 0, sizeof(table_entry));
        table_entry.short_address = FRAME802154_INVALIDADDR;

        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        switch (dst_addr->type) {
            case SN_ENDPOINT_SHORT_ADDRESS:
                if(dst_addr->short_address == FRAME802154_INVALIDADDR) {
                    SN_ErrPrintf("attempting to transmit to invalid%s\n", "short address");
                    return -SN_ERR_INVALID;
                }
                table_entry.short_address = dst_addr->short_address;
                break;

            case SN_ENDPOINT_LONG_ADDRESS:
                if(!memcmp(dst_addr->long_address, null_address, 8)) {
                    SN_ErrPrintf("attempting to transmit to invalid%s\n", "long address");
                    return -SN_ERR_INVALID;
                }
                ALLOCATE_ARRAY_COND(table_entry.long_address, 8, {
                    SN_InfoPrintf("failed to allocate space for long address storage\n");
                    return -SN_ERR_RESOURCES;
                });
                memcpy(table_entry.long_address, dst_addr->long_address, 8);
                break;

            case SN_ENDPOINT_PUBLIC_KEY:
                if(!memcmp(&dst_addr->public_key, &null_key, sizeof(null_key))) {
                    SN_ErrPrintf("attempting to transmit to invalid%s\n", "key");
                    return -SN_ERR_INVALID;
                }
                table_entry.details_known = 1;
                memcpy(&table_entry.public_key, &dst_addr->public_key, sizeof(dst_addr->public_key));
                break;

            default:
                SN_ErrPrintf("invalid address type: %d\n", dst_addr->type);
                return -SN_ERR_INVALID;
        }
        ret = SN_Table_insert(&table_entry);
        if (ret != SN_OK) {
            SN_ErrPrintf("node table is full\n");
            if(table_entry.long_address != NULL) {
                FREE(table_entry.long_address);
            }
            return -SN_ERR_RESOURCES;
        }
    }

    SN_InfoPrintf("sending to 0x%04x (state %d)\n", table_entry.short_address, table_entry.state);

    //check the association state, and do appropriate crypto work
    if (table_entry.state == SN_Unassociated || table_entry.state == SN_Associate_received) {
        SN_InfoPrintf("generating ECDH keypair\n");

        //generate ephemeral keypair
        ret = SN_Crypto_generate_keypair(&table_entry.local_key_agreement_keypair);
        if (ret != SN_OK) {
            SN_ErrPrintf("key generation error: %d\n", -ret);
            return -SN_ERR_KEYGEN;
        }
    } else {
        SN_ErrPrintf("can't associate in state %d\n", table_entry.state);
        return -SN_ERR_UNEXPECTED;
    }

    if (table_entry.state == SN_Associate_received) {
        SN_InfoPrintf("doing ECDH\n");

        //do ECDH math
        ret = SN_Crypto_key_agreement(
            &table_entry.public_key,
            &starfishnet_config.device_root_key.public_key,
            &table_entry.remote_key_agreement_key,
            &table_entry.local_key_agreement_keypair.private_key,
            &table_entry.link_key
        );
        if (ret != SN_OK) {
            SN_ErrPrintf("ECDH error: %d\n", -ret);
            return ret;
        }
        table_entry.packet_rx_counter = table_entry.packet_tx_counter = 0;

    }

    generate_network_header(&packet, &table_entry, &associate_message);
    ret = generate_subheaders(&packet, &table_entry, &associate_message);
    if (ret != SN_OK) {
        SN_ErrPrintf("header generation error: %d\n", -ret);
        return ret;
    }

    assert(packet.layout.present.signature_header);
    assert(!packet.layout.present.encryption_header);

    ret = SN_Crypto_sign(
        &starfishnet_config.device_root_key.private_key,
        packet.data,
        packet.layout.signature_header,
        &PACKET_ENTRY(packet, signature_header)->signature);

    if (ret != SN_OK) {
        SN_ErrPrintf("crypto error: %d\n", -ret);
        return ret;
    }

    ret = SN_Retransmission_send(&packet, &table_entry);
    if (ret != SN_OK) {
        SN_ErrPrintf("transmission error: %d\n", -ret);
        return ret;
    }

    //we've changed the table entry. update it
    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
