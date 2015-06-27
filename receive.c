#include "starfishnet.h"
#include "config.h"
#include "crypto.h"
#include "logging.h"
#include "node_table.h"
#include "status.h"
#include "retransmission_queue.h"
#include "nonqueued_transmission.h"
#include "receive.h"

#include "net/mac/frame802154.h"

#include <assert.h>
#include <string.h>

static SN_Receive_callback_t* receive_callback = NULL;

void SN_Receive(SN_Receive_callback_t* callback) {
    receive_callback = callback;
}

void SN_Receive_data_packet(packet_t* packet) {
    int ret;
    SN_Altstream_t altstream;
    SN_Endpoint_t src_addr = {.altstream = &altstream};
    SN_Message_t message;
    network_header_t* network_header;
    static SN_Table_entry_t table_entry;

    SN_InfoPrintf("enter\n");

    if(packet == NULL) {
        SN_ErrPrintf("called with null packet, aborting...\n");
        return;
    }

    SN_InfoPrintf("detecting packet layout...\n");
    ret = packet_detect_layout(packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("invalid packet received (packet_detect_layout returned %d)\n", -ret);
        return;
    }

    network_header = PACKET_ENTRY(*packet, network_header, indication);
    assert(network_header != NULL);

    SN_DebugPrintf("network layer says packet is to %#06x\n", network_header->dst_addr);
    SN_DebugPrintf("network layer says packet is from %#06x\n", network_header->src_addr);

    if(network_header->src_addr == FRAME802154_INVALIDADDR || network_header->dst_addr == FRAME802154_INVALIDADDR) {
        SN_ErrPrintf("invalid addressing information: %#06x -> %#06x. dropping\n", network_header->src_addr, network_header->dst_addr);
        return;
    }

    if(network_header->dst_addr == FRAME802154_BROADCASTADDR) {
        //TODO: broadcast handling goes here
        SN_WarnPrintf("broadcasts not currently implemented\n");
        return;
    } else {
        if(starfishnet_config.short_address != FRAME802154_INVALIDADDR &&
           network_header->dst_addr != starfishnet_config.short_address &&
           network_header->dst_addr != FRAME802154_INVALIDADDR) {
            /* packet's network-layer header is a valid
             * network-layer address that isn't ours,
             * which means we're expected to route it
             */
            SN_InfoPrintf("packet isn't for us. routing\n");
            if(starfishnet_config.enable_routing) {
                SN_Forward_Packetbuf(network_header->src_addr, network_header->dst_addr);
                return;
            } else {
                SN_WarnPrintf("received packet to route when routing was turned off. dropping\n");
                return;
            }
        } else if(starfishnet_config.short_address == FRAME802154_INVALIDADDR &&
                  network_header->src_addr == starfishnet_config.parent_address) {
            //potential address assignment from our parent. process normally
        }
    }

    SN_InfoPrintf("setting source address to %#06x\n", network_header->src_addr);
    src_addr.type          = SN_ENDPOINT_SHORT_ADDRESS;
    src_addr.short_address = network_header->src_addr;

    SN_InfoPrintf("consulting neighbor table...\n");

    if(PACKET_ENTRY(*packet, alt_stream_header, indication) != NULL) {
        altstream.stream_idx_length = PACKET_ENTRY(*packet, alt_stream_header, indication)->length;
        altstream.stream_idx = PACKET_ENTRY(*packet, alt_stream_header, indication)->stream_idx;
    }

    ret = SN_Table_lookup(&src_addr, &table_entry);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");
        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK && ret != -SN_ERR_UNEXPECTED) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return;
        }
    }

    //extract data
    SN_InfoPrintf("packet contains payload of length %d\n", packet->layout.payload_length);

    SN_InfoPrintf("doing packet security checks...\n");
    ret = packet_security_checks(packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet security checks. aborting\n", -ret);
        //certain security check failures could come from a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
        if(-ret == SN_ERR_UNEXPECTED) {
            SN_WarnPrintf("possible retransmission bug; triggering retransmission\n");
            SN_Retransmission_retry(0);

            //special case: if the security check failure is because this is a finalise, and we've already received one, it's probably an acknowledgement drop. send acknowledgements
            if(PACKET_ENTRY(*packet, key_confirmation_header, indication) != NULL && PACKET_ENTRY(*packet, association_header, indication) == NULL) {
                SN_WarnPrintf("possible dropped acknowledgement; triggering acknowledgement transmission\n");
                if(table_entry.short_address != FRAME802154_INVALIDADDR) {
                    SN_Send(&src_addr, NULL);
                }
            }
        }
        return;
    }

    SN_InfoPrintf("doing public-key operations...\n");
    ret = packet_public_key_operations(packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in public-key operations. aborting\n", -ret);
        return;
    }

    if(PACKET_ENTRY(*packet, encryption_header, indication) != NULL) {
        bool pure_ack = 0;
        SN_InfoPrintf("doing decryption and integrity checking...\n");

        if(PACKET_ENTRY(*packet, key_confirmation_header, indication) == NULL && PACKET_ENTRY(*packet, encrypted_ack_header, indication) != NULL && PACKET_ENTRY(*packet, payload_data, indication) == NULL) {
            //this is a pure-acknowledgement packet; don't change the counter
            pure_ack = 1;
        }

        if(pure_ack) {
            ret = packet_decrypt_verify(packet, &table_entry.local_key_agreement_keypair.public_key,
                                        &table_entry.link_key,
                                        PACKET_ENTRY(*packet, encrypted_ack_header, indication)->counter, 1);
        } else {
            ret = packet_decrypt_verify(packet, &table_entry.remote_key_agreement_key, &table_entry.link_key,
                                        table_entry.packet_rx_counter++, 0);
        }
        if(ret != SN_OK) {
            SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
            //certain crypto failures could be a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
            SN_WarnPrintf("crypto error could be due to dropped acknowledgement; triggering acknowledgement and packet retransmission\n");
            SN_Retransmission_retry(0);
            if(table_entry.short_address != FRAME802154_INVALIDADDR) {
                SN_Send(&src_addr, NULL);
            }
            return;
        } else {
            if(!pure_ack)
                table_entry.ack = 1;
        }
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = packet_process_headers(packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return;
    }

    table_entry.unavailable = 0;

    SN_InfoPrintf("processing packet->..\n");
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL &&
       //we have an association header, and...
       !(PACKET_ENTRY(*packet, association_header, indication)->dissociate &&
         (PACKET_ENTRY(*packet, association_header, indication)->child)
       )
        //...it's not a rights revocation
        ) {
        //this was an association packet; generate an association message
        SN_InfoPrintf("received association/dissociation request; synthesising appropriate message...\n");

        //fill in the association message contents
        message.type = PACKET_ENTRY(*packet, association_header, indication)->dissociate ? SN_Dissociation_request : SN_Association_request;
    } else if(packet->layout.payload_length != 0) {
        uint8_t* payload_data = PACKET_ENTRY(*packet, payload_data, indication);
        assert(payload_data != NULL);

        if(PACKET_ENTRY(*packet, evidence_header, indication) != NULL && PACKET_ENTRY(*packet, evidence_header, indication)->certificate) {
            SN_Certificate_t* evidence;

            //evidence packet
            if(packet->layout.payload_length != sizeof(SN_Certificate_t)) {
                SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %zu)\n", packet->layout.payload_length, sizeof(SN_Certificate_t));
                return;
            }

            //error-check the certificate, and add it to certificate storage
            evidence = (SN_Certificate_t*)payload_data;
            if(SN_Crypto_check_certificate(evidence) != SN_OK) {
                SN_ErrPrintf("received evidence packet with invalid payload\n");
                return;
            }

            //fill in message structure
            message.type                               = SN_Explicit_Evidence_message;
            message.explicit_evidence_message.evidence = evidence;
        } else {
            if(PACKET_ENTRY(*packet, evidence_header, indication) != NULL) {
                SN_WarnPrintf("don't yet know how to handle implicit evidence packets");
                //TODO: implicit evidence packets
            }

            //data packet
            if(PACKET_ENTRY(*packet, encryption_header, indication) == NULL) {
                //stapled plain data on unencrypted packet-> warn and ignore
                SN_WarnPrintf("received plain data in unencrypted packet-> ignoring.\n");
            } else {
                message.type                        = SN_Data_message;
                message.data_message.payload_length = packet->layout.payload_length;
                message.data_message.payload        = payload_data;
            }
        }
    }

    SN_Table_update(&table_entry);

    if(message.type != SN_No_message) {
        if(receive_callback)
            receive_callback(&src_addr, &message);
    }

    SN_InfoPrintf("exit\n");
}
