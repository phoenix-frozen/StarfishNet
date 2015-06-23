#include <assert.h>
#include <string.h>
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "lib/random.h"

#include "starfishnet.h"
#include "config.h"
#include "crypto.h"
#include "logging.h"
#include "uECC.h"
#include "node_table.h"
#include "packet.h"
#include "status.h"
#include "retransmission_queue.h"
#include "nonqueued_transmission.h"

static int generate_random_number(uint8_t *dest, unsigned size) {
    uint16_t rand;

    for(; size > 1; size -= 2, dest += 2) {
        rand = random_rand();
        memcpy(dest, &rand, 2);
    }

    if(size > 0) {
        rand = random_rand();
        memcpy(dest, &rand, 1);
    }

    return 1;
}

static void init(void) {
    radio_value_t radio_result;

    SN_InfoPrintf("enter\n");
    queuebuf_init();
    packetbuf_clear();

    uECC_set_rng(&generate_random_number);

    //populate configuration structure
    //designed so that we can store a root key in future...
    if(!starfishnet_config.device_root_key_valid) {
        SN_WarnPrintf("generating new device root key\n");
        SN_Crypto_generate_keypair(&starfishnet_config.device_root_key);
    }
    NETSTACK_RADIO.get_object(RADIO_PARAM_64BIT_ADDR, starfishnet_config.mib.macExtendedAddress, 8);
    if(NETSTACK_RADIO.get_value(RADIO_PARAM_PAN_ID, &radio_result) == RADIO_RESULT_OK) {
        starfishnet_config.mib.macPANId = (uint16_t)radio_result;
    }

    //set up the radio with an invalid short address
    NETSTACK_RADIO.set_value(RADIO_PARAM_16BIT_ADDR, SN_NO_SHORT_ADDRESS);

    //TODO: other init stuff goes in here
    SN_InfoPrintf("exit\n");
}

static SN_Receive_callback_t receive_callback = NULL;

void SN_Receive(SN_Receive_callback_t callback) {
    receive_callback = callback;
}

static void input(void) {
    int ret;
    packet_t packet;
    SN_Altstream_t altstream;
    SN_Endpoint_t src_addr = {.altstream = &altstream};
    SN_Message_t message;
    network_header_t* network_header;
    static SN_Table_entry_t table_entry;

    SN_InfoPrintf("enter\n");

    //print some debugging information
    if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet to %#018"PRIx64"\n", *(uint64_t*)(packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8));
    } else {
        SN_DebugPrintf("received packet to %#06x\n", packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u16);
    }
    if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet from %#018"PRIx64"\n", *(uint64_t*)(packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8));
    } else {
        SN_DebugPrintf("received packet from %#06x\n", packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16);
    }
    packet.length = (uint8_t)packetbuf_datalen(); //cast is safe because datalen <= 128
    packet.data = packetbuf_dataptr();
    SN_InfoPrintf("received packet containing %d-byte payload\n", meta.length);

    SN_InfoPrintf("detecting packet layout...\n");
    ret = packet_detect_layout(&packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("invalid packet received (packet_detect_layout returned %d)\n", -ret);
        return;
    }

    network_header = PACKET_ENTRY(packet, network_header, indication);
    assert(network_header != NULL);

    SN_DebugPrintf("network layer says packet is to %#06x\n", network_header->dst_addr);
    SN_DebugPrintf("network layer says packet is from %#06x\n", network_header->src_addr);

    if(starfishnet_config.mib.macShortAddress != SN_NO_SHORT_ADDRESS && network_header->dst_addr != starfishnet_config.mib.macShortAddress) {
        //packet was sent to our MAC address, but wasn't for our network address. that means we need to route it
        SN_InfoPrintf("packet isn't for us. routing\n");
        if(starfishnet_config.nib.enable_routing) {
            SN_TX_Packetbuf(network_header->src_addr, network_header->dst_addr);
            return;
        } else {
            SN_WarnPrintf("received packet to route when routing was turned off. dropping\n");
            return;
        }
    }

    if(network_header->src_addr == SN_NO_SHORT_ADDRESS) {
        SN_WarnPrintf("network header has no address; using MAC-layer header\n");
        if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) == 8) {
            src_addr.type = SN_ENDPOINT_LONG_ADDRESS;
            memcpy(src_addr.long_address, packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8, 8);
        } else {
            src_addr.type = SN_ENDPOINT_SHORT_ADDRESS;
            src_addr.short_address = packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16;
        }
    } else {
        SN_InfoPrintf("setting source address to %#06x\n", network_header->src_addr);
        src_addr.type          = SN_ENDPOINT_SHORT_ADDRESS;
        src_addr.short_address = network_header->src_addr;
    }

    SN_InfoPrintf("consulting neighbor table...\n");

    if(PACKET_ENTRY(packet, alt_stream_header, indication) != NULL) {
        altstream.stream_idx_length = PACKET_ENTRY(packet, alt_stream_header, indication)->length;
        altstream.stream_idx = PACKET_ENTRY(packet, alt_stream_header, indication)->stream_idx;
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
    SN_InfoPrintf("packet contains payload of length %d\n", packet.layout.payload_length);

    SN_InfoPrintf("doing packet security checks...\n");
    ret = packet_security_checks(&packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet security checks. aborting\n", -ret);
        //certain security check failures could come from a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
        if(-ret == SN_ERR_UNEXPECTED) {
            SN_WarnPrintf("possible retransmission bug; triggering retransmission\n");
            SN_Retransmission_retry(0);

            //special case: if the security check failure is because this is a finalise, and we've already received one, it's probably an acknowledgement drop. send acknowledgements
            if(PACKET_ENTRY(packet, key_confirmation_header, indication) != NULL && PACKET_ENTRY(packet, association_header, indication) == NULL) {
                SN_WarnPrintf("possible dropped acknowledgement; triggering acknowledgement transmission\n");
                if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                    SN_Altstream_t ack_altstream;
                    SN_Endpoint_t ack_address = {
                        .type = SN_ENDPOINT_SHORT_ADDRESS,
                        .short_address = table_entry.short_address,
                        .altstream = &ack_altstream,
                    };

                    //this should be an initialiser, but SDCC freaks out
                    ack_altstream.stream_idx        = table_entry.altstream.stream_idx;
                    ack_altstream.stream_idx_length = table_entry.altstream.stream_idx_length;

                    SN_Send(&ack_address, NULL);
                }
            }
        }
        return;
    }

    SN_InfoPrintf("doing public-key operations...\n");
    ret = packet_public_key_operations(&packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in public-key operations. aborting\n", -ret);
        return;
    }

    if(PACKET_ENTRY(packet, encryption_header, indication) != NULL) {
        bool pure_ack = 0;
        SN_InfoPrintf("doing decryption and integrity checking...\n");

        if(PACKET_ENTRY(packet, key_confirmation_header, indication) == NULL && PACKET_ENTRY(packet, encrypted_ack_header, indication) != NULL && PACKET_ENTRY(packet, payload_data, indication) == NULL) {
            //this is a pure-acknowledgement packet; don't change the counter
            pure_ack = 1;
        }

        if(pure_ack) {
            ret = packet_decrypt_verify(&packet, &table_entry.local_key_agreement_keypair.public_key,
                                        &table_entry.link_key,
                                        PACKET_ENTRY(packet, encrypted_ack_header, indication)->counter, 1);
        } else {
            ret = packet_decrypt_verify(&packet, &table_entry.remote_key_agreement_key, &table_entry.link_key,
                                        table_entry.packet_rx_counter++, 0);
        }
        if(ret != SN_OK) {
            SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
            //certain crypto failures could be a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
            SN_WarnPrintf("crypto error could be due to dropped acknowledgement; triggering acknowledgement and packet retransmission\n");
            SN_Retransmission_retry(0);
            if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                SN_Altstream_t ack_altstream;
                SN_Endpoint_t ack_address = {
                    .type = SN_ENDPOINT_SHORT_ADDRESS,
                    .short_address = table_entry.short_address,
                    .altstream = &ack_altstream,
                };

                //this should be an initialiser, but SDCC freaks out
                ack_altstream.stream_idx        = table_entry.altstream.stream_idx;
                ack_altstream.stream_idx_length = table_entry.altstream.stream_idx_length;

                SN_Send(&ack_address, NULL);
            }
            return;
        } else {
            if(!pure_ack)
                table_entry.ack = 1;
        }
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = packet_process_headers(&packet, &table_entry);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return;
    }

    table_entry.unavailable = 0;

    SN_InfoPrintf("processing packet...\n");
    if(PACKET_ENTRY(packet, association_header, indication) != NULL &&
       //we have an association header, and...
       !(PACKET_ENTRY(packet, association_header, indication)->dissociate &&
         (PACKET_ENTRY(packet, association_header, indication)->child)
       )
        //...it's not a rights revocation
        ) {
        //this was an association packet; generate an association message
        SN_InfoPrintf("received association/dissociation request; synthesising appropriate message...\n");

        //fill in the association message contents
        message.type = PACKET_ENTRY(packet, association_header, indication)->dissociate ? SN_Dissociation_request : SN_Association_request;
    } else if(packet.layout.payload_length != 0) {
        uint8_t* payload_data = PACKET_ENTRY(packet, payload_data, indication);
        assert(payload_data != NULL);

        if(PACKET_ENTRY(packet, evidence_header, indication) != NULL && PACKET_ENTRY(packet, evidence_header, indication)->certificate) {
            SN_Certificate_t* evidence;

            //evidence packet
            if(packet.layout.payload_length != sizeof(SN_Certificate_t)) {
                SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %zu)\n", packet.layout.payload_length, sizeof(SN_Certificate_t));
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
            if(PACKET_ENTRY(packet, evidence_header, indication) != NULL) {
                SN_WarnPrintf("don't yet know how to handle implicit evidence packets");
                //TODO: implicit evidence packets
            }

            //data packet
            if(PACKET_ENTRY(packet, encryption_header, indication) == NULL) {
                //stapled plain data on unencrypted packet. warn and ignore
                SN_WarnPrintf("received plain data in unencrypted packet. ignoring.\n");
            } else {
                message.type                        = SN_Data_message;
                message.data_message.payload_length = packet.layout.payload_length;
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

const struct network_driver starfishnet_driver = {
  "StarfishNet",
  init,
  input
};
