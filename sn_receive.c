//StarfishNet message transmission rules are in sn_transmit.c

#include "sn_core.h"
#include "crypto.h"
#include "node_table.h"
#include "logging.h"
#include "status.h"
#include "constants.h"
#include "packet.h"
#include "retransmission_queue.h"
#include "sn_beacons.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

static int do_queued_receive_exactly(SN_Session_t* session, const mac_primitive_t* primitive) {
    if(session == NULL || primitive == NULL) {
        return -SN_ERR_NULL;
    }

    mac_primitive_t packet;

    while(1) {
        int ret = mac_receive(session->mac_session, &packet);
        if(ret <= 0)
            return -SN_ERR_RADIO;

        if(packet.type == primitive->type) {
            if(memcmp(&packet, primitive, (size_t)ret)) {
                //they're different
                return -SN_ERR_UNEXPECTED;
            } else {
                return SN_OK;
            }
        } else {
            SN_Enqueue(session, &packet); //implicitly drops irrelevant primitives
        }
    }
}

//receive packet, decoding into one or more messages
int SN_Receive(SN_Session_t *session, SN_Endpoint_t *src_addr, SN_Message_t *buffer,
               size_t buffer_size) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || src_addr == NULL || buffer == NULL || buffer_size == 0) {
        SN_ErrPrintf("session, src_addr, buffer, and buffer_size must all be valid\n");
        return -SN_ERR_NULL;
    }

    if(buffer_size < sizeof(buffer->association_message)) {
        //too small to even hold an associate message, hence too small for anything
        SN_ErrPrintf("buffer is below minimum size (is %zu bytes, should be %zu bytes)\n", buffer_size, sizeof(buffer->association_message));
        return -SN_ERR_RESOURCES;
    }

    SN_DebugPrintf("output buffer size is %ld\n", buffer_size);

    packet_t packet;
    SN_InfoPrintf("receiving packet...\n");

    int ret = 0;

    //this is the receive loop. takes timeouts into account, and does retransmissions every timeout
    while(1) {
        //check the receive queue
        if(SN_Dequeue(session, &packet.contents, mac_mcps_data_indication) == SN_OK) {
            break;
        }

        //receive queue was empty. wait for a packet from the radio
        struct timeval tv = {.tv_usec = session->nib.tx_retry_timeout * 1000};
        if((ret = mac_receive_timeout(session->mac_session, &packet.contents, &tv)) != 0) {
            break;
        }

        //wait timed out. do retransmission processing
        SN_DebugPrintf("receive timed out; ticking...\n");
        SN_Transmission_retry(1);
    }

    if(ret < 0) {
        SN_ErrPrintf("packet receive failed with %d\n", ret);
        if(ret == -SN_ERR_RADIO) {
            SN_ErrPrintf("radio has died.\n");
            return -SN_ERR_RADIO;
        }
    }

    //just skip things that aren't packets
    if(ret < -1 || packet.contents.type != mac_mcps_data_indication) {
        //TODO: some kind of COMM-STATUS.indication / DATA.confirm processing here?
        return SN_Receive(session, src_addr, buffer, buffer_size);
    }

    //print some debugging information
    if(packet.contents.MCPS_DATA_indication.DstAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet to %#018"PRIx64"\n", *(uint64_t*)packet.contents.MCPS_DATA_indication.DstAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet to %#06x\n", packet.contents.MCPS_DATA_indication.DstAddr.ShortAddress);
    }
    if(packet.contents.MCPS_DATA_indication.SrcAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet from %#018"PRIx64"\n", *(uint64_t*)packet.contents.MCPS_DATA_indication.SrcAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet from %#06x\n", packet.contents.MCPS_DATA_indication.SrcAddr.ShortAddress);
    }
    SN_InfoPrintf("received packet containing %d-byte payload\n", packet.contents.MCPS_DATA_indication.msduLength);

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet.contents.MCPS_DATA_indication.msduLength; i += 8) {
        SN_DebugPrintf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
            packet.contents.MCPS_DATA_indication.msdu[i],
            packet.contents.MCPS_DATA_indication.msdu[i + 1],
            packet.contents.MCPS_DATA_indication.msdu[i + 2],
            packet.contents.MCPS_DATA_indication.msdu[i + 3],
            packet.contents.MCPS_DATA_indication.msdu[i + 4],
            packet.contents.MCPS_DATA_indication.msdu[i + 5],
            packet.contents.MCPS_DATA_indication.msdu[i + 6],
            packet.contents.MCPS_DATA_indication.msdu[i + 7]
        );
    }
    SN_DebugPrintf("end packet data\n");

    SN_InfoPrintf("detecting packet layout...\n");
    ret = detect_packet_layout(&packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("invalid packet received (detect_packet_layout returned %d)\n", -ret);
        return ret;
    }

    network_header_t* network_header = PACKET_ENTRY(packet, network_header, indication);
    assert(network_header != NULL);

    SN_DebugPrintf("network layer says packet is to %#06x\n", network_header->dst_addr);
    SN_DebugPrintf("network layer says packet is from %#06x\n", network_header->src_addr);

    if(session->mib.macShortAddress != SN_NO_SHORT_ADDRESS && network_header->dst_addr != session->mib.macShortAddress) {
        //packet was sent to our MAC address, but wasn't for our network address. that means we need to route it
        SN_InfoPrintf("packet isn't for us. routing\n");
        if(session->nib.enable_routing) {
            SN_Transmission_forward(network_header->src_addr, network_header->dst_addr, &packet);
            return SN_Receive(session, src_addr, buffer, buffer_size);
        } else {
            SN_WarnPrintf("received packet to route when routing was turned off. dropping\n");
            return SN_Receive(session, src_addr, buffer, buffer_size);
        }
    }

    if(network_header->src_addr == SN_NO_SHORT_ADDRESS) {
        SN_WarnPrintf("network header has no address; using MAC-layer header\n");
        src_addr->type    = packet.contents.MCPS_DATA_indication.SrcAddrMode;
        src_addr->address = packet.contents.MCPS_DATA_indication.SrcAddr;
    } else {
        SN_InfoPrintf("setting source address to %#06x\n", network_header->src_addr);
        src_addr->type                 = mac_short_address;
        src_addr->address.ShortAddress = network_header->src_addr;
    }

    SN_InfoPrintf("consulting neighbor table...\n");

    SN_Table_entry_t table_entry = {
        .session       = session,
        .stream_idx_length = src_addr->stream_idx_length,
    };
    memcpy(table_entry.stream_idx, src_addr->stream_idx, src_addr->stream_idx_length);
    if(src_addr->type == mac_extended_address) {
        table_entry.short_address = SN_NO_SHORT_ADDRESS;
        table_entry.long_address = src_addr->address;
    } else {
        table_entry.short_address = src_addr->address.ShortAddress;
    }

    ret = SN_Table_lookup_by_address(&table_entry, src_addr->type);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");
        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK && ret != -SN_ERR_UNEXPECTED) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return -SN_ERR_RESOURCES;
        }
    }

    //extract data
    SN_InfoPrintf("packet contains payload of length %d\n", packet.layout.payload_length);

    SN_InfoPrintf("doing packet security checks...\n");
    ret = packet_security_checks(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet security checks. aborting\n", -ret);
        //certain security check failures could come from a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
        if(-ret == SN_ERR_UNEXPECTED) {
            SN_WarnPrintf("possible retransmission bug; triggering retransmission\n");
            SN_Transmission_retry(0);

            //special case: if the security check failure is because this is a finalise, and we've already received one, it's probably an acknowledgement drop. send acknowledgements
            if(PACKET_ENTRY(packet, key_confirmation_header, indication) != NULL && PACKET_ENTRY(packet, association_header, indication) == NULL) {
                SN_WarnPrintf("possible dropped acknowledgement; triggering acknowledgement transmission\n");
                if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                    SN_Endpoint_t ack_address = {
                        .type = mac_short_address,
                        .address.ShortAddress = table_entry.short_address,
                    };
                    SN_Send(&ack_address, NULL);
                }
            }
        }
        return ret;
    }

    SN_InfoPrintf("doing public-key operations...\n");
    ret = packet_public_key_operations(&session->device_root_key.public_key, &table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in public-key operations. aborting\n", -ret);
        return ret;
    }

    if(network_header->encrypt) {
        SN_InfoPrintf("doing decryption and integrity checking...\n");
        bool pure_ack = 0;

        if(PACKET_ENTRY(packet, key_confirmation_header, indication) == NULL && PACKET_ENTRY(packet, encrypted_ack_header, indication) != NULL && PACKET_ENTRY(packet, payload_data, indication) == NULL) {
            //this is a pure-acknowledgement packet; don't change the counter
            pure_ack = 1;
        }

        if(pure_ack) {
            ret = decrypt_verify_packet(&table_entry.link_key, &table_entry.local_key_agreement_keypair.public_key, PACKET_ENTRY(packet, encrypted_ack_header, indication)->counter, &packet, 1);
        } else {
            ret = decrypt_verify_packet(&table_entry.link_key, &table_entry.remote_key_agreement_key, table_entry.packet_rx_counter++, &packet, 0);
        }
        if(ret != SN_OK) {
            SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
            //certain crypto failures could be a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
            SN_WarnPrintf("crypto error could be due to dropped acknowledgement; triggering acknowledgement and packet retransmission\n");
            SN_Transmission_retry(0);
            if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                SN_Endpoint_t ack_address = {
                    .type = mac_short_address,
                    .address.ShortAddress = table_entry.short_address,
                };
                SN_Send(&ack_address, NULL);
            }
            return ret;
        }
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = process_packet_headers(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return ret;
    }

    table_entry.unavailable = 0;

    SN_Message_t* association_request = NULL;

    if(PACKET_ENTRY(packet, association_header, indication) != NULL &&
       //we have an association header, and...
       !(PACKET_ENTRY(packet, association_header, indication)->dissociate &&
         (PACKET_ENTRY(packet, association_header, indication)->child)
       )
        //...it's not a rights revocation
        ) {
        //this was an association packet; generate an association message
        SN_InfoPrintf("received association/dissociation request; synthesising appropriate message...\n");

        //the association request will be the first of two message
        association_request = buffer;

        //fill in the association message contents
        association_request->type                             = PACKET_ENTRY(packet, association_header, indication)->dissociate ? SN_Dissociation_request : SN_Association_request;

        SN_InfoPrintf("message synthesis done. output buffer has %zu bytes remaining.\n", buffer_size);
        if(buffer_size == 0) {
            SN_WarnPrintf("output buffer has no space remaining after association message synthesis\n");
        }
    }

    SN_InfoPrintf("processing packet...\n");
    uint8_t* payload_data = PACKET_ENTRY(packet, payload_data, indication);
    if(packet.layout.payload_length != 0 && association_request != NULL) {
        assert(payload_data != NULL);

        table_entry.ack = (uint8_t)(PACKET_ENTRY(packet, encryption_header, indication) != NULL);
        if(network_header->evidence && PACKET_ENTRY(packet, evidence_header, indication)->certificate) {
            //evidence packet
            if(packet.layout.payload_length != sizeof(SN_Certificate_t)) {
                SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %zu)\n", packet.layout.payload_length, sizeof(SN_Certificate_t));
                return -SN_ERR_INVALID;
            }

            //error-check the certificate, and add it to certificate storage
            SN_Certificate_t* evidence = (SN_Certificate_t*)payload_data;
            if(SN_Crypto_check_certificate(evidence) != SN_OK) {
                SN_ErrPrintf("received evidence packet with invalid payload\n");
                return -SN_ERR_SIGNATURE;
            }

            //return to user
            if(buffer_size < sizeof(buffer->explicit_evidence_message)) {
                SN_ErrPrintf("output buffer is too small for incoming certificate\n");
                return -SN_ERR_RESOURCES;
            }
            buffer->type                      = SN_Explicit_Evidence_message;
            buffer->explicit_evidence_message.evidence = *evidence;
        } else {
            if(PACKET_ENTRY(packet, evidence_header, indication) != NULL) {
                SN_WarnPrintf("don't yet know how to handle implicit evidence packets");
                //TODO: implicit evidence packets
            }

            //data packet
            if(!network_header->encrypt) {
                //stapled plain data on unencrypted packet. warn and ignore
                SN_WarnPrintf("received plain data in unencrypted packet. ignoring.\n");
            } else {
                if(buffer_size < sizeof(buffer->data_message) + packet.layout.payload_length) {
                    SN_ErrPrintf("output buffer is too small for incoming data\n");
                    return -SN_ERR_RESOURCES;
                }
                buffer->type                        = SN_Data_message;
                buffer->data_message.payload_length = packet.layout.payload_length;
                memcpy(buffer->data_message.payload, payload_data, packet.layout.payload_length);
            }
        }
    }

    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
