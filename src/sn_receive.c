//StarfishNet message transmission rules are in sn_transmit.c

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <sn_status.h>

#include <string.h>
#include <assert.h>

#include "polarssl/sha1.h"

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_txrx.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

//outputs crypto margin, and pointers to the key agreement header and payload data
//also detects basic protocol failures
typedef struct packet_layout {
    network_header_t* network_header;
    node_details_header_t* node_details;
    association_request_header_t* association_header;
    key_confirmation_header_t* key_confirm;
    address_allocation_header_t* address_allocation;
    address_block_allocation_header_t* address_block_allocation;
    uint8_t* payload_data;
    uint8_t crypto_margin;
} packet_layout_t;
static int detect_packet_layout(mac_primitive_t* packet, packet_layout_t* packet_layout) {
    SN_DebugPrintf("enter\n");

    if(packet == NULL || packet_layout == NULL) {
        SN_ErrPrintf("packet and packet_layout must be valid\n");
        return -SN_ERR_NULL;
    }

    uint8_t current_position = 0;
    memset(packet_layout, 0, sizeof(*packet_layout));

    packet_layout->network_header = (network_header_t*)packet->MCPS_DATA_indication.msdu;
    if(packet->MCPS_DATA_indication.msduLength < sizeof(network_header_t)) {
        SN_ErrPrintf("packet doesn't appear to have a valid network header. aborting\n");
        return -SN_ERR_END_OF_DATA;
    }
    current_position += sizeof(network_header_t);

    if(packet_layout->network_header->data.details) {
        if(packet->MCPS_DATA_indication.msduLength < current_position + sizeof(node_details_header_t)) {
            SN_ErrPrintf("packet indicates a node details header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet_layout->node_details = (node_details_header_t*)(packet->MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(node_details_header_t);
    }

    if(packet_layout->network_header->data.associate) {
        if(packet->MCPS_DATA_indication.msduLength < current_position + sizeof(association_request_header_t)) {
            SN_ErrPrintf("packet indicates an association request header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet_layout->association_header = (association_request_header_t*)(packet->MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(association_request_header_t);
    }

    if(packet_layout->network_header->data.key_confirm) {
        if(packet->MCPS_DATA_indication.msduLength < current_position + sizeof(key_confirmation_header_t)) {
            SN_ErrPrintf("packet indicates a key confirmation header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        packet_layout->key_confirm = (key_confirmation_header_t*)(packet->MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(key_confirmation_header_t);
    }

    //address_allocation_header_t / address_block_allocation_header_t (only found in associate_reply packets
    if(packet_layout->network_header->data.associate && packet_layout->network_header->data.key_confirm && packet_layout->association_header->signed_data.child) {
        if(packet_layout->association_header->signed_data.router) {
            //block allocation
            if(packet->MCPS_DATA_indication.msduLength < current_position + sizeof(address_block_allocation_header_t)) {
                SN_ErrPrintf("packet indicates an address block allocation header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet_layout->address_block_allocation = (address_block_allocation_header_t*)(packet->MCPS_DATA_indication.msdu + current_position);
            current_position += sizeof(address_block_allocation_header_t);
        } else {
            //single allocation
            if(packet->MCPS_DATA_indication.msduLength < current_position + sizeof(address_allocation_header_t)) {
                SN_ErrPrintf("packet indicates an address allocation header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            packet_layout->address_allocation = (address_allocation_header_t*)(packet->MCPS_DATA_indication.msdu + current_position);
            current_position += sizeof(address_allocation_header_t);
        }
    }

    packet_layout->payload_data  = packet->MCPS_DATA_indication.msdu + current_position;
    packet_layout->crypto_margin = current_position - (uint8_t)sizeof(network_header_t);

    assert(current_position <= packet->MCPS_DATA_indication.msduLength);
    assert(packet_layout->crypto_margin < packet->MCPS_DATA_indication.msduLength);

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int bootstrap_security_processing(SN_Table_entry_t* table_entry, packet_layout_t* packet_layout, SN_Kex_result_t* link_key) {
    /* this is called before any decryption or verification, which means no integrity-checking has happened.
     * we therefore only do the minimum amount of work necessary to get integrity-checking working:
     * finish the authentication transaction and do key confirmation.
     */

    if(table_entry == NULL || packet_layout == NULL || link_key == NULL) {
        SN_ErrPrintf("table_entry, packet_layout, and link_key must all be valid\n");
        return -SN_ERR_NULL;
    }

    int ret;

    //first, we do a relationship-state check
    if(packet_layout->association_header != NULL && (table_entry->state == SN_Associate_received || table_entry->state >= SN_Awaiting_finalise) && !packet_layout->association_header->signed_data.dissociate) {
        SN_ErrPrintf("received association header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }
    if(packet_layout->key_confirm != NULL && (table_entry->state != SN_Awaiting_reply || table_entry->state != SN_Awaiting_finalise)) {
        SN_ErrPrintf("received key confirmation header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }

    //assertions to double-check my logic.
    if(!packet_layout->association_header->signed_data.dissociate) {
        if (packet_layout->association_header != NULL && packet_layout->key_confirm == NULL) {
            assert(table_entry->state == SN_Unassociated);
        }
        if (packet_layout->association_header != NULL && packet_layout->key_confirm != NULL) {
            assert(table_entry->state == SN_Awaiting_reply);
        }
        if (packet_layout->association_header == NULL && packet_layout->key_confirm != NULL) {
            assert(table_entry->state == SN_Awaiting_finalise);
        }
    }

    SN_Public_key_t* remote_public_key = NULL;

    //get the signing key from node_details, if we need it
    if(table_entry->details_known) {
        remote_public_key = &table_entry->public_key;
    } else if(packet_layout->node_details != NULL) {
        //if we don't know the remote node's signing key, we use the one in the message
        remote_public_key = &packet_layout->node_details->signing_key;
    }

    //association_header signature
    if(packet_layout->association_header != NULL) {
        if(remote_public_key == NULL) {
            SN_ErrPrintf("we don't know their public key, and they haven't told us. aborting\n");
            return -SN_ERR_SECURITY;
        }

        ret = SN_Crypto_verify(remote_public_key, (uint8_t *) &packet_layout->association_header->signed_data, sizeof(packet_layout->association_header->signed_data), &packet_layout->association_header->signature);
        if (ret != SN_OK) {
            SN_ErrPrintf("association header authentication failed.\n");
            return -SN_ERR_SIGNATURE;
        }
    }

    //if this is an associate_reply, finish the key agreement
    if(packet_layout->association_header != NULL && !packet_layout->association_header->signed_data.dissociate) {
        if(packet_layout->key_confirm != NULL) {
            //associate_reply
            assert(table_entry->state == SN_Awaiting_reply);

            //finish the key agreement
            ret = SN_Crypto_key_agreement(&packet_layout->association_header->signed_data.key_agreement_key, &table_entry->local_key_agreement_keypair.private_key, link_key);
            if (ret != SN_OK) {
                SN_ErrPrintf("key agreement failed with %d.\n", -ret);
                return ret;
            }

            //do the challenge1 check (double-hash) here, so we know immediately if there's a problem
            SN_Hash_t hashbuf;
            sha1(link_key->key_id.data, sizeof(link_key->key_id.data), hashbuf.data);
            sha1(hashbuf.data, sizeof(hashbuf.data), hashbuf.data);
            if(memcmp(hashbuf.data, packet_layout->key_confirm->challenge.data, sizeof(hashbuf.data)) != 0) {
                SN_ErrPrintf("key confirmation (challenge1) failed");
                return -SN_ERR_KEYGEN;
            }
        } else {
            //associate_request
            //nothing to do here
        }
    } else {
        *link_key = table_entry->link_key;
    }

    return SN_OK;
}

static int process_packet_headers(SN_Table_entry_t* table_entry, packet_layout_t* packet_layout, SN_Kex_result_t* temp_link_key) {
    //at this point, security and integrity checks are guaranteed to have passed

    if(table_entry == NULL || packet_layout == NULL || temp_link_key == NULL) {
        SN_ErrPrintf("table_entry, packet_layout, and temp_link_key must all be valid\n");
        return -SN_ERR_NULL;
    }

    //network_header
    table_entry->knows_details = packet_layout->network_header->data.req_details;

    //node_details
    if(packet_layout->node_details != NULL) {
        if(!table_entry->details_known) {
            table_entry->details_known = 1;
            table_entry->public_key = packet_layout->node_details->signing_key;
        }
        table_entry->long_address = packet_layout->node_details->long_address;
        table_entry->short_address = packet_layout->node_details->short_address;
    }

    //association_header
    if(packet_layout->association_header != NULL) {
        //relationship state is checked in bootstrap_security_processing
        //signature is checked in bootstrap_security_processing
        if(!packet_layout->association_header->signed_data.dissociate) {
            //association processing
            table_entry->remote_key_agreement_key = packet_layout->association_header->signed_data.key_agreement_key;

            if(packet_layout->key_confirm == NULL) {
                //associate_request
                assert(table_entry->state == SN_Unassociated);

                table_entry->child  = packet_layout->association_header->signed_data.child;
                table_entry->router = packet_layout->association_header->signed_data.router;

                table_entry->state = SN_Associate_received;
            } else {
                //associate_reply
                assert(table_entry->state == SN_Awaiting_reply);
                //key agreement processing in bootstrap_security_processing
                table_entry->link_key = *temp_link_key;
            }

            //TODO: packet_layout->association_header->signed_data.delegate;
        } else {
            //TODO: dissociation processing
        }
    }

    //key_confirm
    if(packet_layout->key_confirm != NULL) {
        if(packet_layout->association_header != NULL) {
            //associate_reply
            assert(table_entry->state == SN_Awaiting_reply);
            //key confirmation processing in bootstrap_security_processing
            table_entry->state = SN_Send_finalise;
        } else {
            //associate_finalise
            assert(table_entry->state == SN_Awaiting_finalise);
            //do challenge2 check
            SN_Hash_t hashbuf;
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), hashbuf.data);
            if(memcmp(hashbuf.data, packet_layout->key_confirm->challenge.data, sizeof(hashbuf.data)) != 0) {
                SN_ErrPrintf("key confirmation (challenge1) failed");
                return -SN_ERR_KEYGEN;
            }
            table_entry->state = SN_Associated;
        }
    }

    //TODO: address_allocation
    //TODO: address_block_allocation

    return SN_OK;
}

/*argument notes:
 * margin: how much data to skip (after the network header, before the payload) for encryption
 * safe  : if true, arrange so that the original data is untouched on a decryption failure
 */
static int decrypt_verify_packet(SN_Kex_result_t* link_key, uint8_t margin, mac_primitive_t* packet) {
    SN_DebugPrintf("enter\n");

    if(link_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    network_header_t* header = (network_header_t*)packet->MCPS_DATA_request.msdu;
    if(packet->MCPS_DATA_request.msduLength < sizeof(network_header_t) + margin) {
        SN_ErrPrintf("cannot decrypt packet of length %d with a margin of %d\n", packet->MCPS_DATA_request.msduLength, margin);
        return -SN_ERR_END_OF_DATA;
    }

    int ret;

    if(header->data.encrypt) {
        ret = SN_Crypto_decrypt(&link_key->key, &link_key->key_id, header->crypto.counter,
                (uint8_t*)&header->data, (uint8_t)sizeof(header->data) + margin, //XXX: this line makes assumptions about packet layout in order to integrity-check the margin
                packet->MCPS_DATA_request.msdu + sizeof(*header) + margin, packet->MCPS_DATA_request.msduLength - ((uint8_t)sizeof(*header) + margin),
                header->crypto.tag);
        if(ret != SN_OK) {
            SN_ErrPrintf("Packet dencryption failed with %d, aborting\n", -ret);
            return -SN_ERR_SECURITY;
        }

        SN_InfoPrintf("payload decryption complete\n");
    } else {
        SN_InfoPrintf("packet not encrypted. doing hash check instead...\n");
        //if the packet wasn't encrypted, tag contains a hash instead (truncated if necessary)
        SN_Hash_t hashbuf;
        sha1_context hashctx;

        sha1_init(&hashctx);
        sha1_starts(&hashctx);
        sha1_update(&hashctx, (uint8_t*)&header->data, sizeof(header->data));
        sha1_update(&hashctx, (uint8_t*)&header->crypto.counter, sizeof(header->crypto.counter));
        sha1_update(&hashctx, packet->MCPS_DATA_request.msdu + sizeof(*header), packet->MCPS_DATA_request.msduLength - sizeof(*header));
        sha1_finish(&hashctx, hashbuf.data);
        sha1_free(&hashctx);

        if(memcmp(header->crypto.tag, hashbuf.data, sizeof(header->crypto.tag)) != 0) { //XXX: crypto.tag is smaller than hashbuf
            SN_ErrPrintf("Packet hash check failed\n");
            return -SN_ERR_SIGNATURE;
        }

        SN_InfoPrintf("hash check complete\n");
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

//receive packet, decoding into one or more messages
int SN_Receive(SN_Session_t* session, SN_Address_t* src_addr, SN_Message_t* buffer, size_t buffer_size) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || src_addr == NULL || buffer == NULL || buffer_size == 0) {
        SN_ErrPrintf("session, src_addr, buffer, and buffer_size must all be valid\n");
        return -SN_ERR_NULL;
    }

    SN_DebugPrintf("output buffer size is %ld\n", buffer_size);

    //TODO: presumably there's some kind of queue-check here

    mac_primitive_t packet;
    SN_InfoPrintf("receiving packet...\n");
    //TODO: switch to a raw mac_receive() and do network-layer housekeeping (including retransmission)
    int ret = mac_receive_primitive_type(session->mac_session, &packet, mac_mcps_data_indication);

    if (ret <= 0) {
        SN_ErrPrintf("packet receive failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    //print some debugging information
    if(packet.MCPS_DATA_indication.DstAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet to %#018lx\n", *(uint64_t*)packet.MCPS_DATA_indication.DstAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet to %#06x\n", packet.MCPS_DATA_indication.DstAddr.ShortAddress);
    }
    if(packet.MCPS_DATA_indication.SrcAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet from %#018lx\n", *(uint64_t*)packet.MCPS_DATA_indication.SrcAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet from %#06x\n", packet.MCPS_DATA_indication.SrcAddr.ShortAddress);
    }
    SN_InfoPrintf("received packet containing %d-byte payload\n", packet.MCPS_DATA_indication.msduLength);

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet.MCPS_DATA_indication.msduLength; i += 4) {
        SN_DebugPrintf("%2x %2x %2x %2x\n", packet.MCPS_DATA_indication.msdu[i], packet.MCPS_DATA_indication.msdu[i + 1], packet.MCPS_DATA_indication.msdu[i + 2], packet.MCPS_DATA_indication.msdu[i + 3]);
    }
    SN_DebugPrintf("end packet data\n");

    SN_InfoPrintf("detecting packet layout...\n");
    packet_layout_t packet_layout = {};
    ret = detect_packet_layout(&packet, &packet_layout);
    if(ret != SN_OK) {
        SN_ErrPrintf("invalid packet received (detect_packet_layout returned %d)\n", -ret);
        return ret;
    }

    network_header_t* header = packet_layout.network_header;
    if(!(header->protocol_id == STARFISHNET_PROTOCOL_ID && header->protocol_ver == STARFISHNET_PROTOCOL_VERSION)) {
        SN_ErrPrintf("packet has invalid protocol ID bytes. protocol is %x (should be %x), version is %x (should be %x)\n", header->protocol_id, STARFISHNET_PROTOCOL_ID, header->protocol_ver, STARFISHNET_PROTOCOL_VERSION);
        return -SN_ERR_OLD_VERSION;
    }

    //TODO: routing/addressing
    src_addr->type    = packet.MCPS_DATA_indication.SrcAddrMode;
    src_addr->address = packet.MCPS_DATA_indication.SrcAddr;

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
            .session       = session,
            .short_address = SN_NO_SHORT_ADDRESS,
    };
    SN_Certificate_storage_t* cert_storage = NULL;
    ret = SN_Table_lookup_by_address(src_addr, &table_entry, &cert_storage);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(src_addr->type == mac_short_address)
            table_entry.short_address = src_addr->address.ShortAddress;
        else
            table_entry.long_address  = src_addr->address;

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return -SN_ERR_RESOURCES;
        }
    }

    //extract data
    uint8_t payload_length = packet.MCPS_DATA_indication.msduLength - (uint8_t)(packet_layout.payload_data - packet.MCPS_DATA_indication.msdu);
    SN_InfoPrintf("packet contains payload of length %d\n", payload_length);
    assert(payload_length < packet.MCPS_DATA_indication.msduLength);

    SN_InfoPrintf("bootstapping security processing...\n");
    SN_Kex_result_t link_key = {};
    ret = bootstrap_security_processing(&table_entry, &packet_layout, &link_key);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return ret;
    }

    SN_InfoPrintf("doing decryption and integrity checking...\n");
    ret = decrypt_verify_packet(&link_key, packet_layout.crypto_margin, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
        return ret;
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = process_packet_headers(&table_entry, &packet_layout, &link_key);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return ret;
    }

    SN_Table_update(&table_entry);

    SN_InfoPrintf("processing packet...\n");
    uint8_t* payload_data = packet_layout.payload_data;
    switch(table_entry.state) {
        //TODO: writeme
        //TODO: don't need to switch on state anymore, just process the packet. stapled data is supported, except SD1DV (which means no data in association packets)

        case SN_Send_finalise:
        case SN_Associated:
            //normal state
            if(header->data.encrypt) {
                //normal packet
                if(payload_data != NULL) {
                    if(header->data.data_type) {
                        //evidence packet
                        if(payload_length != sizeof(SN_Certificate_t)) {
                            SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %ld)\n", payload_length, sizeof(SN_Certificate_t));
                            return -SN_ERR_INVALID;
                        }

                        //error-check the certificate, and add it to certificate storage
                        SN_Certificate_t* evidence = (SN_Certificate_t*)payload_data;
                        ret = SN_Crypto_add_certificate(cert_storage, evidence);
                        if(ret == -SN_ERR_SIGNATURE || (ret == -SN_ERR_NULL && SN_Crypto_check_certificate(evidence) != SN_OK)) {
                            SN_ErrPrintf("received evidence packet with invalid payload\n");
                            return -SN_ERR_INVALID;
                        }

                        //return to user
                        if(buffer_size < sizeof(buffer->evidence_message)) {
                            SN_WarnPrintf("buffer too small for certificate\n");
                            return -SN_ERR_RESOURCES;
                        }
                        buffer->type = SN_Evidence_message;
                        buffer->evidence_message.evidence = *evidence;
                    } else {
                        //data packet
                        if(buffer_size < sizeof(buffer->data_message) + payload_length) {
                            SN_ErrPrintf("buffer too small for data\n");
                            return -SN_ERR_RESOURCES;
                        }
                        buffer->type = SN_Data_message;
                        buffer->data_message.payload_length = payload_length;
                        memcpy(buffer->data_message.payload, payload_data, payload_length);
                    }
                }
            } else {
                //TODO: management packet. probably a disconnect
            }
            break;

        default:
            SN_ErrPrintf("relationship is in invalid state %d. halting processing\n", table_entry.state);
            return -SN_ERR_INVALID;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
