//StarfishNet message transmission rules are in sn_transmit.c

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <sn_status.h>

#include <string.h>
#include <assert.h>

#include <polarssl/sha1.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_txrx.h"

//some templates for mac_receive_primitive
static MAC_SET_CONFIRM(macShortAddress);

//outputs crypto margin, and pointers to the key agreement header and payload data
//also detects basic protocol failures
static int detect_packet_layout(packet_t* packet) {
    SN_DebugPrintf("enter\n");

    if(packet == NULL) {
        SN_ErrPrintf("packet must be valid\n");
        return -SN_ERR_NULL;
    }

    uint8_t current_position = 0;
    uint8_t margin           = 0;
    memset(&packet->packet_layout, 0, sizeof(packet->packet_layout));

    PACKET_HEADER(*packet, network, indication) = (network_header_t*)packet->packet_data.MCPS_DATA_indication.msdu;
    network_header_t* network_header = PACKET_HEADER(*packet, network, indication);
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
    margin += sizeof(network_header_t);

    if(network_header->details) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(node_details_header_t)) {
            SN_ErrPrintf("packet indicates a node details header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found node details header\n");
        PACKET_HEADER(*packet, node_details, indication) = (node_details_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(node_details_header_t);
        margin += sizeof(node_details_header_t);
    }

    if(network_header->associate) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(association_header_t)) {
            SN_ErrPrintf("packet indicates an association request header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found association request header\n");
        PACKET_HEADER(*packet, association, indication) =
            (association_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(association_header_t);
        margin += sizeof(association_header_t);
    }

    if(network_header->key_confirm) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(key_confirmation_header_t)) {
            SN_ErrPrintf("packet indicates a key confirmation header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found key confirmation header\n");
        PACKET_HEADER(*packet, key_confirmation, indication) =
            (key_confirmation_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(key_confirmation_header_t);
        margin += sizeof(key_confirmation_header_t);
    }

    //address_allocation_header_t / address_block_allocation_header_t (only found in associate_reply packets
    if(network_header->associate && network_header->key_confirm &&
       PACKET_HEADER(*packet, association, indication)->child) {
        if(PACKET_HEADER(*packet, association, indication)->router) {
            //block allocation
            if(PACKET_SIZE(*packet, indication) < current_position + sizeof(address_block_allocation_header_t)) {
                SN_ErrPrintf("packet indicates an address block allocation header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            SN_InfoPrintf("found address block allocation header\n");
            PACKET_HEADER(*packet, address_block_allocation, indication) =
                (address_block_allocation_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
            current_position += sizeof(address_block_allocation_header_t);
            margin += sizeof(address_block_allocation_header_t);
        } else {
            //single allocation
            if(PACKET_SIZE(*packet, indication) < current_position + sizeof(address_allocation_header_t)) {
                SN_ErrPrintf("packet indicates an address allocation header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            SN_InfoPrintf("found address allocation header\n");
            PACKET_HEADER(*packet, address_allocation, indication) =
                (address_allocation_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
            current_position += sizeof(address_allocation_header_t);
            margin += sizeof(address_allocation_header_t);
        }
    }

    if(network_header->encrypt) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(encryption_header_t)) {
            SN_ErrPrintf("packet indicates an encryption header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found encryption header\n");
        PACKET_HEADER(*packet, encryption, indication) =
            (encryption_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(encryption_header_t);
    } else {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(signature_header_t)) {
            SN_ErrPrintf("packet indicates a signature header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found signature header\n");
        PACKET_HEADER(*packet, signature, indication) =
            (signature_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + current_position);
        current_position += sizeof(signature_header_t);
    }

    packet->packet_layout.payload_length = PACKET_SIZE(*packet, indication) - current_position;
    if(packet->packet_layout.payload_length > 0) {
        SN_InfoPrintf("found payload (%d bytes)\n", packet->packet_layout.payload_length);
        PACKET_DATA(*packet, indication) = packet->packet_data.MCPS_DATA_indication.msdu + current_position;
    }

    packet->packet_layout.crypto_margin = margin;

    //some logic-checking assertions
    assert(current_position <= PACKET_SIZE(*packet, indication));
    assert(packet->packet_layout.payload_length < PACKET_SIZE(*packet, indication));
    if(PACKET_HEADER(*packet, encryption, indication) != NULL) {
        assert(packet->packet_layout.crypto_margin < PACKET_SIZE(*packet, indication));
    }

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

static int do_security_checks(SN_Table_entry_t* table_entry, packet_t* packet) {
    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //relationship-state check: make sure the headers we see match the state the relationship is in
    if(PACKET_HEADER(*packet, association, indication) != NULL &&
       (table_entry->state == SN_Associate_received || table_entry->state >= SN_Awaiting_finalise) &&
       !PACKET_HEADER(*packet, association, indication)->dissociate) {
        SN_ErrPrintf("received association header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }
    if(PACKET_HEADER(*packet, key_confirmation, indication) != NULL && table_entry->state != SN_Awaiting_reply &&
       table_entry->state != SN_Awaiting_finalise) {
        SN_ErrPrintf("received key confirmation header when we're not waiting for one. this is an error\n");
        return -SN_ERR_UNEXPECTED;
    }

    //assertions to double-check my logic.
    if(PACKET_HEADER(*packet, association, indication) != NULL && !PACKET_HEADER(*packet, association, indication)->dissociate) {
        if(PACKET_HEADER(*packet, key_confirmation, indication) == NULL) {
            assert(table_entry->state == SN_Unassociated);
        }
        if(PACKET_HEADER(*packet, key_confirmation, indication) != NULL) {
            assert(table_entry->state == SN_Awaiting_reply);
        }
    }
    if(PACKET_HEADER(*packet, association, indication) == NULL && PACKET_HEADER(*packet, key_confirmation, indication) != NULL) {
        assert(table_entry->state == SN_Awaiting_finalise);
    }

    //packet security checks:
    // 1. packets with plain data payloads must be encrypted
    // 2. unencrypted packets must be signed
    // 3. association (but not dissociation) packets must be signed
    // 4. dissociation packets must be signed or encrypted
    if(PACKET_HEADER(*packet, encryption, indication) == NULL) {
        //1.
        if(PACKET_DATA(*packet, indication) != NULL && !PACKET_HEADER(*packet, network, indication)->evidence) {
            SN_ErrPrintf("received unencrypted packet with plain data payload. this is an error.\n");
            return -SN_ERR_SECURITY;
        }

        //2.
        if(PACKET_HEADER(*packet, signature, indication) == NULL) {
            SN_ErrPrintf("received unencrypted, unsigned packet. this is an error.\n");
            return -SN_ERR_SECURITY;
        }
    }
    //3.
    if(PACKET_HEADER(*packet, signature, indication) == NULL &&
       PACKET_HEADER(*packet, association, indication) != NULL &&
       !PACKET_HEADER(*packet, association, indication)->dissociate) {
        SN_ErrPrintf("received unsigned association packet. this is an error.\n");
        return -SN_ERR_SECURITY;
    }
    //4.
    if(PACKET_HEADER(*packet, association, indication) != NULL &&
       PACKET_HEADER(*packet, association, indication)->dissociate &&
       PACKET_HEADER(*packet, encryption , indication) == NULL &&
       PACKET_HEADER(*packet, signature  , indication) == NULL) {
        SN_ErrPrintf("received non-integrity-checked dissociation packet. this is an error.\n");
        return -SN_ERR_SECURITY;
    }

        return SN_OK;
}

static int do_public_key_operations(SN_Table_entry_t* table_entry, packet_t* packet) {
    /* at this point, security checks have passed, but no integrity-checking has happened.
     * if this packet is signed, we check the signature, and thus integrity-checking is done.
     * if not, it must be encrypted. we must therefore finish key-agreement so that we can
     * do integrity-checking at decrypt time.
     */

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    int ret;

    SN_Public_key_t* remote_public_key = NULL;

    //get the signing key from node_details_header, if we need it
    if(table_entry->details_known) {
        remote_public_key = &table_entry->public_key;
    } else if(PACKET_HEADER(*packet, node_details, indication) != NULL) {
        //if we don't know the remote node's signing key, we use the one in the message
        remote_public_key = &PACKET_HEADER(*packet, node_details, indication)->signing_key;
    }

    //verify packet signature
    if(PACKET_HEADER(*packet, signature, indication) != NULL) {
        SN_InfoPrintf("checking packet signature...\n");

        if(remote_public_key == NULL) {
            SN_ErrPrintf("we don't know their public key, and they haven't told us. aborting\n");
            return -SN_ERR_SECURITY;
        }

        //XXX: warning, this code assumes that signature header is at the end of the header block
        ret = SN_Crypto_verify(
            remote_public_key,
            packet->packet_data.MCPS_DATA_indication.msdu,
            //TODO: remove pointer arithmetic from here
            (uint8_t*)PACKET_HEADER(*packet, signature, indication) - packet->packet_data.MCPS_DATA_indication.msdu,
            &PACKET_HEADER(*packet, signature, indication)->signature
        );
        if(ret != SN_OK) {
            SN_ErrPrintf("packet signature verification failed.\n");
            return -SN_ERR_SIGNATURE;
        }

        SN_InfoPrintf("packet signature check successful\n");
    } else {
        assert(PACKET_HEADER(*packet, encryption, indication) != NULL);
        /* if the packet isn't signed, it's encrypted, which means integrity-checking
         * during decrypt_and_verify will catch any problems
         */
    }

    //if this is an associate_reply, finish the key agreement, so we can use the link key in decrypt_and_verify
    if(PACKET_HEADER(*packet, association, indication) != NULL &&
       !PACKET_HEADER(*packet, association, indication)->dissociate &&
       PACKET_HEADER(*packet, key_confirmation, indication) != NULL) {
        //associate_reply
        assert(table_entry->state == SN_Awaiting_reply);

        //finish the key agreement
        ret = SN_Crypto_key_agreement(
            &PACKET_HEADER(*packet, association, indication)->key_agreement_key,
            &table_entry->local_key_agreement_keypair.private_key,
            &table_entry->link_key
        );
        if(ret != SN_OK) {
            SN_ErrPrintf("key agreement failed with %d.\n", -ret);
            return ret;
        }
    }

    return SN_OK;
}

static int process_packet_headers(SN_Table_entry_t* table_entry, packet_t* packet) {
    //at this point, security and integrity checks are guaranteed to have passed

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //network_header
    table_entry->knows_details = (uint8_t)!PACKET_HEADER(*packet, network, indication)->req_details;


    //node_details_header
    if(PACKET_HEADER(*packet, node_details, indication) != NULL) {
        if(!table_entry->details_known) {
            table_entry->details_known = 1;
            table_entry->public_key    = PACKET_HEADER(*packet, node_details, indication)->signing_key;
        }
    }

    //association_header
    if(PACKET_HEADER(*packet, association, indication) != NULL) {
        //relationship state is checked in do_public_key_operations
        //signature is checked in do_public_key_operations
        if(!PACKET_HEADER(*packet, association, indication)->dissociate) {
            //association processing
            table_entry->remote_key_agreement_key = PACKET_HEADER(*packet, association, indication)->key_agreement_key;

            if(PACKET_HEADER(*packet, key_confirmation, indication) == NULL) {
                //associate_request
                assert(table_entry->state == SN_Unassociated);

                table_entry->child  = PACKET_HEADER(*packet, association, indication)->child;
                table_entry->router = PACKET_HEADER(*packet, association, indication)->router;

                table_entry->state = SN_Associate_received;
            } else {
                //associate_reply
                assert(table_entry->state == SN_Awaiting_reply);
                //key agreement processing in do_public_key_operations
            }

            //TODO: PACKET_HEADER(*packet, association, indication)->delegate;
        } else {
            //TODO: dissociation processing
        }
    }

    //key_confirmation_header
    if(PACKET_HEADER(*packet, key_confirmation, indication) != NULL) {
        if(PACKET_HEADER(*packet, association, indication) != NULL) {
            //associate_reply
            assert(table_entry->state == SN_Awaiting_reply);

            //do the challenge1 check (double-hash)
            SN_Hash_t hashbuf;
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), hashbuf.data);
            sha1(hashbuf.data, sizeof(hashbuf.data), hashbuf.data);
            SN_DebugPrintf("challenge1 (received)   = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data,
                *((uint64_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data + 1),
                *((uint32_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data + 4));
            SN_DebugPrintf("challenge1 (calculated) = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)hashbuf.data,
                *((uint64_t*)hashbuf.data + 1),
                *((uint32_t*)hashbuf.data + 4));
            if(memcmp(hashbuf.data, PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
                SN_ErrPrintf("key confirmation (challenge1) failed.\n");
                return -SN_ERR_KEYGEN;
            }

            //advance the relationship's state
            table_entry->state = SN_Send_finalise;
        } else {
            //associate_finalise
            assert(table_entry->state == SN_Awaiting_finalise);

            //do challenge2 check (single-hash)
            SN_Hash_t hashbuf;
            sha1(table_entry->link_key.key_id.data, sizeof(table_entry->link_key.key_id.data), hashbuf.data);
            SN_DebugPrintf("challenge2 (received)   = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data,
                *((uint64_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data + 1),
                *((uint32_t*)PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data + 4));
            SN_DebugPrintf("challenge2 (calculated) = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)hashbuf.data,
                *((uint64_t*)hashbuf.data + 1),
                *((uint32_t*)hashbuf.data + 4));
            if(memcmp(hashbuf.data, PACKET_HEADER(*packet, key_confirmation, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
                SN_ErrPrintf("key confirmation (challenge1) failed");
                return -SN_ERR_KEYGEN;
            }

            //advance the relationship's state
            table_entry->state = SN_Associated;
        }
    }

    //TODO: address_allocation_header
    //TODO: address_block_allocation_header

    //TODO: {encrypted,signed}_ack_header

    return SN_OK;
}

/*argument notes:
 * margin: how much data to skip (after the network header, before the payload) for encryption
 * safe  : if true, arrange so that the original data is untouched on a decryption failure
 */
static int decrypt_verify_packet(SN_Table_entry_t* table_entry, packet_t* packet) {
    SN_DebugPrintf("enter\n");

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    const size_t skip_size = packet->packet_layout.crypto_margin + sizeof(encryption_header_t);
    if(PACKET_SIZE(*packet, indication) < skip_size) {
        SN_ErrPrintf("cannot decrypt packet of length %d with a margin of %d\n", PACKET_SIZE(*packet, indication), packet->packet_layout.crypto_margin);
        return -SN_ERR_END_OF_DATA;
    }

    encryption_header_t* encryption_header = (encryption_header_t*)(packet->packet_data.MCPS_DATA_indication.msdu + packet->packet_layout.crypto_margin);

    int ret = SN_Crypto_decrypt(&table_entry->link_key.key, &table_entry->link_key.key_id, encryption_header->counter,
        packet->packet_data.MCPS_DATA_request.msdu, packet->packet_layout.crypto_margin,
        packet->packet_data.MCPS_DATA_indication.msdu + skip_size,
        PACKET_SIZE(*packet, indication) - skip_size,
        encryption_header->tag);
    if(ret != SN_OK) {
        SN_ErrPrintf("Packet decryption failed with %d, aborting\n", -ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("payload decryption complete\n");

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

    if(buffer_size < sizeof(buffer->association_message)) {
        //too small to even hold an associate message, hence too small for anything
        SN_ErrPrintf("buffer is below minimum size (is %zu bytes, should be %zu bytes)\n", buffer_size, sizeof(buffer->association_message));
        return -SN_ERR_RESOURCES;
    }

    SN_DebugPrintf("output buffer size is %ld\n", buffer_size);

    //TODO: presumably there's some kind of queue-check here

    packet_t packet;
    SN_InfoPrintf("receiving packet...\n");
    //TODO: switch to a raw mac_receive() and do network-layer housekeeping (including retransmission)
    int ret = mac_receive_primitive_type(session->mac_session, &packet.packet_data, mac_mcps_data_indication);

    if(ret <= 0) {
        SN_ErrPrintf("packet receive failed with %d\n", ret);
        return -SN_ERR_RADIO;
    }

    //print some debugging information
    if(packet.packet_data.MCPS_DATA_indication.DstAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet to %#018"PRIx64"\n", *(uint64_t*)packet.packet_data.MCPS_DATA_indication.DstAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet to %#06x\n", packet.packet_data.MCPS_DATA_indication.DstAddr.ShortAddress);
    }
    if(packet.packet_data.MCPS_DATA_indication.SrcAddrMode == mac_extended_address) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received packet from %#018"PRIx64"\n", *(uint64_t*)packet.packet_data.MCPS_DATA_indication.SrcAddr.ExtendedAddress);
    } else {
        SN_DebugPrintf("received packet from %#06x\n", packet.packet_data.MCPS_DATA_indication.SrcAddr.ShortAddress);
    }
    SN_InfoPrintf("received packet containing %d-byte payload\n", packet.packet_data.MCPS_DATA_indication.msduLength);

    SN_DebugPrintf("packet data:\n");
    for(int i = 0; i < packet.packet_data.MCPS_DATA_indication.msduLength; i += 8) {
        SN_DebugPrintf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
            packet.packet_data.MCPS_DATA_indication.msdu[i],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 1],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 2],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 3],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 4],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 5],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 6],
            packet.packet_data.MCPS_DATA_indication.msdu[i + 7]
        );
    }
    SN_DebugPrintf("end packet data\n");

    SN_InfoPrintf("detecting packet layout...\n");
    ret = detect_packet_layout(&packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("invalid packet received (detect_packet_layout returned %d)\n", -ret);
        return ret;
    }

    //TODO: routing/addressing
    src_addr->type    = packet.packet_data.MCPS_DATA_indication.SrcAddrMode;
    src_addr->address = packet.packet_data.MCPS_DATA_indication.SrcAddr;

    SN_InfoPrintf("consulting neighbor table...\n");
    SN_Table_entry_t table_entry = {
        .session       = session,
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    SN_Certificate_storage_t* cert_storage = NULL;
    ret = SN_Table_lookup_by_address(src_addr, &table_entry, &cert_storage);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(src_addr->type == mac_short_address) {
            table_entry.short_address = src_addr->address.ShortAddress;
        } else {
            table_entry.long_address = src_addr->address;
        }

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return -SN_ERR_RESOURCES;
        }
    }

    //extract data
    SN_InfoPrintf("packet contains payload of length %d\n", packet.packet_layout.payload_length);

    SN_InfoPrintf("doing packet security checks...\n");
    ret = do_security_checks(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet security checks. aborting\n", -ret);
        return ret;
    }

    SN_InfoPrintf("doing public-key operations...\n");
    ret = do_public_key_operations(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in public-key operations. aborting\n", -ret);
        return ret;
    }

    if(PACKET_HEADER(packet, network, indication)->encrypt) {
        SN_InfoPrintf("doing decryption and integrity checking...\n");
        ret = decrypt_verify_packet(&table_entry, &packet);
        if(ret != SN_OK) {
            SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
            return ret;
        }
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = process_packet_headers(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d processing packet headers. aborting\n", -ret);
        return ret;
    }

    if(PACKET_HEADER(packet, association, indication)!= NULL &&
       //we have an association header, and...
       !(PACKET_HEADER(packet, association, indication)->dissociate &&
         (PACKET_HEADER(packet, association, indication)->child || PACKET_HEADER(packet, association, indication)->delegate)
       )
        //...it's not a rights revocation
        ) {
        //this was an association packet; generate an association message
        SN_InfoPrintf("received association/dissociation request; synthesising appropriate message...\n");

        //the association request will be the first of two message
        SN_Message_t* association_request = buffer;

        //advance the buffer by one association message
        buffer = (SN_Message_t*)((uint8_t*)buffer + sizeof(buffer->association_message));
        buffer_size -= sizeof(buffer->association_message);

        //fill in the association message contents
        association_request->type                             = PACKET_HEADER(packet, association, indication)->dissociate ? SN_Dissociation_request : SN_Association_request;
        association_request->association_message.stapled_data = buffer_size == 0 ? NULL : buffer;

        SN_InfoPrintf("message synthesis done. output buffer has %zu bytes remaining.\n", buffer_size);
        if(buffer_size == 0) {
            SN_WarnPrintf("output buffer has no space remaining after association message synthesis\n");
        }
    }

    SN_InfoPrintf("processing packet...\n");
    if(PACKET_DATA(packet, indication) != NULL) {
        if(!PACKET_HEADER(packet, network, indication)->encrypt) {
            //stapled data on unencrypted packet. warn and ignore
            SN_WarnPrintf("received data in unencrypted packet. ignoring.\n");
        } else {
            if(PACKET_HEADER(packet, network, indication)->evidence) {
                //evidence packet
                if(packet.packet_layout.payload_length != sizeof(SN_Certificate_t)) {
                    SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %zu)\n", packet.packet_layout.payload_length, sizeof(SN_Certificate_t));
                    return -SN_ERR_INVALID;
                }

                //error-check the certificate, and add it to certificate storage
                SN_Certificate_t* evidence = (SN_Certificate_t*)PACKET_DATA(packet, indication);
                ret = SN_Crypto_add_certificate(cert_storage, evidence);
                if(ret == -SN_ERR_SIGNATURE ||
                   (ret == -SN_ERR_NULL && SN_Crypto_check_certificate(evidence) != SN_OK)) {
                    SN_ErrPrintf("received evidence packet with invalid payload\n");
                    return -SN_ERR_SIGNATURE;
                }

                //return to user
                if(buffer_size < (uint8_t*)&buffer->evidence_message - (uint8_t*)buffer + sizeof(SN_Certificate_t)) {
                    SN_ErrPrintf("output buffer is too small for incoming certificate\n");
                    return -SN_ERR_RESOURCES;
                }
                buffer->type                      = SN_Evidence_message;
                buffer->evidence_message.evidence = *evidence;
            } else {
                //data packet
                if(buffer_size < buffer->data_message.payload - (uint8_t*)buffer + packet.packet_layout.payload_length) {
                    SN_ErrPrintf("output buffer is too small for incoming data\n");
                    return -SN_ERR_RESOURCES;
                }
                buffer->type                        = SN_Data_message;
                buffer->data_message.payload_length = packet.packet_layout.payload_length;
                memcpy(buffer->data_message.payload, PACKET_DATA(packet, indication), packet.packet_layout.payload_length);
            }
        }
    }

    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
