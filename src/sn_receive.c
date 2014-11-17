//StarfishNet message transmission rules are in sn_transmit.c

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <sn_status.h>

#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_packet.h"
#include "sn_delayed_tx.h"
#include "sn_beacons.h"
#include "sn_queued_rx.h"

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
    memset(&packet->layout, 0, sizeof(packet->layout));

    //network_header_t is always present
    packet->layout.network_header = 0;
    packet->layout.present.network_header = 1;
    network_header_t* network_header = PACKET_ENTRY(*packet, network_header, indication);
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

    //encrypted_ack_header_t / signed_ack_header_t
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
            //signed ack
            if(PACKET_SIZE(*packet, indication) < current_position + sizeof(signed_ack_header_t)) {
                SN_ErrPrintf("packet indicates an acknowledgement (signed) header, but is too small. aborting\n");
                return -SN_ERR_END_OF_DATA;
            }
            SN_InfoPrintf("found acknowledgement (signed) header at %d\n", current_position);
            packet->layout.signed_ack_header = current_position;
            packet->layout.present.signed_ack_header = 1;
            current_position += sizeof(signed_ack_header_t);
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

static int do_security_checks(SN_Table_entry_t* table_entry, packet_t* packet) {
    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
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
            packet->contents.MCPS_DATA_indication.msdu,
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
        //associate_reply
        assert(table_entry->state == SN_Awaiting_reply);
        assert(PACKET_ENTRY(*packet, key_agreement_header, indication) != NULL);

        //finish the key agreement
        SN_Kex_result_t kex_result;
        ret = SN_Crypto_key_agreement(
            &PACKET_ENTRY(*packet, key_agreement_header, indication)->key_agreement_key,
            &table_entry->local_key_agreement_keypair.private_key,
            &kex_result
        );
        if(ret != SN_OK) {
            SN_ErrPrintf("key agreement failed with %d.\n", -ret);
            return ret;
        }
        table_entry->link_key = kex_result.key;
        table_entry->packet_rx_counter = table_entry->packet_tx_counter = 0;
    }

    return SN_OK;
}

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

static int process_packet_headers(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet) {
    //at this point, security and integrity checks are guaranteed to have passed

    if(session == NULL || table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("session, table_entry, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    //network_header
    network_header_t* network_header = PACKET_ENTRY(*packet, network_header, indication);
    assert(network_header != NULL);
    if(network_header->req_details) {
        SN_InfoPrintf("partner has requested our details\n");
    }
    table_entry->knows_details = (uint8_t)!PACKET_ENTRY(*packet, network_header, indication)->req_details;
    if(network_header->src_addr != SN_NO_SHORT_ADDRESS) {
        //if the remote node has a short address, we can erase its MAC address from memory
        SN_InfoPrintf("short address is known; erasing long address\n");
        memset(table_entry->long_address.ExtendedAddress, 0, sizeof(table_entry->long_address.ExtendedAddress));
    }


    //node_details_header
    if(PACKET_ENTRY(*packet, node_details_header, indication) != NULL) {
        SN_InfoPrintf("processing node details header...\n");
        if(!table_entry->details_known) {
            SN_InfoPrintf("storing public key...\n");
            table_entry->details_known = 1;
            table_entry->public_key    = PACKET_ENTRY(*packet, node_details_header, indication)->signing_key;
        }
    }

    //association_header
    if(PACKET_ENTRY(*packet, association_header, indication) != NULL) {
        SN_InfoPrintf("processing association header...\n");
        association_header_t* association_header = PACKET_ENTRY(*packet, association_header, indication);
        //relationship state is checked in do_public_key_operations
        //signature is checked in do_public_key_operations
        if(!association_header->dissociate) {
            //association processing
            assert(PACKET_ENTRY(*packet, key_agreement_header, indication) != NULL);
            SN_InfoPrintf("detected key agreement header\n");
            table_entry->remote_key_agreement_key = PACKET_ENTRY(*packet, key_agreement_header, indication)->key_agreement_key;

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
                //key agreement processing in do_public_key_operations

                //parent/child handling
                if(association_header->child) {
                    if(network_header->src_addr != session->nib.parent_address) {
                        SN_ErrPrintf("received address delegation packet from someone not our parent\n");
                        return -SN_ERR_SECURITY;
                    }

                    if(session->mib.macShortAddress != SN_NO_SHORT_ADDRESS) {
                        SN_ErrPrintf("received address delegation when we already have a short address\n");
                        return -SN_ERR_UNEXPECTED;
                    }

                    if(session->nib.enable_routing) {
                        session->nib.enable_routing = association_header->router;
                    }

                    //set our short address to the one we were just given
                    SN_InfoPrintf("setting our short address to %#06x...\n", network_header->dst_addr);
                    mac_primitive_t set_primitive;
                    set_primitive.type                              = mac_mlme_set_request;
                    set_primitive.MLME_SET_request.PIBAttribute     = macShortAddress;
                    set_primitive.MLME_SET_request.PIBAttributeSize = 2;
                    memcpy(set_primitive.MLME_SET_request.PIBAttributeValue, &network_header->dst_addr, 2);
                    MAC_CALL(mac_transmit, session->mac_session, &set_primitive);
                    do_queued_receive_exactly(session, (mac_primitive_t*)macShortAddress_set_confirm);
                    session->mib.macShortAddress             = network_header->dst_addr;

                    if(session->nib.enable_routing) {
                        int ret = SN_Beacon_update(session);
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
        SN_InfoPrintf("processing key confirmation header...\n");
        if(PACKET_ENTRY(*packet, association_header, indication) != NULL) {
            //associate_reply
            assert(table_entry->state == SN_Awaiting_reply);

            //do the challenge1 check (double-hash)
            SN_Hash_t hashbuf;
            SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &hashbuf, 1);
            SN_DebugPrintf("challenge1 (received)   = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data,
                *((uint64_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 1),
                *((uint32_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 4));
            SN_DebugPrintf("challenge1 (calculated) = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)hashbuf.data,
                *((uint64_t*)hashbuf.data + 1),
                *((uint32_t*)hashbuf.data + 4));
            if(memcmp(hashbuf.data, PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
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
            SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &hashbuf, 0);
            SN_DebugPrintf("challenge2 (received)   = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data,
                *((uint64_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 1),
                *((uint32_t*)PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data + 4));
            SN_DebugPrintf("challenge2 (calculated) = %#18"PRIx64"%16"PRIx64"%08"PRIx32"\n",
                *(uint64_t*)hashbuf.data,
                *((uint64_t*)hashbuf.data + 1),
                *((uint32_t*)hashbuf.data + 4));
            if(memcmp(hashbuf.data, PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
                SN_ErrPrintf("key confirmation (challenge1) failed");
                return -SN_ERR_KEYGEN;
            }

            //advance the relationship's state
            table_entry->state = SN_Associated;
        }

        SN_Delayed_acknowledge_special(table_entry, packet);
    }

    //encrypted_ack_header
    if(PACKET_ENTRY(*packet, encrypted_ack_header, indication) != NULL) {
        SN_InfoPrintf("processing encrypted acknowledgement header...\n");
        SN_Delayed_acknowledge_encrypted(table_entry, PACKET_ENTRY(*packet, encrypted_ack_header, indication)->counter);
    }

    //signed_ack_header
    if(PACKET_ENTRY(*packet, signed_ack_header, indication) != NULL) {
        SN_InfoPrintf("processing signed acknowledgement header...\n");
        SN_Delayed_acknowledge_signed(table_entry, &PACKET_ENTRY(*packet, signed_ack_header, indication)->signature);
    }

    return SN_OK;
}

/*argument notes:
 * margin: how much data to skip (after the network header, before the payload) for encryption
 * safe  : if true, arrange so that the original data is untouched on a decryption failure
 */
static int decrypt_verify_packet(SN_AES_key_t* link_key, SN_Public_key_t* key_agreement_key, uint32_t encryption_counter, packet_t* packet, bool pure_ack) {
    SN_DebugPrintf("enter\n");

    if(link_key == NULL || key_agreement_key == NULL || packet == NULL) {
        SN_ErrPrintf("link_key, key_agreement_key, and packet must all be valid\n");
        return -SN_ERR_NULL;
    }

    encryption_header_t* encryption_header = PACKET_ENTRY(*packet, encryption_header, indication);
    assert(encryption_header != NULL);
    const size_t skip_size = packet->layout.encryption_header + sizeof(encryption_header_t);
    SN_InfoPrintf("attempting to decrypt packet of length %d with an encryption header at %d (counter = %x)\n", PACKET_SIZE(*packet, indication), packet->layout.encryption_header, encryption_counter);
    if(PACKET_SIZE(*packet, indication) < skip_size) {
        SN_ErrPrintf("packet is too small\n");
        return -SN_ERR_END_OF_DATA;
    }

    int ret = SN_Crypto_decrypt(link_key, key_agreement_key,
        encryption_counter,
        packet->contents.MCPS_DATA_indication.msdu, packet->layout.encryption_header,
        packet->contents.MCPS_DATA_indication.msdu + skip_size,
        packet->contents.MCPS_DATA_indication.msduLength - skip_size,
        encryption_header->tag, pure_ack);
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

    packet_t packet;
    SN_InfoPrintf("receiving packet...\n");

    int ret;

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
        SN_Delayed_tick(1);
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
            //TODO: routing
            SN_WarnPrintf("we haven't implemented routing yet. drop\n");
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
        .short_address = SN_NO_SHORT_ADDRESS,
    };
    SN_Certificate_storage_t* cert_storage = NULL;
    ret = SN_Table_lookup_by_address(src_addr, &table_entry, &cert_storage);
    if(ret != SN_OK) { //node isn't in node table, so insert it
        SN_InfoPrintf("node isn't in neighbor table, inserting...\n");

        if(src_addr->type == mac_short_address) {
            table_entry.short_address = packet.contents.MCPS_DATA_indication.SrcAddr.ShortAddress;
        } else {
            table_entry.long_address = packet.contents.MCPS_DATA_indication.SrcAddr;
        }

        ret = SN_Table_insert(&table_entry);
        if(ret != SN_OK && ret != -SN_ERR_UNEXPECTED) {
            SN_ErrPrintf("cannot allocate entry in node table (error %d), aborting.\n", -ret);
            return -SN_ERR_RESOURCES;
        }
    }

    //extract data
    SN_InfoPrintf("packet contains payload of length %d\n", packet.layout.payload_length);

    SN_InfoPrintf("doing packet security checks...\n");
    ret = do_security_checks(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in packet security checks. aborting\n", -ret);
        //certain security check failures could come from a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
        if(-ret == SN_ERR_UNEXPECTED) {
            SN_WarnPrintf("possible retransmission bug; triggering retransmission\n");
            SN_Delayed_tick(0);

            //special case: if the security check failure is because this is a finalise, and we've already received one, it's probably an acknowledgement drop. send acknowledgements
            if(PACKET_ENTRY(packet, key_confirmation_header, indication) != NULL && PACKET_ENTRY(packet, association_header, indication) == NULL) {
                SN_WarnPrintf("possible dropped acknowledgement; triggering acknowledgement transmission");
                if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                    SN_Address_t ack_address = {
                        .type = mac_short_address,
                        .address = {.ShortAddress = table_entry.short_address},
                    };
                    SN_Send(session, &ack_address, NULL);
                }
            }
        }
        return ret;
    }

    SN_InfoPrintf("doing public-key operations...\n");
    ret = do_public_key_operations(&table_entry, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("error %d in public-key operations. aborting\n", -ret);
        return ret;
    }

    if(network_header->encrypt) {
        SN_InfoPrintf("doing decryption and integrity checking...\n");
        uint32_t encryption_counter = table_entry.packet_rx_counter;
        bool pure_ack = 0;

        if(PACKET_ENTRY(packet, key_confirmation_header, indication) == NULL && PACKET_ENTRY(packet, encrypted_ack_header, indication) != NULL && PACKET_ENTRY(packet, payload_data, indication) == NULL) {
            //this is a pure-acknowledgement packet; don't change the counter
            pure_ack = 1;
        } else {
            table_entry.packet_rx_counter++;
        }

        ret = decrypt_verify_packet(&table_entry.link_key, &table_entry.remote_key_agreement_key, encryption_counter, &packet, pure_ack);
        if(ret != SN_OK) {
            SN_ErrPrintf("error %d in packet crypto. aborting\n", -ret);
            //certain crypto failures could be a retransmission as a result of a dropped acknowledgement; trigger retransmissions to guard against this
            SN_WarnPrintf("crypto error could be due to dropped acknowledgement; triggering acknowledgement and packet retransmission");
            SN_Delayed_tick(0);
            if(table_entry.short_address != SN_NO_SHORT_ADDRESS) {
                SN_Address_t ack_address = {
                    .type = mac_short_address,
                    .address = {.ShortAddress = table_entry.short_address},
                };
                SN_Send(session, &ack_address, NULL);
            }
            return ret;
        }
    }

    SN_InfoPrintf("processing packet headers...\n");
    ret = process_packet_headers(session, &table_entry, &packet);
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

        //advance the buffer by one association message
        buffer = (SN_Message_t*)((uint8_t*)buffer + sizeof(buffer->association_message));
        buffer_size -= sizeof(buffer->association_message);

        //fill in the association message contents
        association_request->type                             = PACKET_ENTRY(packet, association_header, indication)->dissociate ? SN_Dissociation_request : SN_Association_request;
        association_request->association_message.stapled_data = buffer_size == 0 ? NULL : buffer;

        SN_InfoPrintf("message synthesis done. output buffer has %zu bytes remaining.\n", buffer_size);
        if(buffer_size == 0) {
            SN_WarnPrintf("output buffer has no space remaining after association message synthesis\n");
        }
    }

    SN_InfoPrintf("processing packet...\n");
    uint8_t* payload_data = PACKET_ENTRY(packet, payload_data, indication);
    if(packet.layout.payload_length != 0) {
        assert(payload_data != NULL);

        table_entry.ack = (uint8_t)(PACKET_ENTRY(packet, encryption_header, indication) != NULL);
        if(network_header->evidence) {
            //evidence packet
            if(packet.layout.payload_length != sizeof(SN_Certificate_t)) {
                SN_ErrPrintf("received evidence packet with payload of invalid length %d (should be %zu)\n", packet.layout.payload_length, sizeof(SN_Certificate_t));
                return -SN_ERR_INVALID;
            }

            //error-check the certificate, and add it to certificate storage
            SN_Certificate_t* evidence = (SN_Certificate_t*)payload_data;
            ret = SN_Crypto_add_certificate(cert_storage, evidence);
            if(ret == -SN_ERR_SIGNATURE ||
               (ret == -SN_ERR_NULL && SN_Crypto_check_certificate(evidence) != SN_OK)) {
                SN_ErrPrintf("received evidence packet with invalid payload\n");
                return -SN_ERR_SIGNATURE;
            }

            //return to user
            if(buffer_size < sizeof(buffer->evidence_message)) {
                SN_ErrPrintf("output buffer is too small for incoming certificate\n");
                return -SN_ERR_RESOURCES;
            }
            buffer->type                      = SN_Evidence_message;
            buffer->evidence_message.evidence = *evidence;
        } else {
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
    } else if(association_request != NULL) {
        association_request->association_message.stapled_data = NULL;
    }

    SN_Table_update(&table_entry);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
