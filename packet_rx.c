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
#include "reliable_tx.h"
#include "constants.h"

#include "net/netstack.h"
#include "net/mac/frame802154.h"

#include <assert.h>

//outputs crypto margin, and pointers to the key agreement header and payload data
//also detects basic protocol failures
int packet_detect_layout(packet_t* packet) {
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
    if(ATTRIBUTE(network_header, alt_stream)) {
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
    if(CONTROL_ATTRIBUTE(network_header, details)) {
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
    if(CONTROL_ATTRIBUTE(network_header, associate)) {
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
    if(ATTRIBUTE(network_header, key_confirm)) {
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
    if(DATA_ATTRIBUTE(network_header, ack)) {
        if(PACKET_SIZE(*packet, indication) < current_position + sizeof(encrypted_ack_header_t)) {
            SN_ErrPrintf("packet indicates an acknowledgement (encrypted) header, but is too small. aborting\n");
            return -SN_ERR_END_OF_DATA;
        }
        SN_InfoPrintf("found acknowledgement (encrypted) header at %d\n", current_position);
        packet->layout.encrypted_ack_header         = current_position;
        packet->layout.present.encrypted_ack_header = 1;
        current_position += sizeof(encrypted_ack_header_t);
    }

    //encryption_header_t / signature_header_t
    if(ATTRIBUTE(network_header, data)) {
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
    if(DATA_ATTRIBUTE(network_header, evidence)) {
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

int packet_security_checks(packet_t* packet, SN_Table_entry_t* table_entry) {
    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //alt-stream check: alt streams are only allowed for nodes using their short address
    if(PACKET_ENTRY(*packet, network_header, indication)->src_addr == FRAME802154_INVALIDADDR &&
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
        if(PACKET_ENTRY(*packet, payload_data, indication) != NULL && PACKET_ENTRY(*packet, evidence_header, indication) != NULL) {
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

int packet_public_key_operations(packet_t* packet, SN_Table_entry_t* table_entry) {
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
            &starfishnet_config.device_root_key.public_key,
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

int packet_process_headers(packet_t* packet, SN_Table_entry_t* table_entry) {
    network_header_t* network_header;

    if(table_entry == NULL || packet == NULL) {
        SN_ErrPrintf("table_entry and packet must be valid\n");
        return -SN_ERR_NULL;
    }

    //at this point, security and integrity checks are guaranteed to have passed

    //network_header
    network_header = PACKET_ENTRY(*packet, network_header, indication);
    assert(network_header != NULL);
    if(CONTROL_ATTRIBUTE(network_header, req_details)) {
        SN_InfoPrintf("partner has requested our details\n");
        table_entry->knows_details = 0;
    } else {
        table_entry->knows_details = 1;
    }
    if(network_header->src_addr != FRAME802154_INVALIDADDR) {
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
                    if(network_header->src_addr != starfishnet_config.parent_address) {
                        SN_ErrPrintf("received address delegation packet from someone not our parent\n");
                        return -SN_ERR_SECURITY;
                    }

                    if(starfishnet_config.short_address != FRAME802154_INVALIDADDR) {
                        SN_ErrPrintf("received address delegation when we already have a short address\n");
                        return -SN_ERR_UNEXPECTED;
                    }

                    if(starfishnet_config.enable_routing) {
                        starfishnet_config.enable_routing = association_header->router;
                    }

                    //set our short address to the one we were just given
                    SN_InfoPrintf("setting our short address to 0x%04x...\n", network_header->dst_addr);
                    if(NETSTACK_RADIO.set_value(RADIO_PARAM_16BIT_ADDR, starfishnet_config.short_address) != RADIO_RESULT_OK) {
                        SN_ErrPrintf("couldn't set the radio's short address...\n");
                        return -SN_ERR_RADIO;
                    }
                    starfishnet_config.short_address = network_header->dst_addr;

                    if(starfishnet_config.enable_routing) {
                        SN_Beacon_update();
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
        SN_Crypto_hash(table_entry->link_key.data, sizeof(table_entry->link_key.data), &hashbuf);
        if(challengenumber == 2) {
            SN_Crypto_hash(hashbuf.data, SN_Hash_size, &hashbuf);
        }
        if(memcmp(hashbuf.data, PACKET_ENTRY(*packet, key_confirmation_header, indication)->challenge.data, sizeof(hashbuf.data)) != 0) {
            SN_ErrPrintf("key confirmation (challenge%d) failed.\n", challengenumber);
            return -SN_ERR_KEYGEN;
        }

        //advance the relationship's state
        table_entry->state = challengenumber == 2 ? SN_Associated : SN_Send_finalise;

        SN_Retransmission_acknowledge_implicit(table_entry, packet);
    }

    //encrypted_ack_header
    if(PACKET_ENTRY(*packet, encrypted_ack_header, indication) != NULL) {
        SN_InfoPrintf("processing encrypted acknowledgement header...\n");
        SN_Retransmission_acknowledge_data(table_entry, PACKET_ENTRY(*packet, encrypted_ack_header, indication)->counter);
    }

    return SN_OK;
}

/*argument notes:
 * margin: how much data to skip (after the network header, before the payload) for encryption
 * safe  : if true, arrange so that the original data is untouched on a decryption failure
 */
int packet_decrypt_verify(packet_t* packet, const SN_Public_key_t* key_agreement_key, const SN_AES_key_t* link_key,
                          uint32_t encryption_counter, bool pure_ack) {
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
    skip_size = packet->layout.encryption_header + (uint8_t)sizeof(encryption_header_t);
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
