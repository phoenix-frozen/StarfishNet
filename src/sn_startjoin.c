#include <sn_core.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <sn_status.h>

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <sn_crypto.h>

#include "sn_constants.h"
#include "mac_util.h"
#include "sn_routing_tree.h"
#include "sn_beacons.h"

static MAC_SET_CONFIRM(macAssociationPermit);

static MAC_SET_CONFIRM(macPANId);

static MAC_SET_CONFIRM(macRxOnWhenIdle);

static MAC_SET_CONFIRM(macShortAddress);

static MAC_SET_CONFIRM(phyCurrentChannel);

static MAC_SET_CONFIRM(macCoordShortAddress);

static MAC_SET_CONFIRM(macCoordExtendedAddress);

static MAC_SET_CONFIRM(macPromiscuousMode);

//start a new StarfishNet network as coordinator
int SN_Start(SN_Session_t* session, SN_Network_descriptor_t* network) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || network == NULL) {
        SN_ErrPrintf("session and network must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    mac_primitive_t packet;

    //reinit node table
    SN_InfoPrintf("clearing node table\n");
    SN_Table_clear(session);

    //Fill NIB
    SN_InfoPrintf("filling NIB...\n");
    session->nib.tree_branching_factor = network->routing_tree_branching_factor;
    session->nib.tree_position       = 0;
    session->nib.leaf_blocks         = network->leaf_blocks;
    session->nib.parent_address      = SN_COORDINATOR_ADDRESS;
    session->nib.enable_routing      = 1;

    int ret = SN_Tree_configure(session);
    if(ret != SN_OK) {
        SN_ErrPrintf("error in routing tree configuration: %d\n", -ret);
        return ret;
    }

    //update the MIB and PIB
    SN_InfoPrintf("filling [MP]IB...\n");
    session->pib.phyCurrentChannel    = network->radio_channel;
    session->mib.macPANId             = network->pan_id;
    session->mib.macCoordAddrMode     = mac_extended_address;
    session->mib.macCoordShortAddress = SN_COORDINATOR_ADDRESS;
    memcpy(session->mib.macCoordExtendedAddress.ExtendedAddress, session->mib.macIEEEAddress.ExtendedAddress, 8);
    session->mib.macShortAddress = SN_COORDINATOR_ADDRESS;

    //Set our short address
    SN_InfoPrintf("setting our short address...\n");
    packet.type                              = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute     = macShortAddress;
    packet.MLME_SET_request.PIBAttributeSize = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

    //Switch on RX_ON_IDLE
    SN_InfoPrintf("switching on radio while idle...\n");
    packet.type                              = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute     = macRxOnWhenIdle;
    packet.MLME_SET_request.PIBAttributeSize = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = 1;
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macRxOnWhenIdle_set_confirm);
    session->mib.macRxOnWhenIdle = 1;

    //configure the radio
    SN_InfoPrintf("setting up beacon transmission, PAN ID, and radio channel...\n");
    return SN_Beacon_update(session);
}

static inline uint8_t log2i(uint32_t n) {
    if(n == 0) {
        return 0;
    }
    return (uint8_t)31 - (uint8_t)__builtin_clz(n);
}

/* scan for StarfishNet networks
 *
 * You get one callback for each network discovered, with the extradata you provided.
 */
int SN_Discover(SN_Session_t* session, uint32_t channel_mask, uint32_t timeout, bool show_full_networks, SN_Discovery_callback_t* callback, void* extradata) {
    SN_InfoPrintf("enter\n");
    SN_InfoPrintf("performing discovery over %#010"PRIx32", in %d ms\n", channel_mask, timeout);

    if(session == NULL || callback == NULL) {
        SN_ErrPrintf("session and callback must both be valid\n");
        return -SN_ERR_NULL;
    }

    channel_mask &= 0x07FFF800; //top 5 bits don't exist, bottom 11 bits aren't 2.4GHz

    SN_InfoPrintf("adjusted channel mask is %#010"PRIx32"\n", channel_mask);
    if(channel_mask == 0) {
        SN_WarnPrintf("no channels to scan, aborting...\n");
        return SN_OK;
    }

    //Setup a network scan
    mac_primitive_t packet;
    packet.type                           = mac_mlme_scan_request;
    packet.MLME_SCAN_request.ScanType     = mac_active_scan;
    packet.MLME_SCAN_request.ScanChannels = channel_mask;

    //Timeout is in ms. We need to convert it into a form the radio will understand.
    //We're given ms, the radio wants an exponent for a calculation denominated in radio symbols.
    timeout /= __builtin_popcount(packet.MLME_SCAN_request.ScanChannels); //divide the timeout equally between the channels to scan, which number 11 to 26
    if(timeout * aSymbolsPerSecond_24 / 1000 <= aBaseSuperframeDuration) {
        SN_ErrPrintf("timeout value %u is too short\n", timeout);
        return -SN_ERR_INVALID;
    }
    packet.MLME_SCAN_request.ScanDuration = log2i(
        (timeout * aSymbolsPerSecond_24 / 1000 - aBaseSuperframeDuration) / aBaseSuperframeDuration);
    if(packet.MLME_SCAN_request.ScanDuration > 14) {
        SN_WarnPrintf("ScanDuration %u is too high, capping.\n", packet.MLME_SCAN_request.ScanDuration);
        packet.MLME_SCAN_request.ScanDuration = 14;
    }

    //initiate the scan
    SN_InfoPrintf("initiating scan with ScanDuration=%u\n", packet.MLME_SCAN_request.ScanDuration);
    MAC_CALL(mac_transmit, session->mac_session, &packet);

    SN_Network_descriptor_t ndesc;

    //During a scan, we get a MLME-BEACON.indication for each received beacon.
    //MLME-SCAN.confirm is received when a scan finishes.
    static const mac_primitive_type_t scan_primitive_types[] = {mac_mlme_beacon_notify_indication,
                                                                mac_mlme_scan_confirm};
    while(1) {
        //receive a primitive
        MAC_CALL(mac_receive_primitive_types, session->mac_session, &packet, scan_primitive_types,
            sizeof(scan_primitive_types) / sizeof(mac_primitive_type_t));
        //implicitly drops anything that isn't of that type

        //if it's an MLME-SCAN.confirm, we're done -- quit out
        if(packet.type == mac_mlme_scan_confirm) {
            break;
        }

        //during a scan, the radio's only supposed to generate MLME-BEACON-NOTIFY.indication or MLME-SCAN.confirm
        assert(packet.type == mac_mlme_beacon_notify_indication);

        SN_InfoPrintf("found network. channel=0x%x, PANId=0x%#04x\n", packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.LogicalChannel, packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordPANId);

        //if we get to here, we're looking at an MLME-BEACON-NOTIFY.indication

        //check beacon payload is of the correct length and router is broadcasting with a short address
        if(packet.MLME_BEACON_NOTIFY_indication.sduLength != sizeof(beacon_payload_t) + BEACON_HASH_LENGTH) {
            continue;
        }

        //set up some pointers, and then do a hash check
        beacon_payload_t* beacon_payload  = (beacon_payload_t*)packet.MLME_BEACON_NOTIFY_indication.sdu;
        if(packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordAddrMode != mac_short_address) {
            SN_InfoPrintf("Router is using its long address; a StarfishNet node should be using its short address.\n");
            continue;
        } else {
            SN_InfoPrintf("    CoordAddress=%#06x\n", packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordAddress.ShortAddress);
            if(beacon_payload->address != packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordAddress.ShortAddress) {
                SN_WarnPrintf("    Address mismatch! Using %#06x\n", beacon_payload->address);
            }
        }

        //check that this is a network of the kind we care about
        SN_InfoPrintf("    PID=%#04x, PVER=%#04x\n", beacon_payload->protocol_id, beacon_payload->protocol_ver);
        if(beacon_payload->protocol_id != STARFISHNET_PROTOCOL_ID || beacon_payload->protocol_ver != STARFISHNET_PROTOCOL_VERSION) {
            SN_InfoPrintf("Beacon is for wrong kind of network.\n");
            continue;
        }

        //XXX: this is the most disgusting way to print a key ever invented by man
        SN_InfoPrintf("    key=%#018"PRIx64"%016"PRIx64"%08"PRIx32"\n",
            *(uint64_t*)beacon_payload->public_key.data,
            *(((uint64_t*)beacon_payload->public_key.data) + 1),
            *(((uint32_t*)beacon_payload->public_key.data) + 4));

        SN_Hash_t* beacon_hash = (SN_Hash_t*)(packet.MLME_BEACON_NOTIFY_indication.sdu + sizeof(beacon_payload_t));
        SN_Hash_t protohash;
        SN_Crypto_hash((uint8_t*)beacon_payload, sizeof(*beacon_payload), &protohash, 0);
        if(memcmp(beacon_hash, &protohash, BEACON_HASH_LENGTH) != 0) {
            SN_WarnPrintf("Beacon hash check failed.\n");
            continue;
        }

        if(beacon_payload->router_capacity == 0 && beacon_payload->leaf_capacity == 0) {
            SN_WarnPrintf("Router is full.\n");

            if(!show_full_networks) {
                continue;
            }
        }

        if(SN_Tree_check_join(beacon_payload->tree_position + (uint8_t)1, beacon_payload->branching_factor) < 0) {
            SN_WarnPrintf("Router has invalid tree configuration\n");
            continue;
        }

        ndesc.router_address        = beacon_payload->address;
        ndesc.router_public_key     = beacon_payload->public_key;
        ndesc.pan_id                = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordPANId;
        ndesc.radio_channel         = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.LogicalChannel;
        ndesc.routing_tree_branching_factor = beacon_payload->branching_factor;
        ndesc.routing_tree_position = beacon_payload->tree_position + (uint8_t)1;
        ndesc.leaf_blocks           = beacon_payload->leaf_blocks;

        callback(session, &ndesc, extradata);
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

/* Tune the radio to a StarfishNet network and listen for packets with its PAN ID.
 * Note, this call does not directly cause any packet exchange.
 * Packets may or may not be routable to us until we associate with a parent, at which point
 * routing is guaranteed to work.
 * Remember that naive broadcasts won't be receivable until we do a SA with a neighbor router.
 *
 * Note that if routing is disabled, we don't transmit beacons.
 */
int mac_join(SN_Session_t* session, SN_Network_descriptor_t* network) {
    SN_DebugPrintf("enter\n");

    if(session == NULL || network == NULL) {
        SN_ErrPrintf("session and network must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    mac_primitive_t packet;

    //configure the radio

    //Tune to the right channel
    if(session->pib.phyCurrentChannel != network->radio_channel) {
        SN_InfoPrintf("setting channel...\n");
        packet.type                              = mac_mlme_set_request;
        packet.MLME_SET_request.PIBAttribute     = phyCurrentChannel;
        packet.MLME_SET_request.PIBAttributeSize = 1;
        packet.MLME_SET_request.PIBAttributeValue[0] = network->radio_channel;
        MAC_CALL(mac_transmit, session->mac_session, &packet);
        MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)phyCurrentChannel_set_confirm);
        session->pib.phyCurrentChannel = network->radio_channel;
    }

    //Set our PAN Id
    if(session->mib.macPANId != network->pan_id) {
        SN_InfoPrintf("setting PAN ID...\n");
        packet.type                              = mac_mlme_set_request;
        packet.MLME_SET_request.PIBAttribute     = macPANId;
        packet.MLME_SET_request.PIBAttributeSize = 2;
        memcpy(packet.MLME_SET_request.PIBAttributeValue, &network->pan_id, 2);
        MAC_CALL(mac_transmit, session->mac_session, &packet);
        MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macPANId_set_confirm);
        session->mib.macPANId = network->pan_id;
    }

    //Set our coord short address
    SN_InfoPrintf("setting coord short address...\n");
    session->mib.macCoordShortAddress        = SN_COORDINATOR_ADDRESS;
    session->mib.macCoordAddrMode            = mac_short_address;
    packet.type                              = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute     = macCoordShortAddress;
    packet.MLME_SET_request.PIBAttributeSize = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macCoordShortAddress, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macCoordShortAddress_set_confirm);

    //Then, do some final configuration.

    //Set our short address to the no-short-address marker address, enabling transmission
    SN_InfoPrintf("setting our short address...\n");
    session->mib.macShortAddress             = SN_NO_SHORT_ADDRESS;
    packet.type                              = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute     = macShortAddress;
    packet.MLME_SET_request.PIBAttributeSize = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

    //Switch on RX_ON_IDLE
    SN_InfoPrintf("switching on radio while idle...\n");
    packet.type                              = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute     = macRxOnWhenIdle;
    packet.MLME_SET_request.PIBAttributeSize = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = 1;
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macRxOnWhenIdle_set_confirm);
    session->mib.macRxOnWhenIdle = 1;

    //And we're done
    SN_DebugPrintf("exit\n");
    return SN_OK;
}

/* Tune the radio to a StarfishNet network.
 * Then, discover any other nearby nodes, and add them to the node table as neighbors.
 * Finally, associate with our new parent and get an address.
 *
 * Note that if routing is disabled, we don't transmit beacons.
 *
 * (fill_node_table is a callback for SN_Discover)
 */
static void fill_node_table(SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata) {
    SN_Table_entry_t router_table_entry = {
        .session       = session,
        .short_address = network->router_address,
        .neighbor      = 1,
        .public_key    = network->router_public_key,
        .details_known = 1,
    };
    SN_InfoPrintf("adding neighbor to node table...\n");
    SN_Table_insert(&router_table_entry);

    (void)extradata;
};
int SN_Join(SN_Session_t* session, SN_Network_descriptor_t* network, bool disable_routing) {
    SN_InfoPrintf("enter\n");
    int ret;

    //perform extra discovery step to fill in node table
    SN_Table_clear_all_neighbors(session);
    ret = SN_Discover(session, 1u << network->radio_channel, 2000, 1, &fill_node_table, NULL);

    //Fill NIB (and set parent)
    if(ret == SN_OK) {
        SN_InfoPrintf("filling NIB...\n");
        session->nib.tree_branching_factor = network->routing_tree_branching_factor;
        session->nib.tree_position    = network->routing_tree_position;
        session->nib.enable_routing   = (uint8_t)(disable_routing ? 0 : 1);
        session->nib.parent_address   = network->router_address;
        session->nib.leaf_blocks      = network->leaf_blocks;
        session->nib.parent_public_key = network->router_public_key;
        session->nib.parent_address    = network->router_address;
    }

    //Do routing tree math and set up address allocation
    if(ret == SN_OK) {
        ret = SN_Tree_configure(session);
    }

    //tune radio
    if(ret == SN_OK) {
        ret = mac_join(session, network);
    }

    //add parent to node table
    if(ret == SN_OK) {
        SN_Table_entry_t parent_table_entry = {
            .session       = session,
            .short_address = network->router_address,
            .neighbor      = 1,
            .public_key    = network->router_public_key,
            .details_known = 1,
        };
        SN_InfoPrintf("adding parent to node table...\n");
        ret = SN_Table_insert(&parent_table_entry);
        if(ret == -SN_ERR_UNEXPECTED) {
            //it's ok if the entry already exists, since the earlier discovery should have added it
            ret = SN_OK;
        }
    }

    //start security association (implicitly requesting an address)
    if(ret == SN_OK) {
        SN_Address_t parent_address = {
            .type = mac_short_address,
            .address.ShortAddress = network->router_address,
        };
        SN_InfoPrintf("sending association message...\n");
        ret = SN_Associate(session, &parent_address, NULL);
    }

    //make sure the association completes
    if(ret == SN_OK) {
        SN_Address_t address;
        SN_Message_t* message = NULL;
        uint8_t message_data[sizeof(message->data_message) + SN_MAX_DATA_MESSAGE_LENGTH]; //XXX: this won't segfault
        message = (SN_Message_t*)message_data;

        SN_InfoPrintf("waiting for association reply...\n");
        do {
            //wait for data...
            ret = SN_Receive(session, &address, message, sizeof(message_data));
        } while(ret != SN_ERR_RADIO || !(ret == SN_OK && address.type == mac_short_address &&
            address.address.ShortAddress == network->router_address));
            //... from our parent

        //received a message from our parent
        if(message->type != SN_Association_request) {
            //received something not an association request; we probably need to abort
            ret = -SN_ERR_DISCONNECTED;
            SN_ErrPrintf("reply from parent was not an association message\n");

            //XXX: this code precludes stapled data in an associate_reply
        }
    }

    //And we're done
    if(ret != SN_OK) {
        SN_ErrPrintf("an error occurred; resetting radio and clearing node table...\n");
        mac_primitive_t packet;
        mac_reset_radio(session, &packet);
    }
    SN_InfoPrintf("exit\n");
    return ret;
}