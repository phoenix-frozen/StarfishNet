#include "sn_core.h"
#include "node_table.h"
#include "logging.h"
#include "status.h"
#include "crypto.h"
#include "constants.h"
#include "routing_tree.h"
#include "sn_beacons.h"

#include <assert.h>
#include <string.h>

//start a new StarfishNet network as coordinator
int SN_Start(SN_Session_t *session, SN_Network_descriptor_t *network) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || network == NULL) {
        SN_ErrPrintf("session and network must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    mac_primitive_t packet;

    //reinit node table
    SN_InfoPrintf("clearing node table\n");
    SN_Table_clear();

    //Fill NIB
    SN_InfoPrintf("filling NIB...\n");
    session->nib.tree_branching_factor = network->routing_tree_branching_factor;
    session->nib.tree_position       = 0;
    session->nib.leaf_blocks         = network->leaf_blocks;
    session->nib.parent_address      = SN_COORDINATOR_ADDRESS;
    session->nib.enable_routing      = 1;

    int ret = SN_Tree_init();
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
    return SN_Beacon_update();
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
int SN_Join(SN_Session_t *session, SN_Network_descriptor_t *network, bool disable_routing) {
    SN_InfoPrintf("enter\n");
    int ret;

    //perform extra discovery step to fill in node table
    SN_Table_clear_all_neighbors();
    ret = SN_OK;
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
        ret = SN_Tree_init();
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
        SN_Endpoint_t parent_address = {
            .type = mac_short_address,
            .address.ShortAddress = network->router_address,
        };
        SN_InfoPrintf("sending association message...\n");
        ret = SN_Associate(&parent_address);
    }

    //make sure the association completes
    if(ret == SN_OK) {
        SN_Endpoint_t address;
        SN_Message_t* message = NULL;
        uint8_t message_data[sizeof(message->data_message) + SN_MAX_DATA_MESSAGE_LENGTH]; //XXX: this won't segfault
        message = (SN_Message_t*)message_data;

        SN_InfoPrintf("waiting for association reply from %#06x...\n", network->router_address);
        do {
            //wait for data...
            ret = SN_Receive(session, &address, message, sizeof(message_data));
            if(ret == SN_OK) {
                switch(address.type) {
                    case mac_extended_address:
                        SN_InfoPrintf("received from (long) %#18"PRIx64"\n", *(uint64_t*)address.address.ExtendedAddress);
                        break;

                    case mac_short_address:
                        SN_InfoPrintf("received from (short) %#06x\n", address.address.ShortAddress);
                        break;

                    default:
                        SN_ErrPrintf("packet address is bullshit\n");
                        break;
                }
            }
        } while(ret != SN_ERR_RADIO && !(ret == SN_OK && address.type == mac_short_address &&
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
