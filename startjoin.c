#include "starfishnet.h"
#include "node_table.h"
#include "logging.h"
#include "status.h"
#include "routing_tree.h"
#include "discovery.h"
#include "config.h"

#include "net/mac/frame802154.h"

#include <string.h>
#include <malloc.h>
#include <assert.h>

//start a new StarfishNet network as coordinator
int8_t SN_Start(const SN_Network_descriptor_t *network) {
    int ret;

    SN_InfoPrintf("enter\n");

    if(network == NULL || network->network_config == NULL) {
        SN_ErrPrintf("network and network->config must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //Fill NIB
    SN_InfoPrintf("filling NIB...\n");
    starfishnet_config.tree_branching_factor = network->network_config->routing_tree_branching_factor;
    starfishnet_config.tree_position         = 0;
    starfishnet_config.enable_routing        = 1;
    starfishnet_config.leaf_blocks           = network->network_config->leaf_blocks;
    starfishnet_config.parent_address        = SN_COORDINATOR_ADDRESS;
    memcpy(&starfishnet_config.parent_public_key, &starfishnet_config.device_root_key.public_key, sizeof(starfishnet_config.parent_public_key));

    ret = SN_Tree_init();
    if(ret != SN_OK) {
        SN_ErrPrintf("error in routing tree configuration: %d\n", -ret);
        return ret;
    }

    SN_InfoPrintf("setting channel...\n");
    if(NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, network->radio_channel) != RADIO_RESULT_OK) {
        SN_ErrPrintf("tried to set channel to %d; radio said no\n", network->radio_channel);
        return -SN_ERR_RADIO;
    }

    SN_InfoPrintf("setting short address...\n");
    if(NETSTACK_RADIO.set_value(RADIO_PARAM_16BIT_ADDR, SN_COORDINATOR_ADDRESS) != RADIO_RESULT_OK) {
        SN_ErrPrintf("tried to set short address to %d; radio said no\n", SN_COORDINATOR_ADDRESS);
        return -SN_ERR_RADIO;
    }
    starfishnet_config.short_address = SN_COORDINATOR_ADDRESS;

    SN_InfoPrintf("setting PAN ID...\n");
    if(NETSTACK_RADIO.set_value(RADIO_PARAM_PAN_ID, network->pan_id) != RADIO_RESULT_OK) {
        SN_ErrPrintf("tried to set PAN ID to %d; radio said no\n", network->pan_id);
        return -SN_ERR_RADIO;
    }
    starfishnet_config.pan_id = network->pan_id;

    SN_InfoPrintf("updating beacon payload\n");
    SN_Beacon_update();

    return SN_OK;
}

static int8_t add_parent_to_node_table() {
    int8_t ret;
    SN_Table_entry_t* parent_table_entry = malloc(sizeof(SN_Table_entry_t));

    SN_InfoPrintf("adding parent (0x%04x) to node table\n", starfishnet_config.parent_address);

    if(parent_table_entry == NULL) {
        SN_InfoPrintf("failed to add parent to node table due to lack of memory\n");
        ret = -SN_ERR_RESOURCES;
        goto exit;
    }
    memset(parent_table_entry, 0, sizeof(*parent_table_entry));
    parent_table_entry->short_address = starfishnet_config.parent_address;
    parent_table_entry->details_known = 1;
    memcpy(&parent_table_entry->public_key, &starfishnet_config.parent_public_key, sizeof(parent_table_entry->public_key));

    ret = SN_Table_lookup(NULL, parent_table_entry);
    if(ret == SN_OK) {
        parent_table_entry->short_address = starfishnet_config.parent_address;
        parent_table_entry->details_known = 1;
        memcpy(&parent_table_entry->public_key, &starfishnet_config.parent_public_key, sizeof(parent_table_entry->public_key));
    }

    parent_table_entry->neighbor = 1;

    SN_InfoPrintf("performing table insertion\n");
    SN_Table_update(parent_table_entry);
    ret = SN_Table_insert(parent_table_entry);
    if(ret == -SN_ERR_UNEXPECTED) {
        //it's ok if the entry already exists
        ret = SN_OK;
    }

    exit:
    free(parent_table_entry);
    return ret;
}

/* Tune the radio to a StarfishNet network.
 * Then, discover any other nearby nodes, and add them to the node table as neighbors.
 * Finally, associate with our new parent and get an address.
 *
 * Note that if routing is disabled, we don't transmit beacons.
 */
int8_t SN_Join(const SN_Network_descriptor_t *network, bool disable_routing) {
    int8_t ret;
    SN_Endpoint_t *parent_address;

    SN_InfoPrintf("enter\n");

    //we're joining a new network, so assume we have no neighbors
    SN_Table_clear_all_neighbors();

    //Fill NIB
    SN_InfoPrintf("filling NIB...\n");
    starfishnet_config.tree_branching_factor = network->network_config->routing_tree_branching_factor;
    starfishnet_config.tree_position = network->network_config->routing_tree_position;
    starfishnet_config.enable_routing = (uint8_t) (disable_routing ? 0 : 1);
    starfishnet_config.leaf_blocks = network->network_config->leaf_blocks;
    starfishnet_config.parent_address = network->network_config->router_address;
    starfishnet_config.pan_id = network->pan_id;
    memcpy(&starfishnet_config.parent_public_key, &network->network_config->router_public_key,
           sizeof(starfishnet_config.parent_public_key));

    //Do routing tree math and set up address allocation
    SN_InfoPrintf("configuring the routing tree...\n");
    ret = SN_Tree_init();

    assert(SN_OK == RADIO_RESULT_OK);

    //Tune to the right channel
    if (ret == SN_OK) {
        SN_InfoPrintf("setting radio channel to %d...\n", network->radio_channel);
        ret = NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, network->radio_channel);
        if (ret != RADIO_RESULT_OK) {
            ret = -SN_ERR_RADIO;
        }
    }

    //Set our PAN ID
    if (ret == SN_OK) {
        SN_InfoPrintf("setting PAN ID to 0x%04x...\n", starfishnet_config.pan_id);
        ret = NETSTACK_RADIO.set_value(RADIO_PARAM_PAN_ID, starfishnet_config.pan_id);
        if (ret != RADIO_RESULT_OK) {
            ret = -SN_ERR_RADIO;
        }
    }

    //add parent to node table
    if (ret == SN_OK) {
        ret = add_parent_to_node_table();
    }

    //start neighbor discovery
    if (ret == SN_OK) {
        ret = SN_Discover_neighbors();
    }

    if (ret != SN_OK) {
        return ret;
    }

    //start security association with our parent (implicitly requesting an address)
    parent_address = malloc(sizeof(SN_Endpoint_t));
    if (parent_address == NULL) {
        SN_InfoPrintf("cannot send association message due to lack of memory\n");
        return -SN_ERR_RESOURCES;
    }
    memset(parent_address, 0, sizeof(*parent_address));
    parent_address->type = SN_ENDPOINT_SHORT_ADDRESS;
    parent_address->short_address = starfishnet_config.parent_address;
    SN_InfoPrintf("sending associate request to 0x%04x\n", parent_address->short_address);
    ret = SN_Associate(parent_address);
    free(parent_address);

    //And we're done
    SN_InfoPrintf("exit\n");
    return ret;
}
