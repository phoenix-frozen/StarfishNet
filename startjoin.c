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

//start a new StarfishNet network as coordinator
int SN_Start(SN_Network_descriptor_t* network) {
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

/* Tune the radio to a StarfishNet network.
 * Then, discover any other nearby nodes, and add them to the node table as neighbors.
 * Finally, associate with our new parent and get an address.
 *
 * Note that if routing is disabled, we don't transmit beacons.
 *
 * (fill_node_table is a callback for SN_Discover)
 */
/*static void fill_node_table(SN_Network_descriptor_t* network, void* extradata) {
    SN_Table_entry_t router_table_entry = {
        .short_address = network->network_config->router_address,
        .neighbor      = 1,
        .details_known = 1,
    };
    memcpy(&router_table_entry.public_key, &network->network_config->router_public_key, sizeof(router_table_entry.public_key));

    (void)extradata; //shut up GCC

    SN_InfoPrintf("adding neighbor to node table...\n");
    SN_Table_insert(&router_table_entry);
}*/
int SN_Join(SN_Network_descriptor_t* network, bool disable_routing) {
    int ret = SN_OK;

    SN_InfoPrintf("enter\n");

    //perform extra discovery step to fill in node table
    SN_Table_clear_all_neighbors();
    //ret = SN_Discover(&fill_node_table, 1u << network->radio_channel, 2000, 1, NULL);

    //Fill NIB
    if(ret == SN_OK) {
        SN_InfoPrintf("filling NIB...\n");
        starfishnet_config.tree_branching_factor = network->network_config->routing_tree_branching_factor;
        starfishnet_config.tree_position         = network->network_config->routing_tree_position;
        starfishnet_config.enable_routing        = (uint8_t)(disable_routing ? 0 : 1);
        starfishnet_config.leaf_blocks           = network->network_config->leaf_blocks;
        starfishnet_config.parent_address        = network->network_config->router_address;
        memcpy(&starfishnet_config.parent_public_key, &network->network_config->router_public_key, sizeof(starfishnet_config.parent_public_key));
        SN_InfoPrintf("starfishnet_config.tree_branching_factor = %d\n", starfishnet_config.tree_branching_factor);
        SN_InfoPrintf("starfishnet_config.tree_position         = %d\n", starfishnet_config.tree_position        );
        SN_InfoPrintf("starfishnet_config.enable_routing        = %d\n", starfishnet_config.enable_routing       );
        SN_InfoPrintf("starfishnet_config.leaf_blocks           = %d\n", starfishnet_config.leaf_blocks          );
        SN_InfoPrintf("starfishnet_config.parent_address        = 0x%04x\n", starfishnet_config.parent_address       );
    }

    //Do routing tree math and set up address allocation
    if(ret == SN_OK) {
        SN_InfoPrintf("configuring the routing tree...\n");
        ret = SN_Tree_init();
    }

    //Tune to the right channel
    if(ret == SN_OK) {
        SN_InfoPrintf("setting radio channel to %d...\n", network->radio_channel);
        if(NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, network->radio_channel) != RADIO_RESULT_OK) {
            ret = -SN_ERR_RADIO;
        }
    }

    //Set our PAN ID
    if(ret == SN_OK) {
        SN_InfoPrintf("setting PAN ID to 0x%04x...\n", network->pan_id);
        if(NETSTACK_RADIO.set_value(RADIO_PARAM_PAN_ID, network->pan_id) != RADIO_RESULT_OK) {
            ret = -SN_ERR_RADIO;
        } else {
            starfishnet_config.pan_id = network->pan_id;
        }
    }

    //add parent to node table
    if(ret == SN_OK) {
        SN_Table_entry_t* parent_table_entry = malloc(sizeof(SN_Table_entry_t));
        memset(parent_table_entry, 0, sizeof(*parent_table_entry));
        parent_table_entry->short_address = starfishnet_config.parent_address;
        parent_table_entry->neighbor = 1;
        parent_table_entry->details_known = 1;
        memcpy(&parent_table_entry->public_key, &starfishnet_config.parent_public_key, sizeof(parent_table_entry->public_key));
        SN_InfoPrintf("adding parent to node table...\n");
        ret = SN_Table_insert(parent_table_entry);
        if(ret == -SN_ERR_UNEXPECTED) {
            //it's ok if the entry already exists, since the earlier discovery should have added it
            ret = SN_OK;
        }
        free(parent_table_entry);
    }

    //start security association with our parent (implicitly requesting an address)
    if(ret == SN_OK) {
        SN_Endpoint_t parent_address = {
            .type = SN_ENDPOINT_SHORT_ADDRESS,
        };
        parent_address.short_address = starfishnet_config.parent_address;
        SN_InfoPrintf("sending association message...\n");
        ret = SN_Associate(&parent_address);
    }

    //And we're done
    SN_InfoPrintf("exit\n");
    return ret;
}
