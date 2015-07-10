#include "starfishnet.h"
#include "discovery.h"
#include "logging.h"
#include "status.h"
#include "constants.h"
#include "crypto.h"
#include "routing_tree.h"
#include "config.h"
#include "types.h"
#include "node_table.h"

#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "sys/etimer.h"

#include <string.h>

#define IEEE802514_BEACON_OVERHEAD 4

#ifndef SN_NEIGHBOR_DISCOVERY_TIMEOUT
#define SN_NEIGHBOR_DISCOVERY_TIMEOUT 1000
#endif //SN_NEIGHBOR_DISCOVERY_TIMEOUT

typedef struct beacon_payload {
    struct {
        //protocol ID information
        uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
        uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

        SN_Network_config_t network_config;

        //capacity information
        uint8_t router_capacity; //remaining router address blocks
        uint8_t leaf_capacity;   //remaining leaf addresses
    } beacon_data;

    SN_Hash_t hash;
} beacon_payload_t;

static beacon_payload_t self_beacon_payload;

void SN_Beacon_update() {
    uint16_t leaf_capacity;
    uint16_t router_capacity;

    //protocol ID information
    self_beacon_payload.beacon_data.protocol_id     = STARFISHNET_PROTOCOL_ID;
    self_beacon_payload.beacon_data.protocol_ver    = STARFISHNET_PROTOCOL_VERSION;
    //routing tree metadata
    self_beacon_payload.beacon_data.network_config.routing_tree_branching_factor = starfishnet_config.tree_branching_factor;
    self_beacon_payload.beacon_data.network_config.routing_tree_position         = starfishnet_config.tree_position;
    self_beacon_payload.beacon_data.network_config.leaf_blocks                   = starfishnet_config.leaf_blocks;

    if(starfishnet_config.enable_routing) {
        SN_Tree_determine_capacity(&leaf_capacity, &router_capacity);
    } else {
        leaf_capacity = router_capacity = 0;
    }
    self_beacon_payload.beacon_data.leaf_capacity   = (uint8_t)(leaf_capacity > 255 ? 255 : leaf_capacity);
    self_beacon_payload.beacon_data.router_capacity = (uint8_t)(router_capacity > 255 ? 255 : router_capacity);

    //public key
    memcpy(&self_beacon_payload.beacon_data.network_config.router_public_key, &starfishnet_config.device_root_key.public_key, sizeof(self_beacon_payload.beacon_data.network_config.router_public_key));

    //address
    self_beacon_payload.beacon_data.network_config.router_address = starfishnet_config.short_address;

    //hash
    SN_Crypto_hash((uint8_t *) &self_beacon_payload.beacon_data, sizeof(self_beacon_payload.beacon_data),
                   &self_beacon_payload.hash);
}

//default behaviour for discovery subsystem: record a node as a neighbor
static void neighbor_discovered(SN_Network_descriptor_t *network, void *extradata) {
    static SN_Table_entry_t router_table_entry;

    (void) extradata; //shut up GCC

    if (network == NULL || network->network_config == NULL)
        return;

    SN_InfoPrintf("enter\n");

    //set up our temporary data structure with the appropriate info
    memset(&router_table_entry, 0, sizeof(router_table_entry));
    router_table_entry.details_known = 1;
    router_table_entry.short_address = network->network_config->router_address;
    memcpy(&router_table_entry.public_key, &network->network_config->router_public_key, sizeof(router_table_entry.public_key));

    if(SN_Table_lookup(NULL, &router_table_entry) == SN_OK) {
        router_table_entry.details_known = 1;
        router_table_entry.short_address = network->network_config->router_address;
        memcpy(&router_table_entry.public_key, &network->network_config->router_public_key, sizeof(router_table_entry.public_key));
    }

    router_table_entry.neighbor = 1;

    SN_Table_update(&router_table_entry);
    SN_Table_insert(&router_table_entry);

    SN_InfoPrintf("exit\n");
}

static struct {
    uint32_t channel_mask;
    clock_time_t timeout;
    uint8_t show_full_networks;

    SN_Discovery_callback_t* callback;
    void* extradata;
} discovery_configuration = {
    .channel_mask = 0,
    .timeout = 0,
    .show_full_networks = 1,

    .callback = neighbor_discovered,
    .extradata = NULL,
};

static inline uint8_t ctz(uint32_t word) {
    uint8_t count = 0;

    for(;!(word & 1); word >>=1) {
        count++;
    }

    return count;
}

PROCESS(starfishnet_discovery_process, "StarfishNet discovery process");

static process_event_t discovery_event;

static void beacon_request_tx() {
    packetbuf_clear();

    packetbuf_set_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE, 0);
    packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_null); //signal to the framer that we're sending a broadcast
    packetbuf_set_attr(PACKETBUF_ATTR_NETWORK_ID, FRAME802154_BROADCASTPANDID);
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_CMDFRAME);

    *(uint8_t*)packetbuf_dataptr() = FRAME802154_BEACONREQ;
    packetbuf_set_datalen(1);

    NETSTACK_LLSEC.send(NULL, NULL);
}

static void end_discovery() {
    NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, RADIO_RX_MODE_ADDRESS_FILTER);
    discovery_configuration.channel_mask = 0;
    discovery_configuration.timeout = 0;
    if(discovery_configuration.callback != NULL) {
        discovery_configuration.callback(NULL, discovery_configuration.extradata);
    }
    discovery_configuration.callback = neighbor_discovered;
    discovery_configuration.extradata = NULL;
    discovery_configuration.show_full_networks = 1;
}

PROCESS_THREAD(starfishnet_discovery_process, ev, data)
{
    static struct etimer timer = {
        .p = &starfishnet_discovery_process,
        .next = NULL,
    };

    PROCESS_BEGIN();
    discovery_event = process_alloc_event();

    (void)data; //shut up GCC

    while(1) {
        SN_InfoPrintf("waiting...\n");
        PROCESS_WAIT_EVENT_UNTIL(ev == discovery_event || ev == PROCESS_EVENT_TIMER);
        SN_InfoPrintf("event received\n");

        if(discovery_configuration.channel_mask) {
            /* if we have more channels to scan
             *  1. set the radio to unfiltered mode
             *  2. set the channel
             *  3. set a timer
             */
            uint8_t current_channel = 0;
            current_channel = ctz(discovery_configuration.channel_mask);
            discovery_configuration.channel_mask &= ~(1 << current_channel);

            SN_InfoPrintf("beginning discovery on channel %d\n", current_channel);
            if(NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, 0) != RADIO_RESULT_OK) {
                SN_ErrPrintf("radio returned error on RX mode set; aborting\n");
                end_discovery();
            } else
            if(NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel) != RADIO_RESULT_OK) {
                SN_ErrPrintf("radio returned error on channel set; aborting\n");
                end_discovery();
            } else {
                beacon_request_tx();
                etimer_set(&timer, discovery_configuration.timeout * CLOCK_CONF_SECOND / 1000); //8 ms per clock tick
            }
        } else {
            /* if we don't have more channels to scan
             *  1. set the radio to filtered mode
             *  2. clear the config structure
             */
            SN_InfoPrintf("ending discovery\n");
            end_discovery();
        }
    }

    PROCESS_END();
}

static inline uint8_t popcount(uint32_t word) {
    uint8_t count = 0;

    for(; word; word >>= 1) {
        if(word & 1)
            count++;
    }

    return count;
}

/* scan for StarfishNet networks
 *
 * You get one callback for each network discovered, with the extradata you provided.
 */
int SN_Discover(SN_Discovery_callback_t* callback, uint32_t channel_mask, clock_time_t timeout,
                bool show_full_networks, void *extradata) {
    SN_InfoPrintf("enter\n");
    SN_InfoPrintf("performing discovery over 0x%08"PRIx32", in %d ms\n", channel_mask, timeout);

    if(callback == NULL) {
        SN_ErrPrintf("callback must be valid\n");
        return -SN_ERR_NULL;
    }

    channel_mask &= 0x07FFF800; //top 5 bits don't exist, bottom 11 bits aren't 2.4GHz

    SN_InfoPrintf("adjusted channel mask is 0x%08"PRIx32"\n", channel_mask);
    if(channel_mask == 0) {
        SN_ErrPrintf("no channels to scan, aborting...\n");
        return -SN_ERR_INVALID;
    }

    if(discovery_configuration.channel_mask != 0) {
        SN_ErrPrintf("error, scan already in progress\n");
        return -SN_ERR_UNEXPECTED;
    }

    discovery_configuration.timeout = timeout / popcount(channel_mask);
    if(discovery_configuration.timeout == 0) {
        SN_ErrPrintf("timeout is too short. must be at least 1ms/channel\n");
        return -SN_ERR_INVALID;
    }

    discovery_configuration.channel_mask = channel_mask;
    discovery_configuration.show_full_networks = (uint8_t)show_full_networks;
    discovery_configuration.callback     = callback;
    discovery_configuration.extradata    = extradata;

    process_post(&starfishnet_discovery_process, discovery_event, NULL);

    return SN_OK;
}

/* trigger a neighbor discovery on our network
 */
int8_t SN_Discover_neighbors() {
    SN_InfoPrintf("enter\n");

    if(discovery_configuration.channel_mask != 0) {
        SN_ErrPrintf("error, scan already in progress\n");
        return -SN_ERR_UNEXPECTED;
    }

    beacon_request_tx();

    return SN_OK;
}

void SN_Beacon_input() {
    static SN_Network_descriptor_t ndesc;
    static SN_Hash_t protohash;
    beacon_payload_t* beacon_payload;

    SN_InfoPrintf("enter\n");

    SN_InfoPrintf("found network. channel=0x%x, PANId=0x%04x\n",
                  packetbuf_attr(PACKETBUF_ATTR_CHANNEL),
                  packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID));

    //check beacon payload is of the correct length and router is broadcasting with a short address
    if(packetbuf_datalen() != sizeof(beacon_payload_t) + IEEE802514_BEACON_OVERHEAD) {
        SN_InfoPrintf("packetbuf is the wrong size (%d, should be %d). aborting\n", packetbuf_datalen(),
                      sizeof(beacon_payload_t) + IEEE802514_BEACON_OVERHEAD);
        return;
    }

    //set up some pointers, and then do a hash check
    beacon_payload = (beacon_payload_t*)((uint8_t*)packetbuf_dataptr() + IEEE802514_BEACON_OVERHEAD);
    if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) != 2) {
        SN_InfoPrintf("Router is using its long address (addr_size = %d); a StarfishNet node should be using its short address.\n", packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE));
        return;
    }

    SN_InfoPrintf("    CoordAddress=0x%04x\n", packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16);
    if(beacon_payload->beacon_data.network_config.router_address != packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16) {
        SN_WarnPrintf("    Address mismatch! Using 0x%04x\n", beacon_payload->beacon_data.network_config.router_address);
    }

    //check that this is a network of the kind we care about
    SN_InfoPrintf("    PID=0x%02x, PVER=0x%02x\n", beacon_payload->beacon_data.protocol_id, beacon_payload->beacon_data.protocol_ver);
    if(beacon_payload->beacon_data.protocol_id != STARFISHNET_PROTOCOL_ID ||
       beacon_payload->beacon_data.protocol_ver != STARFISHNET_PROTOCOL_VERSION) {
        SN_InfoPrintf("Beacon is for wrong kind of network.\n");
        return;
    }

    SN_Crypto_hash((uint8_t *) &beacon_payload->beacon_data, sizeof(beacon_payload->beacon_data), &protohash);
    if(memcmp(beacon_payload->hash.data, protohash.data, SN_Hash_size) != 0) {
        SN_WarnPrintf("Beacon hash check failed.\n");
        return;
    }

    if(beacon_payload->beacon_data.router_capacity == 0 && beacon_payload->beacon_data.leaf_capacity == 0) {
        SN_WarnPrintf("Router is full.\n");

        if(!discovery_configuration.show_full_networks) {
            return;
        }
    }

    if(SN_Tree_check_join(beacon_payload->beacon_data.network_config.routing_tree_position + (uint8_t)1, beacon_payload->beacon_data.network_config.routing_tree_branching_factor) < 0) {
        SN_WarnPrintf("Router has invalid tree configuration\n");
        return;
    }

    ndesc.network_config = &beacon_payload->beacon_data.network_config;
    ndesc.radio_channel = packetbuf_attr(PACKETBUF_ATTR_CHANNEL);
    ndesc.pan_id = packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID);

    if(discovery_configuration.callback) {
        discovery_configuration.callback(&ndesc, discovery_configuration.extradata);
    }

    SN_InfoPrintf("exit\n");
}

void SN_Beacon_TX() {
    linkaddr_t src_address;
    uint8_t* packetbuf_ptr;

    SN_InfoPrintf("enter\n");

    packetbuf_clear();

    packetbuf_set_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE, 2);
    packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 0);

    src_address.u16 = starfishnet_config.short_address;
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &src_address);

    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);
    packetbuf_set_attr(PACKETBUF_ATTR_NETWORK_ID, starfishnet_config.pan_id);

    /* 802.15.4 beacon frame format
     *
     * ----------------------------------------
     * |     2      |  1+ |    1+   | Payload |
     * | Superframe | GTS | Pending | Payload |
     * ----------------------------------------
     */

    packetbuf_ptr = packetbuf_dataptr();

    memset(packetbuf_ptr, 0, IEEE802514_BEACON_OVERHEAD); //no superframe, GTS, or pending frames

    memcpy(packetbuf_ptr + IEEE802514_BEACON_OVERHEAD, &self_beacon_payload, sizeof(self_beacon_payload));

    packetbuf_set_datalen(sizeof(self_beacon_payload) + IEEE802514_BEACON_OVERHEAD);

    NETSTACK_LLSEC.send(NULL, NULL);

    SN_InfoPrintf("exit\n");
}
