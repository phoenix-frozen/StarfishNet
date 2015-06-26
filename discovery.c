#include <assert.h>
#include <net/packetbuf.h>
#include <net/linkaddr.h>

#include "sys/etimer.h"

#include "discovery.h"
#include "starfishnet.h"
#include "logging.h"
#include "status.h"
#include "types.h"
#include "constants.h"
#include "crypto.h"
#include "routing_tree.h"
#include "config.h"

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

void SN_Discovery_beacon_update(void) {
    uint16_t leaf_capacity;
    uint16_t router_capacity;

    //protocol ID information
    self_beacon_payload.beacon_data.protocol_id     = STARFISHNET_PROTOCOL_ID;
    self_beacon_payload.beacon_data.protocol_ver    = STARFISHNET_PROTOCOL_VERSION;
    //routing tree metadata
    self_beacon_payload.beacon_data.network_config.routing_tree_branching_factor = starfishnet_config.nib.tree_branching_factor;
    self_beacon_payload.beacon_data.network_config.routing_tree_position         = starfishnet_config.nib.tree_position;
    self_beacon_payload.beacon_data.network_config.leaf_blocks                   = starfishnet_config.nib.leaf_blocks;

    if(starfishnet_config.nib.enable_routing) {
        SN_Tree_determine_capacity(&leaf_capacity, &router_capacity);
    } else {
        leaf_capacity = router_capacity = 0;
    }
    self_beacon_payload.beacon_data.leaf_capacity   = (uint8_t)(leaf_capacity > 255 ? 255 : leaf_capacity);
    self_beacon_payload.beacon_data.router_capacity = (uint8_t)(router_capacity > 255 ? 255 : router_capacity);

    //public key
    memcpy(&self_beacon_payload.beacon_data.network_config.router_public_key, &starfishnet_config.device_root_key.public_key, sizeof(self_beacon_payload.beacon_data.network_config.router_public_key));

    //address
    self_beacon_payload.beacon_data.network_config.router_address = starfishnet_config.mib.macShortAddress;

    //hash
    SN_Crypto_hash((uint8_t*)&self_beacon_payload.beacon_data, sizeof(self_beacon_payload.beacon_data), &self_beacon_payload.hash, 0);
}

static struct {
    uint32_t channel_mask;
    clock_time_t timeout;
    uint8_t show_full_networks;

    SN_Discovery_callback_t callback;
    void* extradata;
} discovery_configuration;

static inline uint8_t ctz(uint32_t word) {
    uint8_t count = 0;

    for(;!(word & 1); word >>=1) {
        count++;
    }

    return count;
}

PROCESS(starfishnet_discovery_process, "StarfishNet discovery process");

static process_event_t discovery_event;

PROCESS_THREAD(starfishnet_discovery_process, ev, data)
{
    struct etimer timer = {
        .p = &starfishnet_discovery_process,
        .next = NULL,
    };

    PROCESS_BEGIN();
    discovery_event = process_alloc_event();

    while(1) {
        PROCESS_WAIT_EVENT();

        if(ev == discovery_event || ev == PROCESS_EVENT_TIMER) {
            /* if we have more channels to scan
             *  1. set the channel
             *  3. set a timer
             */
            if(discovery_configuration.channel_mask) {
                uint8_t current_channel = 0;
                current_channel = ctz(discovery_configuration.channel_mask);
                discovery_configuration.channel_mask &= ~(1 << current_channel)

                SN_InfoPrintf("beginning discovery on channel %d\n", current_channel);
                if(NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel) != RADIO_RESULT_OK) {
                    SN_ErrPrintf("radio returned error on channel set; aborting\n");
                    discovery_configuration.callback = NULL;
                } else {
                    //TODO: TX a beacon request frame
                    etimer_set(&timer, discovery_configuration.timeout);
                }
            } else {
                discovery_configuration.callback = NULL;
            }
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
int SN_Discover(SN_Discovery_callback_t callback, uint32_t channel_mask, clock_time_t timeout,
                bool show_full_networks, void *extradata) {
    SN_InfoPrintf("enter\n");
    SN_InfoPrintf("performing discovery over %#010"
                      PRIx32
                      ", in %d ms\n", channel_mask, timeout);

    if(callback == NULL) {
        SN_ErrPrintf("callback must be valid\n");
        return -SN_ERR_NULL;
    }

    channel_mask &= 0x07FFF800; //top 5 bits don't exist, bottom 11 bits aren't 2.4GHz

    SN_InfoPrintf("adjusted channel mask is %#010"
                      PRIx32
                      "\n", channel_mask);
    if(channel_mask == 0) {
        SN_WarnPrintf("no channels to scan, aborting...\n");
        return SN_OK;
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
    discovery_configuration.show_full_networks = show_full_networks ? 1 : 0;
    discovery_configuration.callback     = callback;
    discovery_configuration.extradata    = extradata;

    process_post(&starfishnet_discovery_process, discovery_event, NULL);

    return SN_OK;
}

void SN_Discovery_beacon_input(void) {
    static SN_Network_descriptor_t ndesc;
    static SN_Hash_t protohash;
    beacon_payload_t* beacon_payload;

    SN_InfoPrintf("enter\n");

    SN_InfoPrintf("found network. channel=0x%x, PANId=0x%#04x\n",
                  packetbuf_attr(PACKETBUF_ATTR_CHANNEL),
                  packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID));

    //check beacon payload is of the correct length and router is broadcasting with a short address
    if(packetbuf_datalen() != sizeof(beacon_payload_t)) {
        SN_InfoPrintf("packetbuf is the wrong size (%d, should be %d). aborting\n", packetbuf_datalen(),
                      sizeof(beacon_payload_t));
        return;
    }

    //set up some pointers, and then do a hash check
    beacon_payload = (beacon_payload_t*)packetbuf_dataptr();
    if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) != 2) {
        SN_InfoPrintf("Router is using its long address; a StarfishNet node should be using its short address.\n");
        return;
    }

    SN_InfoPrintf("    CoordAddress=%#06x\n", packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16);
    if(beacon_payload->beacon_data.network_config.router_address != packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16) {
        SN_WarnPrintf("    Address mismatch! Using %#06x\n", beacon_payload->beacon_data.address);
    }

    //check that this is a network of the kind we care about
    SN_InfoPrintf("    PID=%#04x, PVER=%#04x\n", beacon_payload->beacon_data.protocol_id, beacon_payload->beacon_data.protocol_ver);
    if(beacon_payload->beacon_data.protocol_id != STARFISHNET_PROTOCOL_ID ||
       beacon_payload->beacon_data.protocol_ver != STARFISHNET_PROTOCOL_VERSION) {
        SN_InfoPrintf("Beacon is for wrong kind of network.\n");
        return;
    }

    //XXX: this is the most disgusting way to print a key ever invented by man
    SN_InfoPrintf("    key=%#018"PRIx64"%016"PRIx64"%08"PRIx32"\n",
                  *(uint64_t*)beacon_payload->beacon_data.public_key.data,
                  *(((uint64_t*)beacon_payload->beacon_data.public_key.data) + 1),
                  *(((uint32_t*)beacon_payload->beacon_data.public_key.data) + 4));

    SN_Crypto_hash((uint8_t*)&beacon_payload->beacon_data, sizeof(beacon_payload->beacon_data), &protohash, 0);
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

    memcpy(&ndesc.network_config, &beacon_payload->beacon_data.network_config, sizeof(ndesc.network_config));
    ndesc.radio_channel = packetbuf_attr(PACKETBUF_ATTR_CHANNEL);
    ndesc.pan_id = packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID);

    if(discovery_configuration.callback) {
        discovery_configuration.callback(&ndesc, discovery_configuration.extradata);
    }

    SN_InfoPrintf("exit\n");
}
