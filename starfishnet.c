#include "starfishnet.h"
#include "config.h"
#include "crypto.h"
#include "logging.h"
#include "receive.h"
#include "discovery.h"
#include "reliable_tx.h"

#include "net/packetbuf.h"
#include "net/queuebuf.h"

#include <string.h>
#include <dev/leds.h>

static void init() {
    SN_InfoPrintf("enter\n");
    queuebuf_init();
    packetbuf_clear();
    process_start(&starfishnet_discovery_process, NULL);
    process_start(&starfishnet_retransmission_process, NULL);

    leds_on(LEDS_RED);

    //populate configuration structure
    //designed so that we can store a root key in future...
    if(!starfishnet_config.device_root_key_valid) {
        SN_WarnPrintf("generating new device root key\n");
        SN_Crypto_generate_keypair(&starfishnet_config.device_root_key);
    }
    SN_InfoPrintf("root key is 0x%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"\n",
                  *(uint32_t*)starfishnet_config.device_root_key.public_key.data,
                  *(((uint32_t*)starfishnet_config.device_root_key.public_key.data) + 1),
                  *(((uint32_t*)starfishnet_config.device_root_key.public_key.data) + 2),
                  *(((uint32_t*)starfishnet_config.device_root_key.public_key.data) + 3),
                  *(((uint32_t*)starfishnet_config.device_root_key.public_key.data) + 4));

    NETSTACK_RADIO.set_value(RADIO_PARAM_16BIT_ADDR, (radio_value_t)FRAME802154_INVALIDADDR);
    NETSTACK_RADIO.set_value(RADIO_PARAM_PAN_ID, (radio_value_t)FRAME802154_BROADCASTPANDID);

    leds_off(LEDS_RED);
    leds_on(LEDS_GREEN);

    SN_InfoPrintf("exit\n");
}

static void input() {
    SN_InfoPrintf("enter\n");

    //print some debugging information
    if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received frame to 0x%08"PRIx32"%08"PRIx32"\n",
                      *(uint32_t*)packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8,
                      *(((uint32_t*)packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8) + 1));
    } else if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 2) {
        SN_DebugPrintf("received frame to 0x%04x\n", SHORT_ADDRESS(packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8));
    } else {
        SN_DebugPrintf("received with blank destination address\n");
    }
    if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received frame to 0x%08"PRIx32"%08"PRIx32"\n",
                       *(uint32_t*)packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8,
                       *(((uint32_t*)packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8) + 1));
    } else if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) == 2) {
        SN_DebugPrintf("received frame from 0x%04x\n", SHORT_ADDRESS(packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8));
    } else {
        SN_DebugPrintf("received with blank source address\n");
    }
    SN_InfoPrintf("received %d-byte frame\n", packetbuf_datalen());

    switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
        case FRAME802154_BEACONFRAME:
            SN_Beacon_input();
            break;

        case FRAME802154_DATAFRAME:
            if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 8) {
                if(memcmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8, linkaddr_node_addr.u8, 8) != 0) {
                    break;
                }
            } else if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 2) {
                const uint16_t dst_addr = SHORT_ADDRESS(packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8);
                if(dst_addr != starfishnet_config.short_address && dst_addr != FRAME802154_BROADCASTADDR) {
                    break;
                }
            }
            SN_Receive_data_packet();
            break;

        case FRAME802154_CMDFRAME:
            if(starfishnet_config.enable_routing && *(uint8_t*)packetbuf_dataptr() == FRAME802154_BEACONREQ && starfishnet_config.short_address != FRAME802154_INVALIDADDR) {
                SN_Beacon_TX();
            }
            break;

        default:
            //ignore all other frame types
            break;
    }

    SN_InfoPrintf("exit\n");
}

const struct network_driver starfishnet_driver = {
  "StarfishNet",
  init,
  input
};
