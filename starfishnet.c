#include <string.h>

#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "lib/random.h"

#include "starfishnet.h"
#include "config.h"
#include "crypto.h"
#include "logging.h"
#include "uECC.h"
#include "packet.h"
#include "receive.h"
#include "discovery.h"

static int generate_random_number(uint8_t *dest, unsigned size) {
    uint16_t rand;

    for(; size > 1; size -= 2, dest += 2) {
        rand = random_rand();
        memcpy(dest, &rand, 2);
    }

    if(size > 0) {
        rand = random_rand();
        memcpy(dest, &rand, 1);
    }

    return 1;
}

static void init(void) {
    SN_InfoPrintf("enter\n");
    queuebuf_init();
    packetbuf_clear();
    process_start(&starfishnet_discovery_process, NULL);

    uECC_set_rng(&generate_random_number);

    //populate configuration structure
    //designed so that we can store a root key in future...
    if(!starfishnet_config.device_root_key_valid) {
        SN_WarnPrintf("generating new device root key\n");
        SN_Crypto_generate_keypair(&starfishnet_config.device_root_key);
    }
    NETSTACK_RADIO.get_object(RADIO_PARAM_64BIT_ADDR, starfishnet_config.mib.macExtendedAddress, 8);

    //set up the radio with an invalid short address
    NETSTACK_RADIO.set_value(RADIO_PARAM_16BIT_ADDR, SN_NO_SHORT_ADDRESS);

    //TODO: other init stuff goes in here
    SN_InfoPrintf("exit\n");
}

static void input(void) {
    static packet_t packet;

    SN_InfoPrintf("enter\n");

    //print some debugging information
    if(packetbuf_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received frame to %#018"PRIx64"\n", *(uint64_t*)(packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8));
    } else {
        SN_DebugPrintf("received frame to %#06x\n", packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u16);
    }
    if(packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE) == 8) {
        //XXX: this is the most disgusting way to print a MAC address ever invented by man
        SN_DebugPrintf("received frame from %#018"PRIx64"\n", *(uint64_t*)(packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8));
    } else {
        SN_DebugPrintf("received frame from %#06x\n", packetbuf_addr(PACKETBUF_ADDR_SENDER)->u16);
    }
    SN_InfoPrintf("received %d-byte frame\n", packetbuf_datalen());

    switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
        case FRAME802154_BEACONFRAME:
            SN_Discovery_beacon_input();
            break;

        case FRAME802154_DATAFRAME:
            //TODO: check link-layer destination address matches either ours or broadcast
            packet.length = (uint8_t)packetbuf_datalen(); //cast is safe because datalen <= 128
            packet.data = packetbuf_dataptr();
            SN_Receive_data_packet(&packet);
            break;

        case FRAME802154_CMDFRAME:
            //TODO: check that this is a command frame of type FRAME802154_BEACONREQ
            //TODO: if so, call out to beacons code to TX
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
