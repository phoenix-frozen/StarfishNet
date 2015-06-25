#include <assert.h>
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
#include "node_table.h"
#include "packet.h"
#include "status.h"
#include "retransmission_queue.h"
#include "nonqueued_transmission.h"
#include "receive.h"

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
    radio_value_t radio_result;

    SN_InfoPrintf("enter\n");
    queuebuf_init();
    packetbuf_clear();

    uECC_set_rng(&generate_random_number);

    //populate configuration structure
    //designed so that we can store a root key in future...
    if(!starfishnet_config.device_root_key_valid) {
        SN_WarnPrintf("generating new device root key\n");
        SN_Crypto_generate_keypair(&starfishnet_config.device_root_key);
    }
    NETSTACK_RADIO.get_object(RADIO_PARAM_64BIT_ADDR, starfishnet_config.mib.macExtendedAddress, 8);
    if(NETSTACK_RADIO.get_value(RADIO_PARAM_PAN_ID, &radio_result) == RADIO_RESULT_OK) {
        starfishnet_config.mib.macPANId = (uint16_t)radio_result;
    }

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
    packet.length = (uint8_t)packetbuf_datalen(); //cast is safe because datalen <= 128
    packet.data = packetbuf_dataptr();
    SN_InfoPrintf("received %d-byte frame\n", PACKET_SIZE(packet, indication));

    switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
        case FRAME802154_BEACONFRAME:
            //TODO: call out to the beacon-parsing code
            break;

        case FRAME802154_DATAFRAME:
            SN_Receive_data_packet(&packet, packetbuf_addr(PACKETBUF_ADDR_SENDER), packetbuf_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE));
            break;

        case FRAME802154_CMDFRAME:
            //TODO: is there a command frame type that should cause us to TX a beacon?
        case FRAME802154_BEACONREQ:
            //TODO: TX a beacon and return
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
