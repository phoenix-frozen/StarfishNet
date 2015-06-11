#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "starfishnet.h"
#include "config.h"
#include "crypto.h"
#include "logging.h"

static void init(void) {
    SN_InfoPrintf("enter\n");
    queuebuf_init();
    packetbuf_clear();

    //TODO: set uECC's RNG

    /*TODO: (load configuration)
     * if (config in flash) then
     *      load config from flash
     * else
     *      generate new default config
     *      save to flash
     * fi
     */

    //for the moment, we just generate a new default config
    if(!starfishnet_config.device_root_key_valid) {
        SN_WarnPrintf("generating new device root key\n");
        SN_Crypto_generate_keypair(&starfishnet_config.device_root_key);
    }

    //TODO: other init stuff goes in here
    SN_InfoPrintf("exit\n");
}

static void input(void) {
    //TODO: called by NETSTACK_LLSEC when there's a packet for us in the packetbuf
}

const struct network_driver starfishnet_driver = {
  "StarfishNet",
  init,
  input
};
