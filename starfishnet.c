#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "starfishnet.h"

static void init(void) {
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
    
    //TODO: other init stuff goes in here
}

static void input(void) {
    //TODO: called by NETSTACK_LLSEC when there's a packet for us in the packetbuf
}

const struct network_driver starfishnet_driver = {
  "StarfishNet",
  init,
  input
};
