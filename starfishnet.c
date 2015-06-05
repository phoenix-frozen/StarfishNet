#include "net/netstack.h"

static void init(void) {
}

const struct network_driver starfishnet_driver = {
  "StarfishNet",
  init
};
