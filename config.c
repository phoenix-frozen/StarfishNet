#include "config.h"

#include "net/mac/frame802154.h"

SN_Config_t starfishnet_config = {
    .tx_retry_limit = STARFISHNET_TX_RETRY_LIMIT,
    .tx_retry_timeout = STARFISHNET_TX_RETRY_TIMEOUT,

    .parent_address = FRAME802154_INVALIDADDR,
    .short_address = FRAME802154_INVALIDADDR,
    .pan_id = IEEE802154_PANID,
};
