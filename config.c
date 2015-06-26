#include "net/mac/frame802154.h"

#include "config.h"

SN_Config_t starfishnet_config = {
    .tx_retry_limit = STARFISHNET_TX_RETRY_LIMIT,
    .tx_retry_timeout = STARFISHNET_TX_RETRY_TIMEOUT,

    .parent_address = SN_NO_SHORT_ADDRESS,
    .short_address = SN_NO_SHORT_ADDRESS,
    .pan_id = IEEE802154_PANID,
};
