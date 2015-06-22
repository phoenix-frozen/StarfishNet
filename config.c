#include "config.h"

SN_Config_t starfishnet_config = {
    .nib = {
        .tx_retry_limit = STARFISHNET_TX_RETRY_LIMIT,
        .tx_retry_timeout = STARFISHNET_TX_RETRY_TIMEOUT,

        .parent_address = SN_NO_SHORT_ADDRESS,
    },

    .mib = {
        .macShortAddress = SN_NO_SHORT_ADDRESS,
    },
};
