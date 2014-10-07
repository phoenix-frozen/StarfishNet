#ifndef __MAC_UTIL_H__
#define __MAC_UTIL_H__

#include <sn_types.h>
#include <sn_logging.h>
#include "mac802154.h"

#include "mac_util.h"

#define MAC_CALL(call, x...) { int ret = call(x); if(ret <= 0) { SN_ErrPrintf(#call"("#x") = %d (failure)\n", ret); return -SN_ERR_RADIO; } else { SN_DebugPrintf(#call"("#x") = %d (success)\n", ret); } }

#define MAC_CONFIRM(primitive)     const uint8_t primitive##_confirm[] = {mac_mlme_##primitive##_confirm, mac_success}
#define MAC_SET_CONFIRM(primitive) const uint8_t primitive##_set_confirm[] = {mac_mlme_set_confirm, mac_success, primitive}

int mac_reset_radio(SN_Session_t* session, mac_primitive_t* packet);

#endif /* __MAC_UTIL_H__ */
