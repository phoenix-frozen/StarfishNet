#ifndef __SN_CORE_H__
#define __SN_CORE_H__

#include "types.h"

#include <stddef.h>
#include <stdbool.h>

int SN_Start( //start a new StarfishNet network as coordinator
    SN_Session_t *session,
    SN_Network_descriptor_t *network
);

int SN_Join( //tune the radio to a StarfishNet network and listen for packets with its PAN ID
    SN_Session_t *session,
    SN_Network_descriptor_t *network,
    bool disable_routing //1 to disable forwarding packets. also disallows us from having children.
);

#endif /* __SN_CORE_H__ */
