#ifndef __SN_CORE_H__
#define __SN_CORE_H__

#include "types.h"

#include <stddef.h>
#include <stdbool.h>

int SN_Dissociate( //start a dissociation
    SN_Session_t *session,
    SN_Endpoint_t *dst_addr
);
int SN_Receive( //receive a packet containing a message. Note, StarfishNet may also do some internal housekeeping (including additional packet transmissions) in the context of this function
    SN_Session_t *session,
    SN_Endpoint_t *src_addr,
    SN_Message_t *buffer,
    size_t buffer_size
);

typedef void (SN_Discovery_callback_t) (SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata);
int SN_Discover( //scan for StarfishNet networks. also serves as a nearest-neighbor scan
    SN_Session_t *session,
    uint32_t channel_mask,
    uint32_t timeout,  //in ms
    bool show_full_networks, //0 gets you a callback only from networks with spare capacity
    SN_Discovery_callback_t *callback, //you get one callback for each network found
    void *extradata //will be passed to the callback
);

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
