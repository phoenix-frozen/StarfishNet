#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sn_core.h"
#include "sn_status.h"

int main(int argc, char* argv[]) {
    const int          channel = 0xb;
    const mac_pan_id_t panid   = 0xcafe;

    if(argc != 2) {
        printf("Usage: %s <radio device>\n", argv[0]);
        return -1;
    }

    SN_Session_t network_session;

    printf("Initialising StarfishNet...\n");

    int ret = SN_Init(&network_session, argv[1]);

    if(ret != SN_OK) {
        printf("StarfishNet initialisation failed: %d\n", -ret);
        return -1;
    }

    printf("Init complete. Starting network on channel %d with ID %x...\n", channel, panid);

    SN_Network_descriptor_t network = {
        //coordinator_address            is ignored
        //nearest_neighbor_address       is ignored
        //nearest_neighbor_short_address is ignored
        .pan_id                         = panid,
        .radio_channel                  = channel,
        .routing_tree_depth             = 2,
        //routing_tree_position          is ignored
    };

    ret = SN_Start(&network_session, &network);

    if(ret != SN_OK) {
        printf("Network start failed: %d\n", -ret);
        SN_Destroy(&network_session);
        return -1;
    }

    printf("Network start complete. Type \"die\" to end.\n");

    char buf[BUFSIZ];

    for(;;) {
        fgets(buf, BUFSIZ, stdin);
        if(strncmp(buf, "die", 3) == 0)
            break;
    }

    printf("Instruction received. Dying.\n");

    SN_Destroy(&network_session);
    return 0;
}
