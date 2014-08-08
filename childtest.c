#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sn_core.h"
#include "sn_status.h"

static void network_discovered(SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata) {
    printf("Found network ID %x on channel %d.\n", network->pan_id, network->radio_channel);
    *((SN_Network_descriptor_t*)extradata) = *network;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("Usage: %s <radio device>\n", argv[0]);
        return -1;
    }

    int rv = 0;

    SN_Session_t network_session;

    printf("Initialising StarfishNet...\n");

    int ret = SN_Init(&network_session, argv[1]);

    if(ret != SN_OK) {
        printf("StarfishNet initialisation failed: %d\n", -ret);
        return -1;
    }

    printf("Init complete. Scanning for networks...\n");

    SN_Network_descriptor_t network = {};
    ret = SN_Discover(&network_session, ~0, 1000, &network_discovered, (void*)&network);

    if(ret != SN_OK) {
        printf("Network discovery failed: %d\n", -ret);
        goto main_exit;
    }

    if(network.radio_channel == 0) {
        printf("No networks found.\n");
        goto main_exit;
    }

    printf("Network discovery complete. Joining network ID %x on channel %d.\n", network.pan_id, network.radio_channel);

    ret = SN_Join(&network_session, &network, 0);

    if(ret != SN_OK) {
        printf("Network join failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Network joining complete. Type \"die\" to end.\n");

    char buf[BUFSIZ];

    for(;;) {
        fgets(buf, BUFSIZ, stdin);
        if(strncmp(buf, "die", 3) == 0)
            break;
    }

    printf("Instruction received. Dying.\n");

main_exit:
    SN_Destroy(&network_session);
    return rv;
}
