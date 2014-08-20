#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sn_core.h"
#include "sn_status.h"

int main(int argc, char* argv[]) {
    const int          channel = 0xb;
    const mac_pan_id_t panid   = 0xcafe;

    if(argc != 2) {
        printf("Usage: %s <radio device>\n", argv[0]);
        return -1;
    }

    int ret = SN_OK;

    printf("Generating master keypair...\n");

    SN_Keypair_t master_keypair;
    ret = SN_Crypto_generate_keypair(&master_keypair);

    if(ret != SN_OK) {
        printf("Key generation failed: %d\n", -ret);
        return -1;
    }

    printf("Initialising StarfishNet...\n");

    SN_Session_t network_session;
    ret = SN_Init(&network_session, &master_keypair, argv[1]);

    if(ret != SN_OK) {
        printf("StarfishNet initialisation failed: %d\n", -ret);
        return -1;
    }

    printf("Init complete. Printing MAC address:\n");

    printf("MAC address is %#018lx\n", *(uint64_t*)network_session.mib.macIEEEAddress.ExtendedAddress);

    printf("Starting network on channel %d with ID %x...\n", channel, panid);

    SN_Network_descriptor_t network = {
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
        goto main_exit;
    }

    printf("Network start complete. Attempting to receive packet.\n");

    uint8_t recvbuf_size = sizeof(struct SN_Data_message) + 5;
    SN_Message_t* recvbuf = malloc(recvbuf_size);
    SN_Address_t srcaddr;

    ret = SN_Receive(&network_session, &srcaddr, &recvbuf_size, recvbuf);

    if(ret != SN_OK) {
        printf("Packet receive failed: %d\n", -ret);
    } else {
        printf("Packet received: \"%s\"\n", recvbuf->data.payload);
    }

    printf("Test complete. Type \"die\" to clean up and exit.\n");

    char buf[BUFSIZ];

    for(;;) {
        fgets(buf, BUFSIZ, stdin);
        if(strncmp(buf, "die", 3) == 0)
            break;
    }

    printf("Instruction received. Dying.\n");

main_exit:
    SN_Destroy(&network_session);
    return ret;
}
