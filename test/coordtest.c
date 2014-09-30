#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_status.h>
#include <sn_table.h>
#include <inttypes.h>

int main(int argc, char* argv[]) {
    const int          channel = 0xb;
    const mac_pan_id_t panid   = 0xcafe;

    if(argc != 2) {
        printf("Usage: %s <radio device>\n", argv[0]);
        return -1;
    }

    int ret;

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

    printf("MAC address is %#018"PRIx64"\n", *(uint64_t*)network_session.mib.macIEEEAddress.ExtendedAddress);

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

    printf("Network start complete.\n");

    printf("Waiting for associate request...\n");

    SN_Address_t remote_address;
    SN_Message_t association_request;

    ret = SN_Receive(&network_session, &remote_address, &association_request, sizeof(association_request));

    if(ret != SN_OK) {
        printf("Receive failed with %d\n", -ret);
        goto main_exit;
    }

    if(association_request.type != SN_Association_request) {
        printf("Received message of type %d instead of association request...\n", association_request.type);
        goto main_exit;
    }

    printf("Transmitting associate reply...\n");

    ret = SN_Associate(&network_session, &remote_address, NULL);

    if(ret != SN_OK) {
        printf("Associate reply transmission failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Associate reply transmission succeeded.\n");

    SN_Table_entry_t table_entry = {
        .session = &network_session,
    };
    SN_Table_lookup_by_address(&remote_address, &table_entry, NULL);
    printf("Relationship is in state %d (should be at least %d)\n", table_entry.state, SN_Awaiting_finalise);
    if(table_entry.state < SN_Awaiting_finalise) {
        goto main_exit;
    }

    printf("Association transaction appears to have succeeded.\n");

    printf("Attempting to receive data message...\n");

    uint8_t recvbuf_size = aMaxPHYPacketSize;
    SN_Message_t* recvbuf = malloc(recvbuf_size);
    SN_Address_t srcaddr;

    ret = SN_Receive(&network_session, &srcaddr, recvbuf, recvbuf_size);

    if(ret != SN_OK) {
        printf("Packet receive failed: %d\n", -ret);
    } else {
        printf("Packet received: \"%s\"\n", recvbuf->data_message.payload);
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
