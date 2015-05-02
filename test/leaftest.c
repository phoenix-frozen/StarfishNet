#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_status.h>
#include <sn_table.h>
#include <inttypes.h>

static void network_discovered(SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata) {
    printf("Found network ID %#06x on channel %d.\n", network->pan_id, network->radio_channel);
    *((SN_Network_descriptor_t*)extradata) = *network;
    (void)session; //shut up CLion
}

int main(int argc, char* argv[]) {
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

    printf("Scanning for networks...\n");

    SN_Network_descriptor_t network = {};
    ret = SN_Discover(&network_session, 0xFFFFFFFF, 5000, 0, &network_discovered, (void*)&network);

    if(ret != SN_OK) {
        printf("Network discovery failed: %d\n", -ret);
        goto main_exit;
    }

    if(network.radio_channel == 0) {
        printf("No networks found.\n");
        goto main_exit;
    }

    printf("Network discovery complete. Joining network ID %#04x on channel %d.\n", network.pan_id, network.radio_channel);

    ret = SN_Join(&network_session, &network, 1);

    if(ret != SN_OK) {
        printf("Network join failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Network joining complete. Waiting before packet transmission.\n");

    sleep(2);

    SN_Address_t address = {
        .type = mac_short_address,
        .address.ShortAddress = network.router_address,
    };

    SN_Table_entry_t table_entry = {
        .session = &network_session,
    };
    SN_Table_lookup_by_address(&address, &table_entry);
    printf("Relationship is in state %d (should be at least %d)\n", table_entry.state, SN_Send_finalise);
    if(table_entry.state < SN_Send_finalise) {
        goto main_exit;
    }

    printf("Attempting data message transmission.\n");

    SN_Message_t* test_message = malloc(sizeof(SN_Message_t) + 5);
    test_message->type = SN_Data_message;
    test_message->data_message.payload_length = 5;
    memcpy(test_message->data_message.payload, "test", 5);

    ret = SN_Send(&network_session, &address, test_message);

    if(ret != SN_OK) {
        printf("Packet transmission failed: %d\n", -ret);
        goto main_exit;
    } else {
        printf("Packet transmission succeeded.\n");
    }

    printf("Attempting to receive acknowledgement...\n");

    do {
        ret = SN_Receive(&network_session, &address, test_message, sizeof(SN_Message_t) + 5);
    } while (ret != SN_OK && ret != -SN_ERR_RADIO);

    if(ret != SN_OK) {
        printf("Acknowledgement receive failed: %d\n", -ret);
    } else {
        printf("Acknowledgement receive succeeded.\n");
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
