#include <stdio.h>
#include <string.h>

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_status.h>
#include <inttypes.h>

#define RECEIVE_BUFFER_SIZE 256

static void network_discovered(SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata) {
    printf("Found network ID %x on channel %d.\n", network->pan_id, network->radio_channel);
    *((SN_Network_descriptor_t*)extradata) = *network;
    (void)session;
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
    ret = SN_Discover(&network_session, 0xFFFFFFFF, 1000, 0, &network_discovered, (void*)&network);

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
    SN_Address_t remote_address = {
        .type = mac_short_address,
        .address = { .ShortAddress = network.router_address },
    };
    SN_Send(&network_session, &remote_address, NULL); //finalise

    if(ret != SN_OK) {
        printf("Network join failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Network joining complete. Entering service loop.\n");

    uint8_t message_data[RECEIVE_BUFFER_SIZE];

    while(ret != -SN_ERR_RADIO) {
        SN_Message_t* message = (SN_Message_t*)message_data;

        printf("Receiving message...\n");
        ret = SN_Receive(&network_session, &remote_address, message, RECEIVE_BUFFER_SIZE);

        if(ret != SN_OK) {
            printf("Received invalid message, continuing...\n");
            continue;
        }

        if(message->type == SN_Association_request) {
            printf("Received association request. Transmitting association reply...\n");
            ret = SN_Associate(&network_session, &remote_address);

            if(ret != SN_OK) {
                printf("Associate reply transmission failed: %d\n", -ret);
            } else {
                printf("Associate reply transmission succeeded.\n");
            }
        } else if(message->type == SN_Dissociation_request) {
            printf("Received dissociation request.\n");
        }

        if(message->type == SN_Data_message && message->data_message.payload_length > 0) {
            printf("Received data message: \"%s\"\n", message->data_message.payload);
            printf("Transmitting acknowledgement...\n");
            ret = SN_Send(&network_session, &remote_address, NULL);

            if(ret != SN_OK) {
                printf("Acknowledgement transmission failed: %d\n", -ret);
            } else {
                printf("Acknowledgement transmission succeeded.\n");
            }
        }

        if(message->type == SN_Evidence_message) {
            printf("Received certificate.\n");

            printf("Transmitting acknowledgement...\n");
            ret = SN_Send(&network_session, &remote_address, NULL);

            if(ret != SN_OK) {
                printf("Acknowledgement transmission failed: %d\n", -ret);
            } else {
                printf("Acknowledgement transmission succeeded.\n");
            }
        }
    }

    printf("Dying due to radio error.\n");

    main_exit:
    SN_Destroy(&network_session);
    return ret;
}
