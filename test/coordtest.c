#include <stdio.h>
#include <stdlib.h>

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_status.h>
#include <inttypes.h>

#define RECEIVE_BUFFER_SIZE 256

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
        //router_address       is ignored
        .pan_id                         = panid,
        .radio_channel                  = channel,
        .routing_tree_branching_factor  = 3,
        //routing_tree_position          is ignored
        .leaf_blocks                    = 0,
    };

    ret = SN_Start(&network_session, &network);

    if(ret != SN_OK) {
        printf("Network start failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Network start complete. Entering service loop.\n");

    SN_Address_t remote_address;
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

        if(message->type == SN_Explicit_Evidence_message) {
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
