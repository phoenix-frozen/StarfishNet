#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sn_core.h>
#include <sn_crypto.h>
#include <sn_status.h>
#include <sn_table.h>

static void network_discovered(SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata) {
    printf("Found network ID %x on channel %d.\n", network->pan_id, network->radio_channel);
    *((SN_Network_descriptor_t*)extradata) = *network;
}

int main(int argc, char* argv[]) {
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

    printf("Scanning for networks...\n");

    SN_Network_descriptor_t network = {};
    ret = SN_Discover(&network_session, ~0, 10000, &network_discovered, (void*)&network);

    if(ret != SN_OK) {
        printf("Network discovery failed: %d\n", -ret);
        goto main_exit;
    }

    if(network.radio_channel == 0) {
        printf("No networks found.\n");
        goto main_exit;
    }

    printf("Network discovery complete. Joining network ID %x on channel %d.\n", network.pan_id, network.radio_channel);

    ret = SN_Join(&network_session, &network, 1);

    if(ret != SN_OK) {
        printf("Network join failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Network joining complete. Waiting before packet transmission.\n");

    sleep(2);

    printf("Attempting association.\n");

    uint8_t association_message_count = 3;
    SN_Message_t* association_message = malloc(aMaxPHYPacketSize); //allocate enough memory to hold the response
    uint8_t* dodgy_hack = (uint8_t*)association_message;
    dodgy_hack[0] = SN_Associate_request;
    dodgy_hack[1] = SN_Node_details;
    dodgy_hack[2] = SN_Authentication_message;

    SN_Address_t address = {
        .type = mac_extended_address,
        .address = network.nearest_neighbor_long_address,
    };

    ret = SN_Transmit(&network_session, &address, &association_message_count, association_message);

    if(ret != SN_OK) {
        printf("Associate transmission failed: %d\n", -ret);
        goto main_exit;
    }

    printf("Associate transmission succeeded. Waiting for reply...\n");

    SN_Address_t remote_address;
    association_message_count = aMaxPHYPacketSize;

    ret = SN_Receive(&network_session, &remote_address, &association_message_count, association_message);

    if(ret != SN_OK) {
        printf("Failed to receive reply: %d\n", -ret);
        goto main_exit;
    }

    printf("Received reply contaning %d messages\n", association_message_count);

    if(association_message->type != SN_Associate_reply) {
        printf("Received message of type %d instead of association reply...\n", association_message->type);
        goto main_exit;
    }

    if(memcmp(&remote_address, &address, sizeof(address))) {
        printf("Received message from %#018lx instead of %#018lx\n", *(uint64_t*)remote_address.address.ExtendedAddress, *(uint64_t*)address.address.ExtendedAddress);
    }

    SN_Table_entry_t table_entry = {
        .session = &network_session,
    };
    SN_Table_lookup_by_address(&address, &table_entry, NULL);
    printf("%suthenticated Relationship is in state %d (should be at least %d)\n", table_entry.authenticated ? "A" : "Una", table_entry.state, SN_Send_finalise);
    if(table_entry.state < SN_Send_finalise) {
        goto main_exit;
    }

    printf("Attempting data message transmission.\n");

    uint8_t test_message_count = 1;
    SN_Message_t* test_message = malloc(sizeof(struct SN_Data_message) + 5);
    test_message->type = SN_Data_message;
    test_message->data.payload_length = 5;
    memcpy(test_message->data.payload, "test", 5);

    ret = SN_Transmit(&network_session, &address, &test_message_count, test_message);

    if(ret != SN_OK) {
        printf("Packet transmission failed: %d\n", -ret);
    } else {
        printf("Packet transmission succeeded.\n");
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
