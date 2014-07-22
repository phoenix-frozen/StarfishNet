#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mac.h"
//#include "network.h"

#ifndef NDEBUG
#define GUARANTEED_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return 1; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define GUARANTEED_CALL(call, x...) { if(call(x) <= 0) { return 1; } }
#endif //NDEBUG

static int process_mlme_get_confirm(
    mac_callback_metadata_t* callback_metadata,
    mac_status_t status,
    mac_pib_attribute_t PIBAttribute,
    uint8_t *PIBAttributeValue
) {
    if(status == mac_success && callback_metadata->extradata != NULL) {
        int length = mac_pib_attribute_length(PIBAttribute);

        assert(length > 0);

        memcpy(callback_metadata->extradata, PIBAttributeValue, length);

        return 1;
    }

    return 0;
}

int process_mlme_protocol_error_indication (
    mac_callback_metadata_t* callback_metadata,
    mac_status_t status
) {
    return 1;
}


int process_unknown_primitive (
    mac_callback_metadata_t* callback_metadata,
    uint8_t primitive,
    uint8_t *data,
    uint8_t length
) {
    return 1;
}

int main(int argc, char* argv[]) {
    const int channel = 0xb;
    const mac_pan_id_t my_panid = 0xcafe;

    static const uint8_t reset_confirm[] = {mac_mlme_reset_confirm, mac_success};
    static const uint8_t channel_set_confirm[] = {mac_mlme_set_confirm, mac_success, phyCurrentChannel};
    static const uint8_t panid_set_confirm[] = {mac_mlme_set_confirm, mac_success, macPANId};

    mac_session_handle_t mac_session;

    assert(argc == 2);

    /* Get a handle on the MAC */
    mac_session = mac_init(argv[1]);
    assert(mac_session.meta != 0);

    /* Reset the MAC */
    GUARANTEED_CALL(MLME_RESET_request, mac_session, 1);
    GUARANTEED_CALL(mac_receive_primitive, mac_session, reset_confirm, sizeof (reset_confirm));
    GUARANTEED_CALL(MLME_SET_request, mac_session, phyCurrentChannel, &channel);
    GUARANTEED_CALL(mac_receive_primitive, mac_session, channel_set_confirm, sizeof (channel_set_confirm));

    mac_address_t my_address;

    /* Set our PAN Id */
    GUARANTEED_CALL(MLME_SET_request, mac_session, macPANId, &my_panid);
    GUARANTEED_CALL(mac_receive_primitive, mac_session, panid_set_confirm, sizeof (panid_set_confirm));

    /* Find our MAC address */
    GUARANTEED_CALL(MLME_GET_request, mac_session, macIEEEAddress);
    mac_primitive_handler_t handler = {
        .MLME_GET_confirm = process_mlme_get_confirm,
        .MLME_PROTOCOL_ERROR_indication = process_mlme_protocol_error_indication,
        .unknown_primitive = process_unknown_primitive,
        .extradata = &(my_address.ExtendedAddress[0]),
    };
    GUARANTEED_CALL(mac_receive, &handler, mac_session);

    char macaddress[64];
    mac_sprintf(macaddress, "%e", my_address.ExtendedAddress);
    printf("MAC address is: %s\n", macaddress);

    mac_address_t broadcast_address = { .ShortAddress = 0xffff };

    unsigned char data[] = { 0xde, 0xad, 0xbe, 0xef };

    GUARANTEED_CALL(MCPS_DATA_request,
        mac_session,
        mac_extended_address,
        my_panid,
        &my_address,
        mac_short_address,
        0xffff,
        &broadcast_address,
        sizeof(data),
        data,
        0,
        0
    );

    handler.MLME_GET_confirm = NULL;
    handler.extradata = NULL;

    mac_receive(&handler, mac_session);
}
