#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "network.h"

#ifndef NDEBUG
#define GUARANTEED_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return 1; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define GUARANTEED_CALL(call, x...) { if(call(x) <= 0) { return 1; } }
#endif //NDEBUG

static const uint8_t tx_confirm[] = {mac_mcps_data_confirm, 0, mac_success};

static mac_address_t my_address = {
    .ExtendedAddress = {}
};

int process_mcps_data_indication (
	mac_callback_metadata_t* callback_metadata,
	mac_address_mode_t SrcAddrMode,
	mac_pan_id_t SrcPANId,
	mac_address_t *SrcAddr,
	mac_address_mode_t DstAddrMode,
	mac_pan_id_t DstPANId,
	mac_address_t *DstAddr,
	uint8_t msduLength,
	uint8_t *msdu,
	uint8_t mpduLinkQuality,
	_Bool SecurityUse,
	mac_acl_entry_t ACLEntry
) {
	printf("received packet with data: 0x");
	for(int i = 0; i < msduLength; i++)
		printf("%.02x", msdu[i]);
	printf("\n");

	static const uint32_t datatemplate = 0xdeadbeef;

	mac_session_handle_t mac_session = callback_metadata->session;

	if((SrcAddrMode == mac_extended_address ? memcmp(SrcAddr->ExtendedAddress, my_address.ExtendedAddress, 8) : !(SrcAddr->ShortAddress == 0)) && !memcmp(msdu, &datatemplate, sizeof(uint32_t))) {
		/* Call the MAC layer */
		GUARANTEED_CALL(MCPS_DATA_request,
			mac_session,
			mac_extended_address,
			DstPANId,
			&my_address,
			SrcAddrMode,
			SrcPANId,
			SrcAddr,
			msduLength,
			msdu,
			0,
			0
		);
		GUARANTEED_CALL(mac_receive_primitive, mac_session, tx_confirm, sizeof (tx_confirm));
	}

	return 1;
}


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

int main(int argc, char* argv[]) {
	assert(argc > 1);

	starfishnet_session_t network_session;
	GUARANTEED_CALL(starfishnet_init, &network_session, argv[1]);

    /* Setup an 802.15.4 PAN */
	starfishnet_network_descriptor_t network_descriptor = {
		.pan_id = 0xcafe,
		.radio_channel = 0xb,
		.routing_tree_depth = 0,
	};
	GUARANTEED_CALL(NLME_FORMATION_request, &network_session, &network_descriptor);

	/* Find our MAC address */
	GUARANTEED_CALL(MLME_GET_request, network_session.mac_session, macIEEEAddress);
	mac_primitive_handler_t handler = {
		.MLME_GET_confirm = process_mlme_get_confirm,
		.extradata = my_address.ExtendedAddress,
	};
	GUARANTEED_CALL(mac_receive, &handler, network_session.mac_session);

    char macaddress[64];
    mac_sprintf(macaddress, "%e", my_address.ExtendedAddress);
    printf("MAC address is: %s\n", macaddress);

	mac_primitive_handler_t mac_handlers = {
		.MCPS_DATA_indication = process_mcps_data_indication,
	};

	while(true) {
		GUARANTEED_CALL(mac_receive, &mac_handlers, network_session.mac_session);
	}

	return 0;
}
