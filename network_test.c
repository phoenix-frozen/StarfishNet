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

	if(!memcmp(msdu, &datatemplate, sizeof(uint32_t))) {
		/* Call the MAC layer */
		GUARANTEED_CALL(MCPS_DATA_request,
			mac_session,
			DstAddrMode,
			DstPANId,
			DstAddr,
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


int main(int argc, char* argv[]) {
	const int channel = 0xb;
	const mac_pan_id_t my_panid = 0xcafe;
	const int rx_on_idle = 1;

	starfishnet_session_t network_session;

	assert(argc > 1);

	GUARANTEED_CALL(starfishnet_init, &network_session, argv[1]);

	GUARANTEED_CALL(NLME_FORMATION_request, &network_session, my_panid, channel);

	mac_primitive_handler_t mac_handlers = {
		.MCPS_DATA_indication = process_mcps_data_indication,
	};

	while(true) {
		GUARANTEED_CALL(mac_receive, &mac_handlers, network_session.mac_session);
	}

	return 0;
}
