#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "mac.h"
#include "network.h"

//network starts here

#define STARFISHNET_PROTOCOL_ID 0x55
#define STARFISHNET_PROTOCOL_VERSION 0x0

#ifndef NDEBUG
#define GUARANTEED_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return 0; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define GUARANTEED_CALL(call, x...) { if(call(x) <= 0) { return 0; } }
#endif //NDEBUG

//some templates for mac_receive_primitive
static const uint8_t channel_set_confirm[] = {mac_mlme_set_confirm, mac_success, phyCurrentChannel};
static const uint8_t panid_set_confirm[] = {mac_mlme_set_confirm, mac_success, macPANId};
static const uint8_t shortaddr_set_confirm[] = {mac_mlme_set_confirm, mac_success, macShortAddress};
static const uint8_t reset_confirm[] = {mac_mlme_reset_confirm, mac_success};
static const uint8_t rxonidle_set_confirm[] = {mac_mlme_set_confirm, mac_success, macRxOnWhenIdle};
static const uint8_t start_confirm[] = {mac_mlme_start_confirm, mac_success};

typedef struct {
	//protocol ID information
	uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
	uint8_t protocol_ver; //Current StarfishNet version

	//device tree metadata
	uint8_t router_depth; //depth in the tree
	uint8_t router_capacity; //remaining child slots. negative if children can only be leaves

	//as for ZB, because PANId is way too small
	uint64_t extendedPANId[8];
} beacon_payload_t;

#define STRUCTCLEAR(x) memset(&(x), 0, sizeof(x))

int starfishnet_init(starfishnet_session_t* session, char* params) {
	assert(session != NULL);

	//allocate some stack space
	starfishnet_session_t protosession;
	STRUCTCLEAR(protosession);

	//init the mac layer
	protosession.mac_session = mac_init(params);
	assert(protosession.mac_session.meta != 0); //this covers the fd case as well
	if(protosession.mac_session.meta == 0) //this covers the fd case as well
		return 0;

	/* Reset the MAC */
	GUARANTEED_CALL(MLME_RESET_request, protosession.mac_session, 1);
	GUARANTEED_CALL(mac_receive_primitive, protosession.mac_session, reset_confirm, sizeof (reset_confirm));

	//return results
	*session = protosession;

	return 1;
}

//start a new StarfishNet network as coordinator
int NLME_FORMATION_request (starfishnet_session_t* session, uint16_t PANId, uint8_t LogicalChannel) {
	const int rx_on_idle = 1;
	const int short_address = 0;

	/* Turn on RxOnIdle */
	GUARANTEED_CALL(MLME_SET_request, session->mac_session, macRxOnWhenIdle, &rx_on_idle);
	GUARANTEED_CALL(mac_receive_primitive, session->mac_session, rxonidle_set_confirm, sizeof (rxonidle_set_confirm))

	/* Take short address 0x0000 */
	GUARANTEED_CALL(MLME_SET_request, session->mac_session, macShortAddress, &short_address);
	GUARANTEED_CALL(mac_receive_primitive, session->mac_session, shortaddr_set_confirm, sizeof (shortaddr_set_confirm))

	//TODO: set beacon payload here

	/* Call the MAC layer */
	GUARANTEED_CALL(MLME_START_request,
		session->mac_session,
		PANId,
		LogicalChannel,
		0 /* BeaconOrder */,
		0 /* SuperframeOrder */,
		1 /* PANCoordinator */,
		0 /* BatteryLifeExtension */,
		0 /* CoordRealignment */,
		0 /* SecurityEnable */
	);
	GUARANTEED_CALL(mac_receive_primitive, session->mac_session, start_confirm, sizeof (start_confirm))

	return 1;
}


#if 0
static int network_init_scan ( mac_session_handle_t mac_session, void* extradata, mac_status_t status,
			mac_scan_type_t ScanType, uint32_t UnscannedChannels,
			uint8_t ResultListSize, uint8_t *EnergyDetectList,
			mac_pan_descriptor_t *PANDescriptorList)
{
	assert(status == mac_success);
	assert(ScanType == mac_active_scan);

	if(status != mac_success)
		return -1;

	if(ResultListSize == 0)
		return 0;

	starfishnet_session_t* session = (starfishnet_session_t*)extradata;
	session->init_network_to_join = *PANDescriptorList;

	return 1;
}

int network_scan(starfishnet_session_t* session) {
	//initiate a scan for networks
	mac_primitive_handler_t handler = {
		.MLME_SCAN_confirm = &network_init_scan,
		.extradata = (void*)session
	};

	rv = MLME_SCAN_request(session.mac_session, mac_active_scan, 0xffffffff, 10); //all channels, some duration
	assert(rv == 0);
	rv = mac_receive(&handler, session.mac_session);

	switch(rv) {
		case 1:
			{
				//TODO: join the network we've indicated
			}

		case 0:
			{
				//TODO: start a PAN
			}

		default:
			{
				//TODO: an error occurred
			}
	}
}
#endif
