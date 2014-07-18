#include <assert.h>
#include <string.h>

#include "mac.h"
#include "network.h"

//network starts here

#define STARFISHNET_PROTOCOL_ID 0x55
#define STARFISHNET_PROTOCOL_VERSION 0x0

#ifndef NDEBUG
#include <stdio.h>
#define GUARANTEED_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return 0; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define GUARANTEED_CALL(call, x...) { if(call(x) <= 0) { return 0; } }
#endif //NDEBUG

//some templates for mac_receive_primitive
#define MAC_CONFIRM(primitive)     static const uint8_t primitive##_confirm[] = {mac_mlme_##primitive##_confirm, mac_success}
#define MAC_SET_CONFIRM(primitive) static const uint8_t primitive##_set_confirm[] = {mac_mlme_set_confirm, mac_success, primitive}
MAC_CONFIRM(reset);
MAC_CONFIRM(start);
MAC_SET_CONFIRM(macAssociationPermit);
MAC_SET_CONFIRM(macBeaconPayload);
MAC_SET_CONFIRM(macBeaconPayloadLength);
MAC_SET_CONFIRM(macPANId);
MAC_SET_CONFIRM(macRxOnWhenIdle);
MAC_SET_CONFIRM(macShortAddress);
MAC_SET_CONFIRM(phyCurrentChannel);
MAC_SET_CONFIRM(macCoordShortAddress);

#define GUARANTEED_MAC_SET(session, parameter, value) { \
	GUARANTEED_CALL(MLME_SET_request, session, parameter, &(value)); \
	GUARANTEED_CALL(mac_receive_primitive, session, parameter##_set_confirm, sizeof (parameter##_set_confirm)); \
}

#define GUARANTEED_MAC_GET(session, handler, parameter, value) {\
	GUARANTEED_CALL(MLME_GET_request, session, parameter); \
	handler.extradata = (void*)&(value); \
	GUARANTEED_CALL(mac_receive, &handler, session); \
}

//just a basic linked list for the moment. do something smart later.
struct starfishnet_sa_container {
	starfishnet_sa_container_t* next;
	starfishnet_sa_t entry;
};

typedef struct beacon_payload {
	//protocol ID information
	uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
	uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

	//device tree metadata
	uint8_t tree_depth; //maximum tree depth
	uint8_t router_depth; //depth in the tree of this router
	int8_t router_capacity; //remaining child slots. negative if children can only be leaves

	//TODO: public key and digital signature?
} beacon_payload_t;

typedef struct starfishnet_msdu {
	//protocol ID information
	uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
	uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

	uint8_t packet_type;

	uint8_t data[]; //data length is implied from the length of the MSDU
} starfishnet_msdu_t;

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

	//set up my basic linkedlist SA tracker
	protosession.sas = NULL;

	//return results
	*session = protosession;

	return 1;
}

//start a new StarfishNet network as coordinator
int NLME_FORMATION_request (starfishnet_session_t* session, starfishnet_network_descriptor_t* network) {
	assert(session != NULL);
	assert(network != NULL);

	/* Turn on RxOnIdle (because we like receiving packets) */
	const int rx_on_idle = 1;
	GUARANTEED_MAC_SET(session->mac_session, macRxOnWhenIdle, rx_on_idle);

	/* Take short address 0x0000 */
	const int short_address = 0;
	GUARANTEED_MAC_SET(session->mac_session, macShortAddress, short_address);

	/* Set beacon payload to contain network metadata */
	beacon_payload_t beacon_payload = {
		.protocol_id = STARFISHNET_PROTOCOL_ID,
		.protocol_ver = STARFISHNET_PROTOCOL_VERSION,

		.tree_depth = network->routing_tree_depth,
		.router_depth = 0, //depth in the tree
		.router_capacity = 0, //remaining child slots. negative if children can only be leaves
			//TODO: FIXME

		//TODO: keys
		//TODO: digitally sign this?
	};
	const int beacon_payload_length = sizeof(beacon_payload_t);
	GUARANTEED_MAC_SET(session->mac_session, macBeaconPayloadLength, beacon_payload_length);
	GUARANTEED_MAC_SET(session->mac_session, macBeaconPayload, beacon_payload);

	/* Call the MAC layer */
	GUARANTEED_CALL(MLME_START_request,
		session->mac_session,
		network->pan_id,
		network->radio_channel,
		0 /* BeaconOrder */,
		0 /* SuperframeOrder */,
		1 /* PANCoordinator */,
		0 /* BatteryLifeExtension */,
		0 /* CoordRealignment */,
		0 /* SecurityEnable */
	);
	GUARANTEED_CALL(mac_receive_primitive, session->mac_session, start_confirm, sizeof (start_confirm));

	//can't remember if MLME_START switched on macAssociationPermit; kill it to be sure
	const int mac_assoc_permit = 0;
	GUARANTEED_MAC_SET(session->mac_session, macAssociationPermit, mac_assoc_permit);

	/* Fill NIB */
	session->nib.tree_depth       = network->routing_tree_depth;
	session->nib.tx_retry_limit   = NETWORK_DEFAULT_TX_RETRY_LIMIT;
	session->nib.tx_retry_timeout = NETWORK_DEFAULT_TX_RETRY_TIMEOUT;
	memset(&session->nib.coordinator_address, 0, sizeof(session->nib.coordinator_address));

	//TODO: crypto stuff
	//TODO: setup metadata structures for address delegations

	return 1;
}
/* Tune the radio to a StarfishNet network and listen for packets with its PAN ID.
 * Note, this call does not directly cause any packet exchange.  However, it will
 * result in route discoveries starting to succeed.
 * Remember that naive broadcasts won't be receivable until we do a SA with a neighbor router.
 */
int NLME_JOIN_request (starfishnet_session_t* session, starfishnet_network_descriptor_t* network) {
	assert(session != NULL);
	assert(network != NULL);

	GUARANTEED_MAC_SET(session->mac_session, macPANId, network->pan_id);
	GUARANTEED_MAC_SET(session->mac_session, phyCurrentChannel, network->radio_channel);
	static const uint16_t coord_address = 0;
	GUARANTEED_MAC_SET(session->mac_session, macCoordShortAddress, coord_address);

	/* Fill NIB */
	session->nib.tree_depth       = network->routing_tree_depth;
	session->nib.tree_position    = 0;
	session->nib.tx_retry_limit   = NETWORK_DEFAULT_TX_RETRY_LIMIT;
	session->nib.tx_retry_timeout = NETWORK_DEFAULT_TX_RETRY_TIMEOUT;
	memcpy(&session->nib.coordinator_address, &network->coordinator_address, sizeof(session->nib.coordinator_address));

	return 1;
}

/* Copy the configuration out of session into the space provided. Anything but session can be NULL.
 * If any IB in session is invalid, does a full update from lower layers.
 */
static int process_mlme_get_confirm(mac_callback_metadata_t* callback_metadata, mac_status_t status, mac_pib_attribute_t PIBAttribute, uint8_t *PIBAttributeValue);
int NLME_GET_request(starfishnet_session_t* session, starfishnet_nib_t* nib, mac_mib_t* mib, mac_pib_t* pib) {
	assert(session != NULL);

	if(!session->ibs_are_valid) {
		//TODO:
		//If our cache is out of date, do a full update from the MAC/PHY layer
		//(fail if update fails)
		mac_primitive_handler_t handler = {
			.MLME_GET_confirm = process_mlme_get_confirm
		};

		//TODO: actually do the update
	}

	if(nib != NULL) {
		memcpy(nib, &session->nib, sizeof(*nib));
	}

	if(mib != NULL) {
		memcpy(mib, &session->mib, sizeof(*mib));
	}

	if(pib != NULL) {
		memcpy(pib, &session->pib, sizeof(*pib));
	}

	return 1;
}
static int process_mlme_get_confirm(mac_callback_metadata_t* callback_metadata, mac_status_t status, mac_pib_attribute_t PIBAttribute, uint8_t *PIBAttributeValue) {
	if(status == mac_success && callback_metadata->extradata != NULL) {
		int length = 0;

		//TODO: security attributes
		switch(PIBAttribute) {
			case macCoordExtendedAddress:
			case macIEEEAddress:
				length = 64/8;
				break;

			case macCoordShortAddress:
			case macPANId:
			case macShortAddress:
			case macTransactionPersistenceTime:
				length = 2;
				break;

			case phyChannelsSupported:
			case macBeaconTxTime:
				length = 4;
				break;

			case macAckWaitDuration:
			case macAssociationPermit:
			case macAutoRequest:
			case macBattLifeExt:
			case macBattLifeExtPeriods:
			case macBeaconPayloadLength:
			case macBeaconOrder:
			case macBSN:
			case macDSN:
			case macGTSPermit:
			case macMaxCSMABackoffs:
			case macMinBE:
			case macPromiscuousMode:
			case macRxOnWhenIdle:
			case macSuperframeOrder:
			case phyCurrentChannel:
			case phyTransmitPower:
			case phyCCAMode:
				length = 1;
				break;

			case macBeaconPayload:
				//length = callback_metadata->session.nib.macBeaconPayloadLength;
				//TODO: FIXME
				length = 0;
				break;
		}

		assert(length > 0);

		memcpy(callback_metadata->extradata, PIBAttributeValue, length);

		return 1;
	}

	return 0;
}

//following is the TODO list, taken from network.h

int NLDE_DATA_request ( //send a packet
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	uint8_t payload_length,
	uint8_t* payload,
	uint8_t packet_handle,
	uint8_t flags, //DO_MESH_ROUTE_DISCOVERY, ASSOCIATE_IF_NECESSARY, DATA_IS_INSECURE, IS_NEIGHBOR (for association)
	starfishnet_security_metadata_t* security
);

int NLME_DISCOVERY_request ( //scan for 802.15.4 networks
	starfishnet_session_t* session,
	uint32_t channel_mask,
	uint8_t scan_duration
);
//if you want to do an ED scan, talk to the MAC layer

/* Request a short address from a neighboring router.
 * Implicitly ASSOCIATES if necessary; if so, request is in plaintext.
 * Must have already JOINed.
 * The router may stipulate a refresh period, which will be handled automatically by StarfishNet
 * The router may also refuse.
 */
int NLME_ADDR_ACQUIRE_request (
	starfishnet_session_t* session,
	mac_address_t router,
	uint8_t leaf
);
int NLME_ADDR_RELEASE_request ( //Release our short address. Implicitly revokes addresses from all children.
	starfishnet_session_t* session
);

int NLME_ASSOCIATE_request ( //associate with another StarfishNet node
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	starfishnet_security_metadata_t* security
);
int NLME_ASSOCIATE_response ( //answer an association request from another node
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	starfishnet_security_metadata_t* security
);
int NLME_DISSOCIATE_request ( //dissociate from a node. if we have one of its short addresses, it is implicitly invalidated (and thus we stop using it); this may lead to follow-on address revocations down the tree
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr
);

int NLME_RESET_request (
	starfishnet_session_t* session,
	_Bool warm
);

int NLME_SYNC_request ( //does MLME-SYNC.request, and also MLME_POLL.request
	starfishnet_session_t* session
);
//TODO: how do I convince the MAC layer to do POLL properly without ASSOCIATE??

//TODO: how the fuck am I going to do this?
int NLME_ROUTE_DISCOVERY_request(
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	starfishnet_security_metadata_t* security
);

int NLME_SET_request( //copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
	starfishnet_session_t* session,
	starfishnet_nib_t* nib,
	mac_mib_t* mib,
	mac_pib_t* pib
);

//other network-layer driver functions
int starfishnet_receive(starfishnet_session_t* session, starfishnet_ops_t* handlers);
