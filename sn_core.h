#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "mac.h"

#define aMaxMACSecurityOverhead (5 /* AuxLen */ + 16 /* AuthLen for MIC-128 */)
#define NETWORK_MAX_PAYLOAD_SIZE (aMinMPDUOverhead + aMaxMACSecurityOverhead)
#define NETWORK_MAX_SAFE_PAYLOAD_SIZE (aMaxMPDUUnsecuredOverhead + aMaxMACSecurityOverhead)
#define NETWORK_DEFAULT_TX_RETRY_LIMIT 3
#define NETWORK_DEFAULT_TX_RETRY_TIMEOUT 2500

/*
 * This is the Starfish protocol.  Named for the neurological independence of
 * the limbs of a starfish from the rest of the animal; nonetheless, the limbs
 * and CNS visibly and functionally form part of a single, coherent body.
 *
 * Starfish works the same way.  Much as in other 802.15.4-based wireless
 * sensor network protocols, there is a single coordinator node at the centre
 * of the network.  This coordinator has a mainly administrative function: it
 * allocates 802.15.4 short addresses to its children (individually if they are
 * RFDs, in blocks if they are FFDs).  It also serves as the root of the
 * fallback routing tree, in case mesh routing fails.
 *
 * However, this is where the similarity ends.  Other network protocols
 * centralise security metadata at this same coordinator node; this node is
 * thus implicitly trusted by every other node on the network.  (Think Wi-Fi
 * access points for a common example of the same problem.)  What if we didn't?
 * What if the coordinator were just a bureaucrat, if security associations
 * were performed pairwise between nodes on the network without the
 * coordinator's invovement?
 * We'd have a handshake problem, that's what.  On a wireless sensor network,
 * where nodes routinely want to talk to each other, we have a quadratic number
 * of handshakes being performed, each of which requires manual verification to
 * ensure no man-in-the-middle attacks.  But what if nodes could vouch for each
 * other?  What if associations between nodes A and B, and B and C, meant B
 * could vouch for A in respect of C, and vice-versa?  Only insofar as B knows
 * anything about them, of course.  But if it's only their identities we're
 * seeking to guarantee, that might just be enough.  Assuming A and C trust B
 * to vouch for that property.
 *
 * StarfishNet does not use 802.15.4 MAC-layer acknowledgements.  This is
 * because they are insecure.  We instead reimplement this functionality at
 * the network layer.
 */

//TODO: introduce fields for session ID? higher-layer protocol ID? (a la IP)
//TODO: how the fuck am I going to do ECC key/certificate management?


//network-layer types
typedef struct starfishnet_address {
	mac_address_t address;
	mac_address_mode_t type;
} starfishnet_address_t;

typedef struct starfishnet_nib {
	//routing tree config
	//globals
	uint8_t tree_depth; //maximum depth of the routing tree
	//node config
	uint8_t tree_position; //where we are on the routing tree
	uint8_t tree_leaf_count; //how much of our address range should be
							 //used for leaf nodes (the rest is delegable blocks). power of two.

	//retransmission config
	uint8_t tx_retry_limit; //number of retransmits before reporting failure
	uint16_t tx_retry_timeout; //time to wait between retransmits

	starfishnet_address_t coordinator_address; //always in 64-bit mode

	//TODO: keys?
} starfishnet_nib_t;

typedef struct starfishnet_sa {
	starfishnet_address_t long_address; //mac address
	starfishnet_address_t short_address; //network address, if available

	//TODO: agreed symmetric key
	//TODO: asymmetric key
	//TODO: certificate(s) and certificate chain(s)
} starfishnet_sa_t;

typedef struct starfishnet_sa_container starfishnet_sa_container_t;

typedef struct starfishnet_session {
	mac_session_handle_t mac_session;
	starfishnet_nib_t nib;
	mac_mib_t mib; //not guaranteed to be valid
	mac_pib_t pib; //not guaranteed to be valid
	uint8_t ibs_are_valid;

	starfishnet_sa_container_t* sas;
} starfishnet_session_t;

typedef enum starfishnet_status {
	starfishnet_success = 0,
} starfishnet_status_t;

typedef struct starfishnet_network_descriptor {
	starfishnet_address_t coordinator_address; //always in 64-bit mode
	starfishnet_address_t nearest_neighbor_address;
	uint16_t pan_id;
	uint8_t radio_channel;
	uint8_t routing_tree_depth;
	uint8_t routing_tree_position;
} starfishnet_network_descriptor_t;

typedef struct starfishnet_security_metadata {
} starfishnet_security_metadata_t;

//function prototypes for event notifications
typedef struct starfishnet_ops {
	int (*NLDE_DATA_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		uint8_t packet_handle,
		starfishnet_status_t status
	);
	int (*NLDE_DATA_indication) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_address_t* src_addr,
		starfishnet_address_t* dst_addr,
		uint8_t payload_length,
		uint8_t* payload,
		uint8_t mac_link_quality,
		starfishnet_security_metadata_t* security
	);

	int (*NLME_DISCOVERY_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		uint8_t starfishnet_count,
		starfishnet_network_descriptor_t* network_descriptors
	);
	int (*NLME_JOIN_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		starfishnet_network_descriptor_t* network_descriptor
	);

	int (*NLME_FORMATION_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status
	);

	int (*NLME_ASSOCIATE_indication) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_address_t* src_addr,
		starfishnet_security_metadata_t* security
	);
	int (*NLME_ASSOCIATE_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		starfishnet_address_t* src_addr,
		starfishnet_security_metadata_t* security
	);
	int (*NLME_DISASSOCIATE_indication) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_address_t* src_addr
	);
	int (*NLME_DISASSOCIATE_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		starfishnet_address_t* src_addr
	);

	int (*NLME_GET_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		mac_pib_attribute_t PIBAttribute
	);
	int (*NLME_SET_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status,
		mac_pib_attribute_t PIBAttribute
	);

	int (*NLME_RESET_confirm) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status
	);

	int (*NLME_SYNC_confirm) ( //this subsumes SYNC-LOSS as well
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status
	);

	int (*NLME_COMM_STATUS_indication) (
		starfishnet_session_t* session,
		void* callback_data,
		starfishnet_status_t status
	);

	int (*unknown_primitive) (
		starfishnet_session_t* session,
		void* callback_data,
		uint8_t primitive,
		uint8_t *data,
		uint8_t length
	);

	void* callback_data;
} starfishnet_ops_t;

int NLDE_DATA_request ( //send a packet
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	uint8_t payload_length,
	uint8_t* payload,
	uint8_t packet_handle,
	uint8_t flags, //DO_MESH_ROUTE_DISCOVERY, ASSOCIATE_IF_NECESSARY, DATA_IS_INSECURE
	starfishnet_security_metadata_t* security
);

int NLME_DISCOVERY_request ( //scan for 802.15.4 networks
	starfishnet_session_t* session,
	uint32_t channel_mask,
	uint8_t scan_duration
);
//if you want to do an ED scan, talk to the MAC layer

int NLME_FORMATION_request ( //start a new StarfishNet network as coordinator
	starfishnet_session_t* session,
	starfishnet_network_descriptor_t* network
);
int NLME_JOIN_request ( //tune the radio to a StarfishNet network ind listen for packets with its PAN ID (note, this causes no packet exchange)
	starfishnet_session_t* session,
	starfishnet_network_descriptor_t* network
);
int NLME_ADDR_ACQUIRE_request ( //request a short address from a neighboring router. implicitly ASSOCIATES and requests in plaintext. must have already JOINed. the router may stipulate a refresh period, which will be handled automatically by StarfishNet. the router may also refuse, if it cannot fulfil the request
	starfishnet_session_t* session,
	mac_address_t router,
	uint8_t leaf
);
int NLME_ADDR_RELEASE_request ( //release our short address
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

int NLME_ROUTE_DISCOVERY_request(
	starfishnet_session_t* session,
	starfishnet_address_t* dst_addr,
	starfishnet_security_metadata_t* security
);

int NLME_GET_request( //copies the configuration out of session into the space provided. anything but session can be NULL
	starfishnet_session_t* session,
	starfishnet_nib_t* nib,
	mac_mib_t* mib,
	mac_pib_t* pib
);
int NLME_SET_request( //copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
	starfishnet_session_t* session,
	starfishnet_nib_t* nib,
	mac_mib_t* mib,
	mac_pib_t* pib
);

//other network-layer driver functions
int starfishnet_init(starfishnet_session_t* session, char* params);
int starfishnet_receive(starfishnet_session_t* session, starfishnet_ops_t* handlers);

#endif /* __NETWORK_H__ */

