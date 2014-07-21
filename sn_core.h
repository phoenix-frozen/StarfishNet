#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "mac802154.h"

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
typedef struct SN_Address {
	mac_address_t address;
	mac_address_mode_t type;
} SN_Address_t;

typedef struct SN_Nib {
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

	mac_address_t coordinator_address; //always in 64-bit mode

	//TODO: keys?
} SN_Nib_t;

typedef struct SN_Sa {
	SN_Address_t long_address; //mac address
	SN_Address_t short_address; //network address, if available

	//TODO: agreed symmetric key
	//TODO: asymmetric key
	//TODO: certificate(s) and certificate chain(s)
} SN_Sa_t;

typedef struct SN_Sa_container SN_Sa_container_t;

typedef struct SN_Session {
	mac_session_handle_t mac_session;
	SN_Nib_t nib;
	mac_mib_t mib; //not guaranteed to be valid
	mac_pib_t pib; //not guaranteed to be valid
	uint8_t ibs_are_valid;

	SN_Sa_container_t* sas;
} SN_Session_t;

typedef enum SN_Status {
	SN_Success = 0,
} SN_Status_t;

typedef struct SN_Network_descriptor {
	mac_address_t coordinator_address; //always in 64-bit mode
	mac_address_t nearest_neighbor_address; //always in 64-bit mode
	uint16_t nearest_neighbor_short_address;
	uint16_t pan_id;
	uint8_t radio_channel;
	uint8_t routing_tree_depth;
	uint8_t routing_tree_position;

	//TODO: key material?
} SN_Network_descriptor_t;

typedef struct SN_Security_metadata {
} SN_Security_metadata_t;

//function prototypes for event notifications
typedef struct SN_Ops {
	int (*SN_Message) (
		SN_Session_t* session,
		SN_Address_t* src_addr,
		SN_Address_t* dst_addr,
		uint8_t payload_length,
		uint8_t* payload,
		SN_Security_metadata_t* security,
		void* extradata
	);

	int (*SN_Association) (
		SN_Session_t* session,
		SN_Address_t* src_addr,
		SN_Security_metadata_t* security,
		bool initiator, //1 if we're initiating, 0 if we're responding
		void* extradata
	);
	int (*SN_Dissociation) (
		SN_Session_t* session,
		SN_Address_t* src_addr,
		bool initiator, //1 if we're initiating, 0 if we're responding
		void* extradata
	);

	int (*unknown_primitive) (
		SN_Session_t* session,
		uint8_t primitive,
		uint8_t *data,
		uint8_t length,
		void* extradata
	);

	void* extradata;
} SN_Ops_t;

int SN_Send ( //send a packet
	SN_Session_t* session,
	SN_Address_t* dst_addr,
	uint8_t payload_length,
	uint8_t* payload,
	uint8_t packet_handle,
	uint8_t flags, //DO_MESH_ROUTE_DISCOVERY, ASSOCIATE_IF_NECESSARY, DATA_IS_INSECURE
	SN_Security_metadata_t* security
);

int SN_Discover ( //scan for 802.15.4 networks
	SN_Session_t* session,
	uint32_t channel_mask,
	uint32_t timeout,
	void (*callback) (SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata), //you get one callback for each network found
	void* extradata //will be passed to the callback
);

int SN_Start ( //start a new StarfishNet network as coordinator
	SN_Session_t* session,
	SN_Network_descriptor_t* network
);

int SN_Join ( //tune the radio to a StarfishNet network and listen for packets with its PAN ID (note, this causes no packet exchange)
	SN_Session_t* session,
	SN_Network_descriptor_t* network,
	bool disable_routing //1 to disable forwarding packets. also disallows us from having children.
);

int SN_Request_address ( //request a short address from a neighboring router. implicitly ASSOCIATES and requests in plaintext. must have already JOINed. the router may stipulate a refresh period, which will be handled automatically by StarfishNet. the router may also refuse, if it cannot fulfil the request
	SN_Session_t* session,
	mac_address_t router
);
int SN_Release_address (SN_Session_t* session); //release our short address

int SN_Associate ( //associate with another StarfishNet node
	SN_Session_t* session,
	SN_Address_t* dst_addr,
	SN_Security_metadata_t* security,
	bool initiator //1 if we're initiating, 0 if we're responding
);
int SN_Dissociate ( //dissociate from a node. if we have one of its short addresses, it is implicitly invalidated (and thus we stop using it); this may lead to follow-on address revocations down the tree
	SN_Session_t* session,
	SN_Address_t* dst_addr,
	bool initiator //1 if we're initiating, 0 if we're responding
);

//int SN_Poll_parent (SN_Session_t* session); //does MLME-SYNC.request, and also MLME_POLL.request
//when implemented, uses MLME-SYNC/MLME-POLL to poll our parent for pending messages

int SN_Get_configuration ( //copies the configuration out of session into the space provided. anything but session can be NULL
	SN_Session_t* session,
	SN_Nib_t* nib,
	mac_mib_t* mib,
	mac_pib_t* pib
);
int SN_Set_configuration ( //copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
	SN_Session_t* session,
	SN_Nib_t* nib,
	mac_mib_t* mib,
	mac_pib_t* pib
);

//other network-layer driver functions
int SN_Init (SN_Session_t* session, char* params);
int SN_Destroy (SN_Session_t* session); //bring down this session, resetting the radio in the process

int SN_Receive (SN_Session_t* session, SN_Ops_t* handlers);

#endif /* __NETWORK_H__ */

