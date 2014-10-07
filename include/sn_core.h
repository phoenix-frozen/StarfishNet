#ifndef __SN_CORE_H__
#define __SN_CORE_H__

#include "sn_types.h"
#include <stddef.h>
#include <stdbool.h>

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
 * coordinator's involvement?
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
 * StarfishNet uses 802.15.4 MAC-layer acknowledgements for all packets
 * other than those involved in establishing an association.  This is because
 * each packet in an association transaction depends on the preceding ones,
 * and thus implicitly acknowledges them.
 */

//TODO: totally ignoring broadcasts for the moment

typedef struct SN_Network_descriptor {
    uint16_t        pan_id;
    uint8_t         radio_channel;
    uint8_t         routing_tree_depth;
    uint8_t         routing_tree_position;

    uint16_t        router_address;
    SN_Public_key_t router_public_key;
} SN_Network_descriptor_t;

//StarfishNet node association states
typedef enum SN_Association_state {
    SN_Unassociated,
    SN_Associate_received,
    SN_Awaiting_reply,
    SN_Awaiting_finalise,
    SN_Send_finalise,
    SN_Associated
} SN_Association_state_t;

typedef enum SN_Message_type {
    SN_Data_message,       //standard data message
    SN_Evidence_message,   //send a certificates to a StarfishNet node, usually as evidence of an attribute
    SN_Dissociation_request, //used by the network layer to signal a dissociation request from another node. implicitly invalidates any short address(es) we've taken from or given to it, forcing a recursive dissociation if needs be
    SN_Association_request,  //used by the network layer to signal an association request from another node
} SN_Message_type_t;

//StarfishNet messages
typedef union SN_Message {
    SN_Message_type_t type;

    struct {
        SN_Message_type_t type;
        uint8_t           payload_length;
        uint8_t           payload[];
    } data_message;

    struct {
        SN_Message_type_t type;
        SN_Certificate_t evidence;
    } evidence_message;

    struct {
        SN_Message_type_t type;
        union SN_Message* stapled_data;
    } association_message;
} SN_Message_t;

int SN_Send ( //transmit packet, containing one or more messages
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    SN_Message_t* message
);
int SN_Associate ( //transmit packet, containing one or more messages
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    SN_Message_t* stapled_data
);
int SN_Dissociate ( //transmit packet, containing one or more messages
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    SN_Message_t* stapled_data
);
int SN_Receive ( //receive a packet, containing one or more messages. Note, StarfishNet may also do some internal housekeeping (including additional packet transmissions) in the context of this function
    SN_Session_t* session,
    SN_Address_t* src_addr,
    SN_Message_t* buffer,
    size_t buffer_size
);

typedef void (SN_Discovery_callback_t) (SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata);
int SN_Discover ( //scan for StarfishNet networks. also serves as a nearest-neighbor scan
    SN_Session_t*            session,
    uint32_t                 channel_mask,
    uint32_t                 timeout,  //in ms
    SN_Discovery_callback_t* callback, //you get one callback for each network found
    void*                    extradata //will be passed to the callback
);

int SN_Start ( //start a new StarfishNet network as coordinator
    SN_Session_t*            session,
    SN_Network_descriptor_t* network
);

int SN_Join ( //tune the radio to a StarfishNet network and listen for packets with its PAN ID (note, this causes no packet exchange)
    SN_Session_t*            session,
    SN_Network_descriptor_t* network,
    bool                     disable_routing //1 to disable forwarding packets. also disallows us from having children.
);

int SN_Get_configuration ( //copies the configuration out of session into the space provided. anything but session can be NULL
    SN_Session_t* session,
    SN_Nib_t*     nib,
    mac_mib_t*    mib,
    mac_pib_t*    pib
);
int SN_Set_configuration ( //copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
    SN_Session_t* session,
    SN_Nib_t*     nib,
    mac_mib_t*    mib,
    mac_pib_t*    pib
);

//other network-layer driver functions
int SN_Init (     //initialise a new StarfishNet session, passing params onto the MAC layer
    SN_Session_t* session,
    SN_Keypair_t* master_keypair,
    char* params
);
void SN_Destroy ( //bring down this session, resetting the radio in the process
    SN_Session_t* session
);

//inform the network stack that a time tick has occurred
void SN_Tick();

#endif /* __SN_CORE_H__ */
