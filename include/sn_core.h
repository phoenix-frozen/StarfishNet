#ifndef __SN_CORE_H__
#define __SN_CORE_H__

#include "sn_types.h"
#include <stddef.h>
#include <stdbool.h>

typedef struct SN_Network_descriptor {
    //MAC information
    uint16_t        pan_id;
    uint8_t         radio_channel;

    //routing tree configuration
    uint8_t         routing_tree_branching_factor;
    uint16_t        leaf_blocks;

    //router information
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
    SN_Explicit_Evidence_message,   //send a certificate to a StarfishNet node
    SN_Implicit_Evidence_message,   //send a partial certificate to a StarfishNet node. we are its implicit signer
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
    } explicit_evidence_message;

    //TODO: implicit_evidence_message

    struct {
        SN_Message_type_t type;
    } association_message;
} SN_Message_t;
#define SN_MAX_DATA_MESSAGE_LENGTH 127
//TODO: make SN_MAX_DATA_MESSAGE_LENGTH right

int SN_Send ( //transmit normal packet, containing either data or evidence
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    SN_Message_t* message
);
int SN_Associate ( //start an association transaction
    SN_Session_t* session,
    SN_Address_t* dst_addr
);
int SN_Dissociate ( //start a dissociation
    SN_Session_t* session,
    SN_Address_t* dst_addr
);
int SN_Receive ( //receive a packet containing a message. Note, StarfishNet may also do some internal housekeeping (including additional packet transmissions) in the context of this function
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
    bool                     show_full_networks, //0 gets you a callback only from networks with spare capacity
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

#endif /* __SN_CORE_H__ */
