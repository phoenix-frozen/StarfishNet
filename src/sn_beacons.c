#include "sn_beacons.h"
#include <sn_status.h>
#include <sn_crypto.h>
#include <string.h>

#include "mac_util.h"
#include "sn_constants.h"
#include "sn_routing_tree.h"

static MAC_CONFIRM(start);

static MAC_SET_CONFIRM(macBeaconPayload);

static MAC_SET_CONFIRM(macBeaconPayloadLength);

static int build_beacon_payload(SN_Session_t* session, beacon_payload_t* buffer, SN_Hash_t* hash) {
    if(session == NULL || buffer == NULL || hash == NULL) {
        return -SN_ERR_NULL;
    }

    //protocol ID information
    buffer->protocol_id     = STARFISHNET_PROTOCOL_ID;
    buffer->protocol_ver    = STARFISHNET_PROTOCOL_VERSION;
    //routing tree metadata
    buffer->branching_factor = session->nib.tree_branching_factor;
    buffer->tree_position    = session->nib.tree_position;
    buffer->leaf_blocks      = session->nib.leaf_blocks;

    uint16_t leaf_capacity;
    uint16_t router_capacity;
    if(session->nib.enable_routing) {
        int ret = SN_Tree_determine_capacity(session, &leaf_capacity, &router_capacity);
        if(ret != SN_OK) {
            return ret;
        }
    } else {
        leaf_capacity = router_capacity = 0;
    }
    buffer->leaf_capacity   = (uint8_t)(leaf_capacity > 255 ? 255 : leaf_capacity);
    buffer->router_capacity = (uint8_t)(router_capacity > 255 ? 255 : router_capacity);

    //public key
    buffer->public_key = session->device_root_key.public_key;

    //address
    buffer->address = session->mib.macShortAddress;

    //hash
    SN_Crypto_hash((uint8_t*)buffer, sizeof(*buffer), hash, 0);

    return SN_OK;
}

static int do_network_start(SN_Session_t* session, mac_primitive_t* packet, bool isCoordinator) {
    SN_DebugPrintf("enter\n");

    if(session == NULL || packet == NULL) {
        return -SN_ERR_NULL;
    }

    //build beacon payload
    beacon_payload_t* proto_beacon = (beacon_payload_t*)session->mib.macBeaconPayload;
    SN_Hash_t beacon_hash;
    build_beacon_payload(session, proto_beacon, &beacon_hash); //no need to check error code, it only checks for nulls
    _Static_assert(sizeof(beacon_payload_t) + BEACON_HASH_LENGTH < aMaxBeaconPayloadSize, "beacon payloads are too big!");
    memcpy(session->mib.macBeaconPayload + sizeof(beacon_payload_t), &beacon_hash, BEACON_HASH_LENGTH);
    session->mib.macBeaconPayloadLength = sizeof(beacon_payload_t) + BEACON_HASH_LENGTH;

    //set beacon payload length
    packet->type                              = mac_mlme_set_request;
    packet->MLME_SET_request.PIBAttribute     = macBeaconPayloadLength;
    packet->MLME_SET_request.PIBAttributeSize = 1;
    packet->MLME_SET_request.PIBAttributeValue[0] = session->mib.macBeaconPayloadLength;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macBeaconPayloadLength_set_confirm);

    //set beacon payload
    packet->type                              = mac_mlme_set_request;
    packet->MLME_SET_request.PIBAttribute     = macBeaconPayload;
    packet->MLME_SET_request.PIBAttributeSize = session->mib.macBeaconPayloadLength;
    memcpy(packet->MLME_SET_request.PIBAttributeValue, session->mib.macBeaconPayload, session->mib.macBeaconPayloadLength);
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macBeaconPayload_set_confirm);

    //start beacon transmissions
    packet->type                                    = mac_mlme_start_request;
    packet->MLME_START_request.PANId                = session->mib.macPANId;
    packet->MLME_START_request.LogicalChannel       = session->pib.phyCurrentChannel;
    packet->MLME_START_request.BeaconOrder          = session->mib.macBeaconOrder;
    packet->MLME_START_request.SuperframeOrder      = session->mib.macSuperframeOrder;
    packet->MLME_START_request.PANCoordinator       = isCoordinator;
    packet->MLME_START_request.BatteryLifeExtension = session->mib.macBattLifeExt;
    packet->MLME_START_request.CoordRealignment     = 0;
    packet->MLME_START_request.SecurityEnable       = 0;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)start_confirm);

    SN_DebugPrintf("exit\n");
    return SN_OK;
}

int SN_Beacon_update(SN_Session_t* session) {
    mac_primitive_t packet;

    return do_network_start(session, &packet, session->mib.macShortAddress == SN_COORDINATOR_ADDRESS);
}