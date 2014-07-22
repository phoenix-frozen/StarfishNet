#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "mac802154.h"
#include "sn_core.h"
#include "sn_status.h"

#define SN_DEBUG
#include "sn_logging.h"

//network starts here

#define STARFISHNET_PROTOCOL_ID 0x55
#define STARFISHNET_PROTOCOL_VERSION 0x0

#define DEFAULT_TX_RETRY_LIMIT 3
#define DEFAULT_TX_RETRY_TIMEOUT 2500

#ifndef NDEBUG
#include <stdio.h>
#define GUARANTEED_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return SN_ERR_RADIO; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define GUARANTEED_CALL(call, x...) { if(call(x) <= 0) { return SN_ERR_RADIO; } }
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
MAC_SET_CONFIRM(macCoordExtendedAddress);

static inline uint8_t log2i(uint32_t n) {
    if(n == 0)
        return 0;
    return 31 - (uint8_t)__builtin_clz(n);
}

//just a basic linked list for the moment. do something smart later.
struct SN_Sa_container {
    SN_Sa_container_t* next;
    SN_Sa_t entry;
};

typedef struct beacon_payload {
    //protocol ID information
    uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
    uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

    //device tree metadata
    uint8_t tree_depth; //maximum tree depth
    uint8_t router_depth; //depth in the tree of this router
    int8_t router_capacity; //remaining child slots. negative if children can only be leaves

    //addressing metadata
    uint16_t short_address;
    mac_address_t long_address;

    mac_address_t coordinator_address;

    /*TODO:
     * this device's public key
     * network root's public key
     * beacon signature?
     */
} beacon_payload_t;

typedef struct SN_Msdu {
    //protocol ID information
    uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
    uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

    uint8_t packet_type;

    uint8_t data[]; //data length is implied from the length of the MSDU
} SN_Msdu_t;

#define STRUCTCLEAR(x) memset(&(x), 0, sizeof(x))

static SN_Status mac_reset_radio(SN_Session_t* session, mac_primitive_t* packet) {
    assert(MAC_IS_SESSION_VALID(session->mac_session));

    //Reset the radio
    packet->type                               = mac_mlme_reset_request;
    packet->MLME_RESET_request.SetDefaultPIB   = 1;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)reset_confirm);

    //load default MIB
    memcpy(&(session->mib), &mac_default_MIB, sizeof(mac_default_MIB));
    //macBSN
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macBSN;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macBSN);
    memcpy(&session->mib.macBSN, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //macDSN
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macDSN;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macDSN);
    memcpy(&session->mib.macDSN, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //macIEEEAddress
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macIEEEAddress;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macIEEEAddress);
    memcpy(session->mib.macIEEEAddress.ExtendedAddress, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));

    //load PIB
    //phyCurrentChannel
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyCurrentChannel;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyCurrentChannel);
    memcpy(&session->pib.phyCurrentChannel, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyChannelsSupported
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyChannelsSupported;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyChannelsSupported);
    memcpy(&session->pib.phyChannelsSupported, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyTransmitPower
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyTransmitPower;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyTransmitPower);
    memcpy(&session->pib.phyTransmitPower, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyCCAMode
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyCCAMode;
    GUARANTEED_CALL(mac_transmit, session->mac_session, packet);
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyCCAMode);
    memcpy(&session->pib.phyCCAMode, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));

    return SN_OK;
}


//start a new StarfishNet network as coordinator
int SN_Start (SN_Session_t* session, SN_Network_descriptor_t* network);

/* Tune the radio to a StarfishNet network and listen for packets with its PAN ID.
 * Note, this call does not directly cause any packet exchange.  However, it will
 * result in route discoveries starting to succeed.
 * Remember that naive broadcasts won't be receivable until we do a SA with a neighbor router.
 */
int SN_Join (SN_Session_t* session, SN_Network_descriptor_t* network, bool disable_routing) {
    assert(session != NULL);
    assert(network != NULL);

    mac_primitive_t packet;

    /* Fill NIB */
    session->nib.tree_depth       = network->routing_tree_depth;
    session->nib.tree_position    = 0;
    session->nib.tx_retry_limit   = DEFAULT_TX_RETRY_LIMIT;
    session->nib.tx_retry_timeout = DEFAULT_TX_RETRY_TIMEOUT;
    memcpy(session->nib.coordinator_address.ExtendedAddress, network->coordinator_address.ExtendedAddress, sizeof(mac_address_t));

    if(!disable_routing) {
        //TODO: start broadcasting beacons
    }

    session->pib.phyCurrentChannel        = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.LogicalChannel;
    session->mib.macPANId                 = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordPANId;
    session->mib.macCoordAddrMode         = mac_extended_address;
    session->mib.macCoordShortAddress     = 0;
    memcpy(session->mib.macCoordExtendedAddress.ExtendedAddress, network->nearest_neighbor_address.ExtendedAddress, 8);

    //... wait until the radio is out of scan mode...
    GUARANTEED_CALL(mac_receive_primitive_type, session->mac_session, &packet, mac_mlme_scan_confirm);

    //... and then update the radio's configuration for the network we discovered.

    //Tune to the right channel
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = phyCurrentChannel;
    packet.MLME_SET_request.PIBAttributeSize     = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = session->pib.phyCurrentChannel;
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)phyCurrentChannel_set_confirm);

    //Set our PAN Id
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macPANId;
    packet.MLME_SET_request.PIBAttributeSize     = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macPANId, 2);
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macPANId_set_confirm);

    //Set our coord address
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macCoordExtendedAddress;
    packet.MLME_SET_request.PIBAttributeSize     = 8;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, session->mib.macCoordExtendedAddress.ExtendedAddress, 8);
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macCoordExtendedAddress_set_confirm);

    //Then, do some final configuration.

    //Set our short address to be the "joined but no short address" flag value
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macShortAddress;
    session->mib.macShortAddress                 = 0xFFFE;
    packet.MLME_SET_request.PIBAttributeSize     = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

    //Switch on RX_ON_IDLE
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macRxOnWhenIdle;
    packet.MLME_SET_request.PIBAttributeSize     = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = 1;
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);
    GUARANTEED_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macRxOnWhenIdle_set_confirm);
    session->mib.macRxOnWhenIdle                 = 1;

    //TODO: add relevant addresses to node table

    //And we're done. Setting up a security association with our new parent is deferred until the first packet exchange.
    return SN_OK;
}

int SN_Send ( //send a packet
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    uint8_t payload_length,
    uint8_t* payload,
    uint8_t packet_handle,
    uint8_t flags, //ASSOCIATE_IF_NECESSARY, DATA_IS_INSECURE
    SN_Security_metadata_t* security
) {
    //TODO: flags

    uint8_t max_payload_size = aMaxMACSafePayloadSize;

    if (payload_length > 0) {
        mac_primitive_t primitive = {
            .type = mac_mcps_data_request,
            .MCPS_DATA_request = {
                .SrcPANId    = session->mib.macPANId,
                //.SrcAddr is filled below
                //.SrcAddrMode is filled below
                .DstPANId    = session->mib.macPANId,
                //.DstAddr is filled below
                .DstAddrMode = dst_addr->type,
                //.msduLength is filled below
                .msduHandle  = packet_handle,
                .TxOptions   = 0,
                //.msdu is filled below
            },
        };

        //SrcAddr and SrcAddrMode
        if(session->mib.macShortAddress != 0xFFFE) { //if we have a short address...
            //use it
            primitive.MCPS_DATA_request.SrcAddrMode          = mac_short_address;
            primitive.MCPS_DATA_request.SrcAddr.ShortAddress = session->mib.macShortAddress;
            max_payload_size += 6; //header size decreases by 6 bytes if we're using a short address
        } else {
            //otherwise, use our MAC address
            primitive.MCPS_DATA_request.SrcAddrMode = mac_extended_address;
            memcpy(primitive.MCPS_DATA_request.SrcAddr.ExtendedAddress, session->mib.macIEEEAddress.ExtendedAddress, 8);
        }

        //DstAddr
        if(primitive.MCPS_DATA_request.DstAddrMode == mac_short_address) {
            primitive.MCPS_DATA_request.DstAddr.ShortAddress = dst_addr->address.ShortAddress;
            max_payload_size += 6; //header size decreases by 6 bytes if we're using a short address
        } else {
            assert(primitive.MCPS_DATA_request.DstAddrMode == mac_extended_address);
            memcpy(primitive.MCPS_DATA_request.DstAddr.ExtendedAddress, dst_addr->address.ExtendedAddress, 8);
        }

        //msduLength and msdu
        if(payload_length > max_payload_size - 1) { //the first byte of the packet tells us whether we have plain or zlib-compressed data
            //if we have too much data, attempt to zlib-compress
            SN_WarnPrintf("%s(): data size %u is larger than max_payload_size(=%d), compressing...\n", __FUNCTION__, (unsigned int)payload_length, max_payload_size - 1);

            unsigned long compressed_data_length = max_payload_size - 1;
            int zret = compress2(primitive.MCPS_DATA_request.msdu + 1, &compressed_data_length, payload, payload_length, Z_BEST_COMPRESSION);

            if(zret != Z_OK) {
                SN_ErrPrintf("%s(): compression failed with %s. aborting send\n", __FUNCTION__, zError(zret));
                return SN_ERR_RESOURCES; //most likely reason is that there wasn't enough space in the target buffer
            }

            primitive.MCPS_DATA_request.msduLength = (uint8_t)compressed_data_length + 1;
            primitive.MCPS_DATA_request.msdu[0] = 'Z'; //zlib-compressed data
        } else {
            primitive.MCPS_DATA_request.msduLength = payload_length + 1;
            primitive.MCPS_DATA_request.msdu[0] = 'P'; //plain data
            memcpy(primitive.MCPS_DATA_request.msdu + 1, payload, payload_length);
        }

        int ret = mac_transmit(session->mac_session, &primitive);

        //printf("ret = %d, payload_length = %ld\n", ret, payload_length);
        assert(ret == 11 + primitive.MCPS_DATA_request.msduLength + (primitive.MCPS_DATA_request.DstAddrMode == mac_extended_address ? 8 : 2) + (primitive.MCPS_DATA_request.SrcAddrMode == mac_extended_address ? 8 : 2)); //27 if both address formats are extended
        if (ret <= 0) {
            SN_ErrPrintf("%s(): MCPS_DATA_request() failed with %d. status=SN_ERR_RADIO\n", __FUNCTION__, ret);
            return SN_ERR_RADIO;
        }
        //TODO: queueing behaviour: queue MCPS_DATA.indication while waiting for MCPS_DATA.confirm or MLME_COMM_STATUS.indication
        //TODO: make sure we're actually waiting for either MCPS_DATA.confirm or MLME_COMM_STATUS.indication
        const uint8_t tx_confirm[] = { mac_mcps_data_confirm, packet_handle, mac_success };
        ret = mac_receive_primitive_exactly(session->mac_session, (mac_primitive_t*)tx_confirm);
        if(ret <= 0) {
            SN_ErrPrintf("%s(): packet tx failed with %d. status=SN_ERR_RADIO\n", __FUNCTION__, ret);
            return SN_ERR_RADIO;
        }
    }

    SN_InfoPrintf("%s(): status=SN_OK\n", __FUNCTION__);
    return SN_OK;
}

/* scan for StarfishNet networks
 *
 * You get one callback for each network discovered, with the extradata you provided.
 */
int SN_Discover (SN_Session_t* session, uint32_t channel_mask, uint32_t timeout, void (*callback) (SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata), void* extradata) {
    mac_primitive_t packet;

    channel_mask &= 0x07FFF800; //top 5 bits must be zero, bottom 11 bits aren't 2.4GHz

    //Setup a network scan
    packet.type                               = mac_mlme_scan_request;
    packet.MLME_SCAN_request.ScanType         = mac_active_scan;
    packet.MLME_SCAN_request.ScanChannels     = channel_mask;

    //Timeout is in seconds. We need to convert it into a form the radio will understand.
    //We're given ms, the radio wants an exponent for a calculation denominated in radio symbols.
    timeout /= __builtin_popcount(channel_mask); //divide the timeout equally between the channels to scan, which number 11 to 26
    if(timeout * aSymbolsPerSecond_24 / 1000 <= aBaseSuperframeDuration) {
        SN_ErrPrintf("%s(): timeout value %u is too short\n", __FUNCTION__, timeout);
        return SN_ERR_INVALID;
    }
    packet.MLME_SCAN_request.ScanDuration     = log2i((timeout * aSymbolsPerSecond_24 / 1000 - aBaseSuperframeDuration) / aBaseSuperframeDuration);
    if(packet.MLME_SCAN_request.ScanDuration > 14) {
        SN_WarnPrintf("%s(): ScanDuration %u is too high, capping.\n", __FUNCTION__, packet.MLME_SCAN_request.ScanDuration);
        packet.MLME_SCAN_request.ScanDuration = 14;
    }

    //initiate the scan
    SN_InfoPrintf("%s(): initiating scan with ScanDuration=%u\n", __FUNCTION__, packet.MLME_SCAN_request.ScanDuration);
    GUARANTEED_CALL(mac_transmit, session->mac_session, &packet);

    SN_Network_descriptor_t ndesc;

    //During a scan, we get a MLME-BEACON.indication for each received beacon.
    //MLME-SCAN.confirm is received when a scan finishes.
    while(1) {
        //receive a primitive
        GUARANTEED_CALL(mac_receive, session->mac_session, &packet);

        //if it's an MLME-SCAN.confirm, we're done -- quit out
        if(packet.type == mac_mlme_scan_confirm)
            break;

        //during a scan, the radio's only supposed to generate MLME-BEACON-NOTIFY.indication or MLME-SCAN.confirm
        assert(packet.type == mac_mlme_beacon_notify_indication);
        if(packet.type != mac_mlme_beacon_notify_indication)
            continue; //still we should handle that error gracefully

        SN_InfoPrintf("%s(): found network. channel=0x%x, PANId=0x%x\n", __FUNCTION__, packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.LogicalChannel, packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordPANId);

        //if we get to here, we're looking at an MLME-BEACON-NOTIFY.indication
        beacon_payload_t* beacon_payload = (beacon_payload_t*)packet.MLME_BEACON_NOTIFY_indication.sdu;

        SN_InfoPrintf("%s():     PID=%#02x, PVER=%#02x\n", __FUNCTION__, beacon_payload->protocol_id, beacon_payload->protocol_ver);

        //check that this is a network of the kind we care about
        if(beacon_payload->protocol_id  != STARFISHNET_PROTOCOL_ID)
            continue;
        if(beacon_payload->protocol_ver != STARFISHNET_PROTOCOL_VERSION)
            continue;

        //TODO: check signature

        memcpy(ndesc.coordinator_address.ExtendedAddress,      beacon_payload->coordinator_address.ExtendedAddress, sizeof(mac_address_t));
        memcpy(ndesc.nearest_neighbor_address.ExtendedAddress, beacon_payload->long_address.ExtendedAddress,        sizeof(mac_address_t));
        ndesc.nearest_neighbor_short_address = beacon_payload->short_address;
        ndesc.pan_id                = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.CoordPANId;
        ndesc.radio_channel         = packet.MLME_BEACON_NOTIFY_indication.PANDescriptor.LogicalChannel;
        ndesc.routing_tree_depth    = beacon_payload->tree_depth;
        ndesc.routing_tree_position = beacon_payload->tree_depth;

        callback(session, &ndesc, extradata);
    }

    return SN_OK;
}

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
int SN_Init (SN_Session_t* session, char* params) {
    assert(session != NULL);

    //allocate some stack space
    SN_Session_t protosession;
    STRUCTCLEAR(protosession);

    //init the mac layer
    protosession.mac_session = mac_init(params);
    assert(protosession.mac_session.meta != 0); //this covers the fd case as well
    if(protosession.mac_session.meta == 0) //this covers the fd case as well
        return 0;

    //set up my basic linkedlist SA tracker
    protosession.sas = NULL;

    //return results
    *session = protosession;

    return 1;
}
int SN_Destroy (SN_Session_t* session) { //bring down this session, resetting the radio in the process
    mac_primitive_t packet;

    /*TODO: disconnect
     * revoke all children's short-address allocations
     * release my short-address allocation(s)
     * terminate all SAs (implicitly cleans out the node table)
     */

    //reset the radio
    mac_reset_radio(session, &packet);

    //close up the MAC-layer session
    mac_destroy(session->mac_session);

    //clean up I/O buffers
    STRUCTCLEAR(*session);
}

int SN_Receive (SN_Session_t* session, SN_Ops_t* handlers);

