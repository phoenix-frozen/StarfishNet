#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "mac802154.h"
#include "sn_core.h"
#include "sn_status.h"
#include "sn_table.h"

#define SN_DEBUG
#include "sn_logging.h"

//network starts here

#define STARFISHNET_PROTOCOL_ID 0x55
#define STARFISHNET_PROTOCOL_VERSION 0x0

#define DEFAULT_TX_RETRY_LIMIT 3
#define DEFAULT_TX_RETRY_TIMEOUT 2500

#define FIXED_COORDINATOR_ADDRESS 0x0000
#define NO_SHORT_ADDRESS          0xFFFE

#ifndef NDEBUG
#include <stdio.h>
#define MAC_CALL(call, x...) { printf(#call"("#x")\n"); int ret = call(x); if(ret <= 0) { printf("\t%d (failure)\n", ret); return -SN_ERR_RADIO; } else { printf("\t%d (success)\n", ret); } }
#else //NDEBUG
#define MAC_CALL(call, x...) { if(call(x) <= 0) { return -SN_ERR_RADIO; } }
#endif //NDEBUG

//some templates for mac_receive_primitive
#define MAC_CONFIRM(primitive)     const uint8_t primitive##_confirm[] = {mac_mlme_##primitive##_confirm, mac_success}
#define MAC_SET_CONFIRM(primitive) const uint8_t primitive##_set_confirm[] = {mac_mlme_set_confirm, mac_success, primitive}
static MAC_CONFIRM(reset);
static MAC_CONFIRM(start);
static MAC_SET_CONFIRM(macAssociationPermit);
static MAC_SET_CONFIRM(macBeaconPayload);
static MAC_SET_CONFIRM(macBeaconPayloadLength);
static MAC_SET_CONFIRM(macPANId);
static MAC_SET_CONFIRM(macRxOnWhenIdle);
static MAC_SET_CONFIRM(macShortAddress);
static MAC_SET_CONFIRM(phyCurrentChannel);
static MAC_SET_CONFIRM(macCoordShortAddress);
static MAC_SET_CONFIRM(macCoordExtendedAddress);

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
    uint8_t tree_position; //depth in the tree of this router
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

typedef struct SN_Packet {
    //protocol ID information
    uint8_t protocol_id; //STARFISHNET_PROTOCOL_ID
    uint8_t protocol_ver; //STARFISHNET_PROTOCOL_VERSION

    uint8_t packet_type;

    uint8_t data[]; //data length is implied from the length of the MSDU
} SN_Packet_t;

#define STRUCTCLEAR(x) memset(&(x), 0, sizeof(x))

static int mac_reset_radio(SN_Session_t* session, mac_primitive_t* packet) {
    assert(MAC_IS_SESSION_VALID(session->mac_session));

    //Reset the radio
    packet->type                               = mac_mlme_reset_request;
    packet->MLME_RESET_request.SetDefaultPIB   = 1;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)reset_confirm);

    //load default MIB
    memcpy(&(session->mib), &mac_default_MIB, sizeof(mac_default_MIB));
    //macBSN
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macBSN;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macBSN);
    memcpy(&session->mib.macBSN, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //macDSN
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macDSN;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macDSN);
    memcpy(&session->mib.macDSN, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //macIEEEAddress
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = macIEEEAddress;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == macIEEEAddress);
    memcpy(session->mib.macIEEEAddress.ExtendedAddress, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));

    //load PIB
    //phyCurrentChannel
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyCurrentChannel;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyCurrentChannel);
    memcpy(&session->pib.phyCurrentChannel, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyChannelsSupported
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyChannelsSupported;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyChannelsSupported);
    memcpy(&session->pib.phyChannelsSupported, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyTransmitPower
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyTransmitPower;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyTransmitPower);
    memcpy(&session->pib.phyTransmitPower, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));
    //phyCCAMode
    packet->type = mac_mlme_get_request;
    packet->MLME_SET_request.PIBAttribute = phyCCAMode;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_type, session->mac_session, packet, mac_mlme_get_confirm);
    assert(packet->type == mac_mlme_get_confirm);
    assert(packet->MLME_GET_confirm.PIBAttribute == phyCCAMode);
    memcpy(&session->pib.phyCCAMode, packet->MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet->MLME_GET_confirm.PIBAttribute));

    return SN_OK;
}


static int build_beacon_payload(SN_Session_t* session, beacon_payload_t* buffer) {
    if(session == NULL || buffer == NULL)
        return -SN_ERR_NULL;

    //protocol ID information
    buffer->protocol_id  = STARFISHNET_PROTOCOL_ID;
    buffer->protocol_ver = STARFISHNET_PROTOCOL_VERSION;
    //device tree metadata
    buffer->tree_depth      = session->nib.tree_depth;
    buffer->tree_position   = session->nib.tree_position;
    buffer->router_capacity = 0;
    //addressing metadata
    buffer->short_address = session->mib.macShortAddress;
    memcpy(buffer->long_address.ExtendedAddress, session->mib.macIEEEAddress.ExtendedAddress, 8);
    memcpy(buffer->coordinator_address.ExtendedAddress, session->nib.coordinator_address.ExtendedAddress, 8);

    /*TODO:
     * this device's public key
     * network root's public key
     * beacon signature?
     */

    return SN_OK;
}

int do_network_start(SN_Session_t* session, mac_primitive_t* packet, bool isCoordinator) {
    assert(session != NULL);
    assert(packet != NULL);

    if(session == NULL || packet == NULL)
        return -SN_ERR_NULL;

    if(isCoordinator)
        session->mib.macPANId = FIXED_COORDINATOR_ADDRESS;

    //build beacon payload
    beacon_payload_t* proto_beacon = (beacon_payload_t*)session->mib.macBeaconPayload;
    build_beacon_payload(session, proto_beacon); //no need to check error code, it only checks for nulls
    session->mib.macBeaconPayloadLength = sizeof(beacon_payload_t);

    //set beacon payload length
    packet->type = mac_mlme_set_request;
    packet->MLME_SET_request.PIBAttribute         = macBeaconPayloadLength;
    packet->MLME_SET_request.PIBAttributeSize     = 1;
    packet->MLME_SET_request.PIBAttributeValue[0] = session->mib.macBeaconPayloadLength;
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macBeaconPayloadLength_set_confirm);

    //set beacon payload
    packet->type = mac_mlme_set_request;
    packet->MLME_SET_request.PIBAttribute         = macBeaconPayload;
    packet->MLME_SET_request.PIBAttributeSize     = session->mib.macBeaconPayloadLength;
    memcpy(packet->MLME_SET_request.PIBAttributeValue, session->mib.macBeaconPayload, session->mib.macBeaconPayloadLength);
    MAC_CALL(mac_transmit, session->mac_session, packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macBeaconPayloadLength_set_confirm);

    //start beacon transmissions
    packet->type = mac_mlme_start_request;
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

    return SN_OK;
}

//start a new StarfishNet network as coordinator
int SN_Start(SN_Session_t* session, SN_Network_descriptor_t* network);

/* Tune the radio to a StarfishNet network and listen for packets with its PAN ID.
 * Note, this call does not directly cause any packet exchange.
 * Packets may or may not be routable to us until we associate with a parent, at which point
 * routing is guaranteed to work.
 * Remember that naive broadcasts won't be receivable until we do a SA with a neighbor router.
 */
int SN_Join(SN_Session_t* session, SN_Network_descriptor_t* network, bool disable_routing) {
    assert(session != NULL);
    assert(network != NULL);

    mac_primitive_t packet;

    //TODO: reinit SA and node tables. anything else?

    /* Implementation note:
     *
     * The way this should work is: joining without routing just tunes the radio, joining
     * with routing does a MLME_start() so that we broadcast beacons.
     */

    //Fill NIB
    session->nib.tree_depth       = network->routing_tree_depth;
    session->nib.tree_position    = network->routing_tree_position + 1;
    session->nib.tx_retry_limit   = DEFAULT_TX_RETRY_LIMIT;
    session->nib.tx_retry_timeout = DEFAULT_TX_RETRY_TIMEOUT;
    memcpy(session->nib.coordinator_address.ExtendedAddress, network->coordinator_address.ExtendedAddress, sizeof(mac_address_t));
    memcpy(session->nib.parent_address.ExtendedAddress, network->nearest_neighbor_address.ExtendedAddress, sizeof(mac_address_t));

    //update the MIB and PIB
    session->pib.phyCurrentChannel        = network->radio_channel;
    session->mib.macPANId                 = network->pan_id;
    session->mib.macCoordAddrMode         = mac_extended_address;
    session->mib.macCoordShortAddress     = FIXED_COORDINATOR_ADDRESS;
    memcpy(session->mib.macCoordExtendedAddress.ExtendedAddress, network->coordinator_address.ExtendedAddress, 8);
    //... (including setting our short address to the "we don't have a short address" flag value)
    session->mib.macShortAddress          = NO_SHORT_ADDRESS;

    //configure the radio

    //Tune to the right channel
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = phyCurrentChannel;
    packet.MLME_SET_request.PIBAttributeSize     = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = session->pib.phyCurrentChannel;
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)phyCurrentChannel_set_confirm);

    //Set our PAN Id
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macPANId;
    packet.MLME_SET_request.PIBAttributeSize     = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macPANId, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macPANId_set_confirm);

    //Set our coord short address
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macCoordShortAddress;
    packet.MLME_SET_request.PIBAttributeSize     = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macCoordShortAddress, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macCoordShortAddress_set_confirm);

    //Set our coord address
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macCoordExtendedAddress;
    packet.MLME_SET_request.PIBAttributeSize     = 8;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, session->mib.macCoordExtendedAddress.ExtendedAddress, 8);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macCoordExtendedAddress_set_confirm);

    //Then, do some final configuration.

    //Set our short address
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macShortAddress;
    packet.MLME_SET_request.PIBAttributeSize     = 2;
    memcpy(packet.MLME_SET_request.PIBAttributeValue, &session->mib.macShortAddress, 2);
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macShortAddress_set_confirm);

    //Switch on RX_ON_IDLE
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macRxOnWhenIdle;
    packet.MLME_SET_request.PIBAttributeSize     = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = 1;
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macRxOnWhenIdle_set_confirm);
    session->mib.macRxOnWhenIdle                 = 1;

    if(!disable_routing) {
        int ret = do_network_start(session, &packet, 0);
        if(ret != SN_OK) {
            mac_reset_radio(session, &packet);
            return ret;
        }
    }

    //TODO: add relevant addresses to node table

    //And we're done. Setting up a security association with our new parent is deferred until the first packet exchange.
    return SN_OK;
}

//transmit a packet
int SN_Send(SN_Session_t* session, SN_Address_t* dst_addr, uint8_t payload_length, uint8_t* payload, uint8_t packet_handle, uint8_t flags, SN_Security_metadata_t* security) {
    //TODO: flags

    uint8_t max_payload_size = aMaxMACSafePayloadSize;

    if(payload_length > 0) {
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
        if(session->mib.macShortAddress != NO_SHORT_ADDRESS) {;
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
                return -SN_ERR_RESOURCES; //most likely reason is that there wasn't enough space in the target buffer
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
        if(ret <= 0) {
            SN_ErrPrintf("%s(): MCPS_DATA_request() failed with %d. status=SN_ERR_RADIO\n", __FUNCTION__, ret);
            return -SN_ERR_RADIO;
        }
        //TODO: queueing behaviour: queue MCPS_DATA.indication while waiting for MCPS_DATA.confirm or MLME_COMM_STATUS.indication
        //TODO: make sure we're actually waiting for either MCPS_DATA.confirm or MLME_COMM_STATUS.indication
        const uint8_t tx_confirm[] = { mac_mcps_data_confirm, packet_handle, mac_success };
        ret = mac_receive_primitive_exactly(session->mac_session, (mac_primitive_t*)tx_confirm);
        if(ret <= 0) {
            SN_ErrPrintf("%s(): packet tx failed with %d. status=SN_ERR_RADIO\n", __FUNCTION__, ret);
            return -SN_ERR_RADIO;
        }
    }

    SN_InfoPrintf("%s(): status=SN_OK\n", __FUNCTION__);
    return SN_OK;
}

/* scan for StarfishNet networks
 *
 * You get one callback for each network discovered, with the extradata you provided.
 */
int SN_Discover(SN_Session_t* session, uint32_t channel_mask, uint32_t timeout, void (*callback) (SN_Session_t* session, SN_Network_descriptor_t* network, void* extradata), void* extradata) {
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
        return -SN_ERR_INVALID;
    }
    packet.MLME_SCAN_request.ScanDuration     = log2i((timeout * aSymbolsPerSecond_24 / 1000 - aBaseSuperframeDuration) / aBaseSuperframeDuration);
    if(packet.MLME_SCAN_request.ScanDuration > 14) {
        SN_WarnPrintf("%s(): ScanDuration %u is too high, capping.\n", __FUNCTION__, packet.MLME_SCAN_request.ScanDuration);
        packet.MLME_SCAN_request.ScanDuration = 14;
    }

    //initiate the scan
    SN_InfoPrintf("%s(): initiating scan with ScanDuration=%u\n", __FUNCTION__, packet.MLME_SCAN_request.ScanDuration);
    MAC_CALL(mac_transmit, session->mac_session, &packet);

    SN_Network_descriptor_t ndesc;

    //During a scan, we get a MLME-BEACON.indication for each received beacon.
    //MLME-SCAN.confirm is received when a scan finishes.
    while(1) {
        //receive a primitive
        MAC_CALL(mac_receive, session->mac_session, &packet);

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

int SN_Request_address( //request a short address from a neighboring router. implicitly ASSOCIATES and requests in plaintext. must have already JOINed. the router may refuse, if it cannot fulfil the request
    SN_Session_t* session,
    mac_address_t router
);
int SN_Release_address(SN_Session_t* session); //release our short address

int SN_Associate( //associate with another StarfishNet node
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    SN_Security_metadata_t* security,
    bool initiator //1 if we're initiating, 0 if we're responding
);
int SN_Dissociate( //dissociate from a node. if we have one of its short addresses, it is implicitly invalidated (and thus we stop using it); this may lead to follow-on address revocations down the tree
    SN_Session_t* session,
    SN_Address_t* dst_addr,
    bool initiator //1 if we're initiating, 0 if we're responding
);

//int SN_Poll_parent(SN_Session_t* session); //does MLME-SYNC.request, and also MLME_POLL.request
//when implemented, uses MLME-SYNC/MLME-POLL to poll our parent for pending messages

//copies the configuration out of session into the space provided. anything but session can be NULL
int SN_Get_configuration(SN_Session_t* session, SN_Nib_t* nib, mac_mib_t* mib, mac_pib_t* pib) {
    //Assumption: config is kept current!

    if(session == NULL)
        return -SN_ERR_NULL;

    if(nib != NULL)
        memcpy(nib, &session->nib, sizeof(*nib));

    if(mib != NULL) {
        //TODO: load macDSN
        memcpy(mib, &session->mib, sizeof(*mib));
    }

    if(pib != NULL)
        memcpy(pib, &session->pib, sizeof(*pib));

    return SN_OK;
}
//copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
int SN_Set_configuration(SN_Session_t* session, SN_Nib_t* nib, mac_mib_t* mib, mac_pib_t* pib) {
    //Assumption: config is kept current!

    if(session == NULL)
        return -SN_ERR_NULL;

    //TODO: for each information base, check each member, and set the ones that have changed
    //      (obviously, ignoring the ones we're not supposed to set)

    return -SN_ERR_UNIMPLEMENTED;
}

//other network-layer driver functions
int SN_Init(SN_Session_t* session, char* params) {
    assert(session != NULL);

    //allocate some stack space
    SN_Session_t protosession;
    STRUCTCLEAR(protosession);

    //init the mac layer
    protosession.mac_session = mac_init(params);
    assert(protosession.mac_session.meta != 0); //this covers the fd case as well
    if(protosession.mac_session.meta == 0) //this covers the fd case as well
        return -SN_ERR_RADIO;

    //reset the radio
    mac_primitive_t packet;
    int ret = mac_reset_radio(session, &packet);
    if(ret != SN_OK)
        return ret;

    //make sure macAssociationPermit is off
    packet.type = mac_mlme_set_request;
    packet.MLME_SET_request.PIBAttribute         = macAssociationPermit;
    packet.MLME_SET_request.PIBAttributeSize     = 1;
    packet.MLME_SET_request.PIBAttributeValue[0] = 0;
    MAC_CALL(mac_transmit, session->mac_session, &packet);
    MAC_CALL(mac_receive_primitive_exactly, session->mac_session, (mac_primitive_t*)macAssociationPermit_set_confirm);
    session->mib.macAssociationPermit            = 0;

    //set up my basic linkedlist SA tracker
    protosession.sas = NULL;

    //return results
    *session = protosession;

    return SN_OK;
}
void SN_Destroy(SN_Session_t* session) { //bring down this session, resetting the radio in the process
    mac_primitive_t packet;

    /*TODO: disconnect
     * revoke all children's short-address allocations
     * release my short-address allocation(s)
     * terminate all SAs
     */

    //clean out the node table
    SN_Table_clear();

    //reset the radio
    mac_reset_radio(session, &packet);

    //close up the MAC-layer session
    mac_destroy(session->mac_session);

    //clean up I/O buffers
    STRUCTCLEAR(*session);
}

int SN_Receive(SN_Session_t* session, SN_Ops_t* handlers);

