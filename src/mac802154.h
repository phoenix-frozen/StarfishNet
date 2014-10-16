/*
 * Integration MAC interface definitions, types and function prototypes.
 *
 * Written by Jon Beniston <jbeniston@integration.com>
 *
 * Copyright 2005 Integration Associates Inc.  All rights reserved.
 *
 * LIMITED USE LICENSE.  By using this software, the user agrees to the terms
 * of the following license.  If the user does not agree to these terms, then
 * this software should be returned within 30 days and a full refund of the
 * purchase price or license fee will provided.  Integration Associates
 * hereby grants a license to the user on the following terms and conditions:
 * The user may use, copy, modify, revise, translate, abridge, condense, expand,
 * collect, compile, link, recast, distribute, transform or adapt this software
 * solely in connection with the development of products incorporating
 * integrated circuits sold by Integration Associates.  Any other use for any
 * other purpose is expressly prohibited with the prior written consent of
 * Integration Associates.
 *
 * Any copy or modification made must satisfy the following conditions:
 *
 * 1. Both the copyright notice and this permission notice appear in all copies
 * of the software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * 2. All copies of the software shall contain the following acknowledgement:
 * "Portions of this software are used under license from Integration Associates
 * Inc. and are copyrighted."
 *
 * 3  Neither the name of Integration Associates Inc. nor any of its
 * subsidiaries may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY "AS IS" AND ALL WARRANTIES OF ANY KIND,
 * INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR USE,
 * ARE EXPRESSLY DISCLAIMED.  THE DEVELOPER SHALL NOT BE LIABLE FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.  THIS SOFTWARE MAY NOT
 * BE USED IN PRODUCTS INTENDED FOR USE IN IMPLANTATION OR OTHER DIRECT LIFE
 * SUPPORT APPLICATIONS WHERE MALFUNCTION MAY RESULT IN THE DIRECT PHYSICAL
 * HARM OR INJURY TO PERSONS.  ALL SUCH IS USE IS EXPRESSLY PROHIBITED.
 *
 */

#ifndef __MAC802154_H__
#define __MAC802154_H__

#include "mac802154_types.h"
#include <sys/time.h>

/* MCPS-DATA.request TxOptions flags */
#define MAC_TX_OPTION_ACKNOWLEDGED              0x01
#define MAC_TX_OPTION_GTS                       0x02
#define MAC_TX_OPTION_INDIRECT                  0x04
#define MAC_TX_OPTION_SECURITY_ENABLED          0x08

/* MLME-ASSOCIATE.request CapabilityInformation flags */
#define MAC_CAPABILITY_ALT_PAN_COORDINATOR      0x01
#define MAC_CAPABILITY_DEVICE_TYPE_FFD          0x02
#define MAC_CAPABILITY_DEVICE_TYPE_RFD          0x00
#define MAC_CAPABILITY_MAINS_POWERED            0x04
#define MAC_CAPABILITY_RX_ON_WHEN_IDLE          0x08
#define MAC_CAPABILITY_SECURITY                 0x40
#define MAC_CAPABILITY_ALLOCATE_ADDRESS         0x80

/* MLME-GTS.request GTSCharacteristics flags */
#define MAC_GTS_RECEIVE                         0x10
#define MAC_GTS_TRANSMIT                        0x00
#define MAC_GTS_ALLOCATE                        0x20
#define MAC_GTS_DEALLOCATE                      0x00
//TODO: are these constant values right?

/* Associations status' */
enum mac_association_status {
    mac_association_successful = 0x00,
    mac_pan_at_capacity        = 0x01,
    mac_pan_access_denied      = 0x02,
};
typedef uint8_t mac_association_status_t;

/* Disassociation reasons */
enum mac_disassociate_reason {
    mac_coordinator_disassociate = 0x01,
    mac_device_disassociate      = 0x02,
};
typedef uint8_t mac_disassociate_reason_t;

/* Scan types */
enum mac_scan_type {
    mac_energy_detect_scan,
    mac_active_scan,
    mac_passive_scan,
    mac_orphan_scan,
};
typedef uint8_t mac_scan_type_t;

/* MAC status */
enum mac_status {
    mac_success                = 0x00,
    mac_beacon_lost            = 0xe0,
    mac_channel_access_failure = 0xe1,
    mac_denied                 = 0xe2,
    mac_disable_trx_failure    = 0xe3,
    mac_failed_security_check  = 0xe4,
    mac_frame_too_long         = 0xe5,
    mac_invalid_gts            = 0xe6,
    mac_invalid_handle         = 0xe7,
    mac_invalid_parameter      = 0xe8,
    mac_no_ack                 = 0xe9,
    mac_no_beacon              = 0xea,
    mac_no_data                = 0xeb,
    mac_no_short_address       = 0xec,
    mac_out_of_cap             = 0xed,
    mac_pan_id_conflict        = 0xee,
    mac_realignment            = 0xef,
    mac_transaction_expired    = 0xf0,
    mac_transaction_overflow   = 0xf1,
    mac_tx_active              = 0xf2,
    mac_unavailable_key        = 0xf3,
    mac_unsupported_attribute  = 0xf4,
    mac_out_of_spec            = 0xf5,
    mac_impossible_request     = 0xf7,
};
typedef uint8_t mac_status_t;

/* PHY PIB attributes */
enum phy_pib_attribute {
    phyCurrentChannel,
    phyChannelsSupported,
    phyTransmitPower,
    phyCCAMode,
};
typedef uint8_t phy_pib_attribute_t;

/* MAC PIB attributes */
enum mac_pib_attribute {
    macAckWaitDuration               = 0x40,
    macAssociationPermit             = 0x41,
    macAutoRequest                   = 0x42,
    macBattLifeExt                   = 0x43,
    macBattLifeExtPeriods            = 0x44,
    macBeaconPayload                 = 0x45,
    macBeaconPayloadLength           = 0x46,
    macBeaconOrder                   = 0x47,
    macBeaconTxTime                  = 0x48,
    macBSN                           = 0x49,
    macCoordExtendedAddress          = 0x4a,
    macCoordShortAddress             = 0x4b,
    macDSN                           = 0x4c,
    macGTSPermit                     = 0x4d,
    macMaxCSMABackoffs               = 0x4e,
    macMinBE                         = 0x4f,
    macPANId                         = 0x50,
    macPromiscuousMode               = 0x51,
    macRxOnWhenIdle                  = 0x52,
    macShortAddress                  = 0x53,
    macSuperframeOrder               = 0x54,
    macTransactionPersistenceTime    = 0x55,
    macIEEEAddress                   = 0x6f, /* Integration extension */
    macACLEntryDescriptorSet         = 0x70,
    macACLEntryDescriptorSetSize     = 0x71,
    macDefaultSecurity               = 0x72,
    macDefaultSecurityMaterialLength = 0x73,
    macDefaultSecurityMaterial       = 0x74,
    macDefaultSecuritySuite          = 0x75,
    macSecurityMode                  = 0x76,
    macACLEntryDescriptorNumber      = 0x7f,
};
typedef uint8_t mac_pib_attribute_t;

/* ACL Entry */
enum mac_acl_entry {
    mac_acl_none,
    mac_acl_aes_ctr,
    mac_acl_aes_ccm_128,
    mac_acl_aes_ccm_64,
    mac_acl_aes_ccm_32,
    mac_acl_aes_cbc_mac_128,
    mac_acl_aes_cbc_mac_64,
    mac_acl_aes_cbc_mac_32,
    mac_acl_not_found
};
typedef uint8_t mac_acl_entry_t;

/* MAC Primitive IDs */
enum mac_primitive_type {
    mac_mcps_data_request              = 0x40,
    mac_mcps_data_confirm              = 0x41,
    mac_mcps_data_indication           = 0x42,
    mac_mcps_purge_request             = 0x43,
    mac_mcps_purge_confirm             = 0x44,
    mac_mlme_associate_request         = 0x45,
    mac_mlme_associate_confirm         = 0x46,
    mac_mlme_associate_indication      = 0x47,
    mac_mlme_associate_response        = 0x48,
    mac_mlme_disassociate_request      = 0x49,
    mac_mlme_disassociate_confirm      = 0x4a,
    mac_mlme_disassociate_indication   = 0x4b,
    mac_mlme_beacon_notify_indication  = 0x4c,
    mac_mlme_get_request               = 0x4d,
    mac_mlme_get_confirm               = 0x4e,
    mac_mlme_gts_request               = 0x4f,
    mac_mlme_gts_confirm               = 0x50,
    mac_mlme_gts_indication            = 0x51,
    mac_mlme_orphan_indication         = 0x52,
    mac_mlme_orphan_response           = 0x53,
    mac_mlme_reset_request             = 0x54,
    mac_mlme_reset_confirm             = 0x55,
    mac_mlme_rx_enable_request         = 0x56,
    mac_mlme_rx_enable_confirm         = 0x57,
    mac_mlme_scan_request              = 0x58,
    mac_mlme_scan_confirm              = 0x59,
    mac_mlme_comm_status_indication    = 0x5a,
    mac_mlme_set_request               = 0x5b,
    mac_mlme_set_confirm               = 0x5c,
    mac_mlme_start_request             = 0x5d,
    mac_mlme_start_confirm             = 0x5e,
    mac_mlme_sync_request              = 0x5f,
    mac_mlme_sync_loss_indication      = 0x60,
    mac_mlme_poll_request              = 0x61,
    mac_mlme_poll_confirm              = 0x62,
    mac_mlme_protocol_error_indication = 0xff,
};
typedef uint8_t mac_primitive_type_t;

//TODO: what's the biggest size mac_primitive_t can actually be?
//TODO: some kind of poll()-based isAPacketWaiting() call
typedef union mac_primitive {
    struct __attribute__((packed)) {
        mac_primitive_type_t type;
        union {
            struct MCPS_DATA_indication {
                mac_pan_id_t    SrcPANId;
                mac_address_t   SrcAddr;
                mac_address_mode_t SrcAddrMode;
                mac_pan_id_t    DstPANId;
                mac_address_t   DstAddr;
                mac_address_mode_t DstAddrMode;
                uint8_t         msduLength;
                uint8_t         mpduLinkQuality;
                uint8_t         SecurityUse;
                mac_acl_entry_t ACLEntry;
                uint8_t         msdu[aMaxMACPayloadSize];
            } MCPS_DATA_indication;

            struct MCPS_DATA_request {
                mac_pan_id_t  SrcPANId;
                mac_address_t SrcAddr;
                mac_address_mode_t SrcAddrMode;
                mac_pan_id_t  DstPANId;
                mac_address_t DstAddr;
                mac_address_mode_t DstAddrMode;
                uint8_t       msduLength;
                uint8_t       msduHandle;
                uint8_t       TxOptions;
                uint8_t       padding;
                uint8_t       msdu[aMaxMACPayloadSize];
            } MCPS_DATA_request;

            struct MCPS_DATA_confirm {
                uint8_t      msduHandle;
                mac_status_t status;
            } MCPS_DATA_confirm;

            struct MCPS_PURGE_request {
                uint8_t msduHandle;
            } MCPS_PURGE_request;

            struct MCPS_PURGE_confirm {
                uint8_t      msduHandle;
                mac_status_t status;
            } MCPS_PURGE_confirm;

            struct MLME_COMM_STATUS_indication {
                mac_pan_id_t  PANId;
                mac_address_mode_t SrcAddrMode;
                mac_address_t SrcAddr;
                mac_address_mode_t DstAddrMode;
                mac_address_t DstAddr;
                mac_status_t  status;
            } MLME_COMM_STATUS_indication;

            struct MLME_ASSOCIATE_indication {
                mac_address_t   DeviceAddress;
                uint8_t         CapabilityInformation;
                struct {
                    uint8_t     SecurityUse :1;
                    uint8_t     ACLEntry    :4;
                    uint8_t                 :3;
                };
            } MLME_ASSOCIATE_indication;

            struct MLME_ASSOCIATE_response {
                mac_address_t            DeviceAddress;
                uint16_t                 AssocShortAddress;
                mac_association_status_t Status;
                uint8_t                  SecurityEnable;
            } MLME_ASSOCIATE_response;

            struct MLME_ASSOCIATE_request {
                mac_pan_id_t  CoordPANId;
                uint8_t       LogicalChannel;
                mac_address_mode_t CoordAddrMode;
                mac_address_t CoordAddr;
                uint8_t       CapabilityInfo;
                uint8_t       SecurityEnable;
            } MLME_ASSOCIATE_request;

            struct __attribute__((packed)) MLME_ASSOCIATE_confirm {
                uint16_t     AssocShortAddress;
                mac_status_t status;
            } MLME_ASSOCIATE_confirm;

            struct MLME_DISASSOCIATE_indication {
                mac_address_t             DeviceAddress;
                mac_disassociate_reason_t DisassociateReason;
                struct {
                    uint8_t     SecurityUse :1;
                    uint8_t     ACLEntry    :4;
                    uint8_t                 :3;
                };
            } MLME_DISASSOCIATE_indication;

            struct MLME_DISASSOCIATE_request {
                mac_address_t             DeviceAddress;
                mac_disassociate_reason_t DisassociateReason;
                uint8_t                   SecurityEnable;
            } MLME_DISASSOCIATE_request;

            struct MLME_DISASSOCIATE_confirm {
                mac_status_t status;
            } MLME_DISASSOCIATE_confirm;

            struct __attribute__((packed)) MLME_ORPHAN_indication {
                mac_address_t   OrphanAddress;
                struct {
                    uint8_t     SecurityUse :1;
                    uint8_t     ACLEntry    :4;
                    uint8_t                 :3;
                };
            } MLME_ORPHAN_indication;

            struct __attribute__((packed)) MLME_ORPHAN_response {
                mac_address_t OrphanAddress;
                uint16_t      ShortAddress;
                struct {
                    uint8_t   AssociatedMember :1;
                    uint8_t   SecurityEnable   :1;
                    uint8_t                    :6;
                };
            } MLME_ORPHAN_response;

            struct MLME_GET_request {
                mac_pib_attribute_t PIBAttribute;
            } MLME_GET_request;

            struct __attribute__((packed)) MLME_GET_confirm {
                mac_status_t        status;
                mac_pib_attribute_t PIBAttribute;
                uint8_t             PIBAttributeValue[aMaxBeaconPayloadSize];
            } MLME_GET_confirm;

            struct MLME_SET_request {
                mac_pib_attribute_t PIBAttribute;
                uint8_t             PIBAttributeSize;
                uint8_t             PIBAttributeValue[aMaxBeaconPayloadSize];
            } MLME_SET_request;

            struct __attribute__((packed)) MLME_SET_confirm {
                mac_status_t        status;
                mac_pib_attribute_t PIBAttribute;
            } MLME_SET_confirm;

            struct MLME_RESET_request {
                uint8_t SetDefaultPIB;
            } MLME_RESET_request;

            struct MLME_RESET_confirm {
                mac_status_t status;
            } MLME_RESET_confirm;

            struct MLME_RX_ENABLE_request {
                uint8_t  DeferPermit;
                uint32_t RxOnTime;
                uint32_t RxOnDuration;
            } MLME_RX_ENABLE_request;

            struct MLME_RX_ENABLE_confirm {
                mac_status_t status;
            } MLME_RX_ENABLE_confirm;

            struct __attribute__((packed)) MLME_SCAN_request {
                mac_scan_type_t ScanType;
                uint32_t        ScanChannels;
                uint8_t         ScanDuration;
            } MLME_SCAN_request;

            struct __attribute__((packed)) MLME_SCAN_confirm {
                mac_status_t         status;
                mac_scan_type_t      ScanType;
                uint32_t             UnscannedChannels;
                uint8_t              ResultListSize;
                union {
                    uint8_t              EnergyDetectList[32]; //channel bitfield is 32 wide, so it can't be bigger than that
                    mac_pan_descriptor_t PANDescriptorList[aMaxPHYPacketSize / (sizeof(mac_pan_descriptor_t) - 6 /*sizeof(MAC address) - sizeof(short address)*/)]; //safe upper bound
                };
            } MLME_SCAN_confirm;

            struct __attribute__((packed)) MLME_START_request {
                mac_pan_id_t PANId;
                uint8_t      LogicalChannel;
                struct {
                    uint8_t      BeaconOrder     :4;
                    uint8_t      SuperframeOrder :4;
                };
                struct {
                    uint8_t         PANCoordinator       :1;
                    uint8_t         BatteryLifeExtension :1;
                    uint8_t         CoordRealignment     :1;
                    uint8_t         SecurityEnable       :1;
                    uint8_t                              :4;
                };
            } MLME_START_request;

            struct MLME_START_confirm {
                mac_status_t status;
            } MLME_START_confirm;

            struct MLME_POLL_request {
                mac_address_mode_t CoordAddrMode;
                mac_pan_id_t       CoordPANId;
                mac_address_t      CoordAddress;
                uint8_t            SecurityEnable;
            } MLME_POLL_request;

            struct MLME_POLL_confirm {
                mac_status_t status;
            } MLME_POLL_confirm;

            struct MLME_SYNC_request {
                uint8_t LogicalChannel;
                uint8_t TrackBeacon;
            } MLME_SYNC_request;

            struct MLME_SYNC_LOSS_indication {
                mac_status_t LossReason;
            } MLME_SYNC_LOSS_indication;

            struct MLME_BEACON_NOTIFY_indication {
                uint8_t              BSN;
                mac_pan_descriptor_t PANDescriptor;
                union {
                    struct __attribute__((packed)) {
                        uint8_t        Short    :3;
                        uint8_t                 :1;
                        uint8_t        Extended :3;
                        uint8_t                 :1;
                    };
                    uint8_t            raw;
                }                    PendAddrSpec;
                struct {
                    uint16_t           Short   [7]; //because their length fields are 3 bits in size
                    mac_address_t      Extended[7];
                }                    AddrList;
                uint8_t              sduLength;
                uint8_t              sdu[aMaxBeaconPayloadSize];
            } MLME_BEACON_NOTIFY_indication;

            struct MLME_GTS_indication {
                uint16_t        DevAddress;
                uint8_t         GTSCharacteristics;
                struct {
                    uint8_t     SecurityUse :1;
                    uint8_t     ACLEntry    :4;
                    uint8_t                 :3;
                };
            } MLME_GTS_indication;

            struct MLME_GTS_request {
                uint8_t GTSCharacteristics;
                uint8_t SecurityEnable;
            } MLME_GTS_request;

            struct MLME_GTS_confirm {
                uint8_t      GTSCharacteristics;
                mac_status_t status;
            } MLME_GTS_confirm;

            struct MLME_PROTOCOL_ERROR_indication {
                mac_status_t status;
            } MLME_PROTOCOL_ERROR_indication;
        };
    };
    uint8_t raw_data[aMaxPHYPacketSize * 2]; //safe upper bound
} mac_primitive_t;

const mac_acl_entry_descriptor_t mac_default_ACLEntry;
const mac_mib_t mac_default_MIB;

mac_session_handle_t mac_init(char* params);
void                 mac_destroy(mac_session_handle_t session);

/*
 * DESCRIPTION
 *  Transmit a primitive.
 *
 * RETURNS
 *  n - Size of transmitted primitive.
 *  0 - If primitive cannot be decoded.
 *  -1 - If an error occurs while trying to write to the radio.
 */
int mac_transmit(mac_session_handle_t session, mac_primitive_t* primitive);

/*
 * DESCRIPTION
 *  Receive a primitive.
 *
 * RETURNS
 *  n - Size of received primitive.
 *  0 - If an error occurs while trying to read the primitive.
 *  -n - -size of received primitive, if primitive is received but cannot be decoded. (The data structure will be filled with the raw bytes.)
 */
int mac_receive(mac_session_handle_t session, mac_primitive_t* primitive);
int mac_receive_timeout(mac_session_handle_t session, mac_primitive_t* primitive, struct timeval* timeout);

/*
 * DESCRIPTION
 *  Receive a primitive of the given type, dropping any others received in between.
 *
 * RETURNS
 *  n - Size of received primitive.
 *  0 - If an error occurs while trying to read the primitive.
 *  -1 - If an error occurs while trying to read the primitive.
 */
int mac_receive_primitive_type(mac_session_handle_t session, mac_primitive_t* primitive, mac_primitive_type_t primitive_type);

/*
 * DESCRIPTION
 *  Receive a primitive of one of the given types, dropping any others received in between.
 *
 * RETURNS
 *  n - Size of received primitive.
 *  0 - If an error occurs while trying to read the primitive.
 *  -1 - If an error occurs while trying to read the primitive.
 */
int mac_receive_primitive_types(mac_session_handle_t session, mac_primitive_t* primitive, const mac_primitive_type_t* primitive_types, unsigned int primitive_type_count);

/*
 * DESCRIPTION
 *  Receive a primitive, and compare with the one given.
 *
 * RETURNS
 *  1 - Received primitive matches argument.
 *  0 - Received primitive does not match argument (or received primitive couldn't be decoded).
 *  -1 - If an error occurs while trying to read the primitive.
 */
int mac_receive_primitive_exactly(mac_session_handle_t session, const mac_primitive_t* primitive); //receive a primtive from the radio, and make sure it looks like the one given

/*
 * DESCRIPTION
 *  Similar to sprintf, except it provides the following MAC specific format
 *  specifiers:
 *
 *   %d - Integer
 *   %x - Hexidecimal
 *   %a - Address mode, PAN Id, Address
 *   %q - Address mode, Address
 *   %s - Short address
 *   %e - Extended address
 *   %b - Boolean
 *   %A - Association status
 *   %D - Diassociate reason
 *   %S - Scan type
 *   %p - PIB attribute
 *   %P - PIB attribute, value
 *   %g - GTS characteristics
 *   %t - TX options
 *   %m - MSDU length, MSDU
 *   %R - Status
 *   %c - ACL entry
 *   %n - PAN descriptor
 *
 * RETURNS
 *  void
 */
void mac_sprintf(char *buffer, const char *format, ...);

mac_pib_attribute_t mac_string_to_value     (const char*         string);
const char*         mac_value_to_string     (mac_pib_attribute_t value);
uint8_t             mac_pib_attribute_length(mac_pib_attribute_t PIBAttribute);

#endif /* __MAC802154_H__ */
