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
 * “Portions of this software are used under license from Integration Associates
 * Inc. and are copyrighted.”
 *
 * 3  Neither the name of Integration Associates Inc. nor any of its
 * subsidiaries may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY “AS IS” AND ALL WARRANTIES OF ANY KIND,
 * INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR USE,
 * ARE EXPRESSLY DISCLAIMED.  THE DEVELOPER SHALL NOT BE LIABLE FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.  THIS SOFTWARE MAY NOT
 * BE USED IN PRODUCTS INTENDED FOR USE IN IMPLANTATION OR OTHER DIRECT LIFE
 * SUPPORT APPLICATIONS WHERE MALFUNCTION MAY RESULT IN THE DIRECT PHYSICAL
 * HARM OR INJURY TO PERSONS.  ALL SUCH IS USE IS EXPRESSLY PROHIBITED.
 *
 */

#ifndef MAC_H
#define MAC_H

#include <stdint.h>
#include <stdbool.h>

/* MAC constants */
#define aMaxPHYPacketSize                       127
#define aMaxFrameOverhead                       25
#define aMaxMACFrameSize                        (aMaxPHYPacketSize-aMaxFrameOverhead)

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

typedef union {
	int fd;
	void* meta;
} mac_session_handle_t;

/* Addressing modes */
typedef enum {
	mac_no_address = 0x0,
	mac_short_address = 0x2,
	mac_extended_address = 0x3
} mac_address_mode_t;

/* Address */
typedef union {
	uint16_t ShortAddress;
	uint8_t ExtendedAddress[8];
} mac_address_t;

/* Associations status' */
typedef enum {
	mac_association_successful = 0x00,
	mac_pan_at_capacity = 0x01,
	mac_pan_access_denied = 0x02
} mac_association_status_t;

/* Disassociation reasons */
typedef enum {
	mac_coordinator_disassociate = 0x01,
	mac_device_disassociate = 0x02
} mac_disassociate_reason_t;

/* Scan types */
typedef enum {
	mac_energy_detect_scan,
	mac_active_scan,
	mac_passive_scan,
	mac_orphan_scan
} mac_scan_type_t;

/* MAC status */
typedef enum {
	mac_success = 0x00,
	mac_beacon_lost = 0xe0,
	mac_channel_access_failure = 0xe1,
	mac_denied = 0xe2,
	mac_disable_trx_failure = 0xe3,
	mac_failed_security_check = 0xe4,
	mac_frame_too_long = 0xe5,
	mac_invalid_gts = 0xe6,
	mac_invalid_handle = 0xe7,
	mac_invalid_parameter = 0xe8,
	mac_no_ack = 0xe9,
	mac_no_beacon = 0xea,
	mac_no_data = 0xeb,
	mac_no_short_address = 0xec,
	mac_out_of_cap = 0xed,
	mac_pan_id_conflict = 0xee,
	mac_realignment = 0xef,
	mac_transaction_expired = 0xf0,
	mac_transaction_overflow = 0xf1,
	mac_tx_active = 0xf2,
	mac_unavailable_key = 0xf3,
	mac_unsupported_attribute = 0xf4
} mac_status_t;

/* PHY PIB attributes */
typedef enum {
	phyCurrentChannel,
	phyChannelsSupported,
	phyTransmitPower,
	phyCCAMode
} phy_pib_attribute_t;

/* MAC PIB attributes */
typedef enum {
	macAckWaitDuration = 0x40,
	macAssociationPermit = 0x41,
	macAutoRequest = 0x42,
	macBattLifeExt = 0x43,
	macBattLifeExtPeriods = 0x44,
	macBeaconPayload = 0x45,
	macBeaconPayloadLength = 0x46,
	macBeaconOrder = 0x47,
	macBeaconTxTime = 0x48,
	macBSN = 0x49,
	macCoordExtendedAddress = 0x4a,
	macCoordShortAddress = 0x4b,
	macDSN = 0x4c,
	macGTSPermit = 0x4d,
	macMaxCSMABackoffs = 0x4e,
	macMinBE = 0x4f,
	macPANId = 0x50,
	macPromiscuousMode = 0x51,
	macRxOnWhenIdle = 0x52,
	macShortAddress = 0x53,
	macSuperframeOrder = 0x54,
	macTransactionPersistenceTime = 0x55,
	macIEEEAddress = 0x6f,                          /* Integration extension */
	macACLEntryDescriptorSet = 0x70,
	macACLEntryDescriptorSetSize = 0x71,
	macDefaultSecurity = 0x72,
	macDefaultSecurityMaterialLength = 0x73,
	macDefaultSecurityMaterial = 0x74,
	macDefaultSecuritySuite = 0x75,
	macSecurityMode = 0x76
} mac_pib_attribute_t;

/* ACL Entry */
typedef enum {
	mac_acl_none,
	mac_acl_aes_ctr,
	mac_acl_aes_ccm_128,
	mac_acl_aes_ccm_64,
	mac_acl_aes_ccm_32,
	mac_acl_aes_cbc_mac_128,
	mac_acl_aes_cbc_mac_64,
	mac_acl_aes_cbc_mac_32,
	mac_acl_not_found
} mac_acl_entry_t;

/* PAN Identifier */
typedef uint16_t mac_pan_id_t;

/* PAN descriptor */
typedef struct {
	mac_address_mode_t CoordAddrMode;
	mac_pan_id_t CoordPANId;
	mac_address_t CoordAddress;
	uint8_t LogicalChannel;
	uint16_t SuperframeSpec;
	_Bool GTSPermit;
	uint8_t LinkQuality;
	uint32_t TimeStamp;
	_Bool SecurityUse;
	mac_acl_entry_t ACLEntry;
	_Bool SecurityFailure;
} mac_pan_descriptor_t;

/* MAC Primitive IDs */
typedef enum {
	mac_mcps_data_request = 0x40,
	mac_mcps_data_confirm = 0x41,
	mac_mcps_data_indication = 0x42,
	mac_mcps_purge_request = 0x43,
	mac_mcps_purge_confirm	= 0x44,
	mac_mlme_associate_request = 0x45,
	mac_mlme_associate_confirm = 0x46,
	mac_mlme_associate_indication = 0x47,
	mac_mlme_associate_response = 0x48,
	mac_mlme_disassociate_request = 0x49,
	mac_mlme_disassociate_confirm = 0x4a,
	mac_mlme_disassociate_indication = 0x4b,
	mac_mlme_beacon_notify_indication = 0x4c,
	mac_mlme_get_request = 0x4d,
	mac_mlme_get_confirm = 0x4e,
	mac_mlme_gts_request = 0x4f,
	mac_mlme_gts_confirm = 0x50,
	mac_mlme_gts_indication	= 0x51,
	mac_mlme_orphan_indication = 0x52,
	mac_mlme_orphan_response = 0x53,
	mac_mlme_reset_request = 0x54,
	mac_mlme_reset_confirm = 0x55,
	mac_mlme_rx_enable_request = 0x56,
	mac_mlme_rx_enable_confirm = 0x57,
	mac_mlme_scan_request = 0x58,
	mac_mlme_scan_confirm = 0x59,
	mac_mlme_comm_status_indication	= 0x5a,
	mac_mlme_set_request = 0x5b,
	mac_mlme_set_confirm = 0x5c,
	mac_mlme_start_request = 0x5d,
	mac_mlme_start_confirm = 0x5e,
	mac_mlme_sync_request = 0x5f,
	mac_mlme_sync_loss_indication = 0x60,
	mac_mlme_poll_request = 0x61,
	mac_mlme_poll_confirm = 0x62,
} mac_primitive_t;

/* Primitive callback function pointers. */
typedef struct {
	int (*MCPS_DATA_confirm) (
			mac_session_handle_t session,
			uint8_t msduHandle,
			mac_status_t status
			);
	int (*MCPS_DATA_indication) (
			mac_session_handle_t session,
			mac_address_mode_t SrcAddrMode,
			mac_pan_id_t SrcPANId,
			mac_address_t *SrcAddr,
			mac_address_mode_t DstAddrMode,
			mac_pan_id_t DstPANId,
			mac_address_t *DstAddr,
			uint8_t msduLength,
			uint8_t *msdu,
			uint8_t mpduLinkQuality,
			_Bool SecurityUse,
			mac_acl_entry_t ACLEntry
			);
	int (*MCPS_PURGE_confirm) (
			mac_session_handle_t session,
			uint8_t msduHandle,
			mac_status_t status
			);
	int (*MLME_ASSOCIATE_indication) (
			mac_session_handle_t session,
			uint8_t *DeviceAddress,
			uint8_t CapabilityInformation,
			_Bool SecurityUse,
			mac_acl_entry_t ACLEntry
			);
	int (*MLME_ASSOCIATE_confirm) (
			mac_session_handle_t session,
			uint16_t AssocShortAddress,
			mac_status_t status
			);
	int (*MLME_DISASSOCIATE_indication) (
			mac_session_handle_t session,
			uint8_t *DeviceAddress,
			mac_disassociate_reason_t DisassociateReason,
			_Bool SecurityUse,
			mac_acl_entry_t ACLEntry
			);
	int (*MLME_DISASSOCIATE_confirm) (
			mac_session_handle_t session,
			mac_status_t status
			);
	int (*MLME_BEACON_NOTIFY_indication) (
			mac_session_handle_t session,
			uint8_t BSN,
			mac_pan_descriptor_t *PANDescriptor,
			uint8_t PendAddrSpec,
			uint8_t *AddrList,
			uint8_t sduLength,
			uint8_t *sdu
			);
	int (*MLME_GET_confirm) (
			mac_session_handle_t session,
			mac_status_t status,
			mac_pib_attribute_t PIBAttribute,
			uint8_t *PIBAttributeValue
			);
	int (*MLME_GTS_confirm) (
			mac_session_handle_t session,
			uint8_t GTSCharacteristics,
			mac_status_t status
			);
	int (*MLME_GTS_indication) (
			mac_session_handle_t session,
			uint16_t DevAddress,
			uint8_t GTSCharacteristics,
			_Bool SecurityUse,
			mac_acl_entry_t ACLEntry
			);
	int (*MLME_ORPHAN_indication) (
			mac_session_handle_t session,
			uint8_t *OrphanAddress,
			_Bool SecurityUse,
			mac_acl_entry_t ACLEntry
			);
	int (*MLME_RESET_confirm) (
			mac_session_handle_t session,
			mac_status_t status
			);
	int (*MLME_RX_ENABLE_confirm) (
			mac_session_handle_t session,
			mac_status_t status
			);
	int (*MLME_SCAN_confirm) (
			mac_session_handle_t session,
			mac_status_t status,
			mac_scan_type_t ScanType,
			uint32_t UnscannedChannels,
			uint8_t ResultListSize,
			uint8_t *EnergyDetectList,
			mac_pan_descriptor_t *PANDescriptorList
			);
	int (*MLME_COMM_STATUS_indication) (
			mac_session_handle_t session,
			mac_pan_id_t PANId,
			mac_address_mode_t SrcAddrMode,
			mac_address_t *SrcAddr,
			mac_address_mode_t DstAddrMode,
			mac_address_t *DstAddr,
			mac_status_t status
			);
	int (*MLME_SET_confirm) (
			mac_session_handle_t session,
			mac_status_t status,
			mac_pib_attribute_t PIBAttribute
			);
	int (*MLME_START_confirm) (
			mac_session_handle_t session,
			mac_status_t status
			);
	int (*MLME_SYNC_LOSS_indication) (
			mac_session_handle_t session,
			mac_status_t LossReason
			);
	int (*MLME_POLL_confirm) (
			mac_session_handle_t session,
			mac_status_t status
			);
	int (*unknown_primitive) (
			mac_session_handle_t session,
			uint8_t primitive,
			uint8_t *data,
			uint8_t length
			);
} mac_primitive_handler_t;

/* Function prototypes */

int MCPS_DATA_request (
		mac_session_handle_t session,
		mac_address_mode_t SrcAddrMode,
		mac_pan_id_t SrcPANId,
		mac_address_t *SrcAddr,
		mac_address_mode_t DstAddrMode,
		mac_pan_id_t DstPANId,
		mac_address_t *DstAddr,
		uint8_t msduLength,
		uint8_t *msdu,
		uint8_t msduHandle,
		uint8_t TxOptions
		);
int MCPS_PURGE_request (
		mac_session_handle_t session,
		uint8_t msduHandle
		);
int MLME_ASSOCIATE_request (
		mac_session_handle_t session,
		uint8_t LogicalChannel,
		mac_address_mode_t CoordAddrMode,
		mac_pan_id_t CoordPANId,
		mac_address_t *CoordAddr,
		uint8_t CapabilityInfo,
		_Bool SecurityEnable
		);
int MLME_ASSOCIATE_response (
		mac_session_handle_t session,
		uint8_t *DeviceAddress,
		uint16_t AssocShortAddress,
		mac_association_status_t Status,
		_Bool SecurityEnable
		);
int MLME_DISASSOCIATE_request (
		mac_session_handle_t session,
		uint8_t *DeviceAddress,
		mac_disassociate_reason_t DisassociateReason,
		_Bool SecurityEnable
		);
int MLME_GET_request (
		mac_session_handle_t session,
		mac_pib_attribute_t PIBAttribute
		);
int MLME_GTS_request (
		mac_session_handle_t session,
		uint8_t GTSCharacteristics,
		_Bool SecurityEnable
		);
int MLME_ORPHAN_response (
		mac_session_handle_t session,
		uint8_t *OrphanAddress,
		uint16_t ShortAddress,
		_Bool AssociatedMember,
		_Bool SecurityEnable
		);
int MLME_RESET_request (
		mac_session_handle_t session,
		_Bool SetDefaultPIB
		);
int MLME_RX_ENABLE_request (
		mac_session_handle_t session,
		_Bool DeferPermit,
		uint32_t RxOnTime,
		uint32_t RxOnDuration
		);
int MLME_SCAN_request (
		mac_session_handle_t session,
		mac_scan_type_t ScanType,
		uint32_t ScanChannels,
		uint8_t ScanDuration
		);
int MLME_SET_request (
		mac_session_handle_t session,
		mac_pib_attribute_t PIBAttribute,
		void *PIBAttributeValue
		);
int MLME_START_request (
		mac_session_handle_t session,
		mac_pan_id_t PANId,
		uint8_t LogicalChannel,
		uint8_t BeaconOrder,
		uint8_t SuperframeOrder,
		_Bool PANCoordinator,
		_Bool BatteryLifeExtension,
		_Bool CoordRealignment,
		_Bool SecurityEnable
		);
int MLME_SYNC_request (
		mac_session_handle_t session,
		uint8_t LogicalChannel,
		_Bool TrackBeacon
		);
int MLME_POLL_request (
		mac_session_handle_t session,
		mac_address_mode_t CoordAddrMode,
		mac_pan_id_t CoordPANId,
		mac_address_t *CoordAddress,
		_Bool SecurityEnable
		);

mac_session_handle_t mac_init(char* params);

int mac_receive (mac_primitive_handler_t *handler, mac_session_handle_t session);
int mac_receive_primitive (mac_session_handle_t session, const uint8_t *data, uint8_t length);

void mac_sprintf (char *buffer, const char *format, ...);

mac_pib_attribute_t mac_string_to_value (const char *string);
const char *mac_value_to_string (mac_pib_attribute_t value);
uint8_t mac_pib_attribute_length (mac_pib_attribute_t PIBAttribute);

#endif /* MAC_H */
