/*
 * Integration MAC interface utility functions.
 *
 * Written by Jon Beniston <jbeniston@integration.com>
 *
 * Copyright 2005, 2006 Integration Associates Inc.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "mac.h"

//HACK HACK HACK
#define write(fd, buffer, size) sendto(fd, buffer, size, 0, (struct sockaddr*) &remote_addr, sizeof(remote_addr))

static struct sockaddr_in remote_addr = {
	.sin_family = AF_INET
};

typedef struct mac_string_value_struct {
	const char *string;
	mac_pib_attribute_t value;
} mac_string_value_t;

static const mac_string_value_t mac_pib_attribute_string_values[] = {
	{"macAckWaitDuration", macAckWaitDuration},
	{"macAssociationPermit", macAssociationPermit},
	{"macAutoRequest", macAutoRequest},
	{"macBattLifeExt", macBattLifeExt},
	{"macBattLifeExtPeriods", macBattLifeExtPeriods},
	{"macBeaconPayload", macBeaconPayload},
	{"macBeaconPayloadLength", macBeaconPayloadLength},
	{"macBeaconOrder", macBeaconOrder},
	{"macBeaconTxTime", macBeaconTxTime},
	{"macBSN", macBSN},
	{"macCoordExtendedAddress", macCoordExtendedAddress},
	{"macCoordShortAddress", macCoordShortAddress},
	{"macDSN", macDSN},
	{"macGTSPermit", macGTSPermit},
	{"macMaxCSMABackoffs", macMaxCSMABackoffs},
	{"macMinBE", macMinBE},
	{"macPANId", macPANId},
	{"macPromiscuousMode", macPromiscuousMode},
	{"macRxOnWhenIdle", macRxOnWhenIdle},
	{"macShortAddress", macShortAddress},
	{"macSuperframeOrder", macSuperframeOrder},
	{"macTransactionPersistenceTime", macTransactionPersistenceTime},
	{"macIEEEAddress", macIEEEAddress},
	{"macACLEntryDescriptorSet", macACLEntryDescriptorSet},
	{"macACLEntryDescriptorSetSize", macACLEntryDescriptorSetSize},
	{"macDefaultSecurity", macDefaultSecurity},
	{"macDefaultSecurityMaterialLength", macDefaultSecurityMaterialLength},
	{"macDefaultSecurityMaterial", macDefaultSecurityMaterial},
	{"macDefaultSecuritySuite", macDefaultSecuritySuite},
	{"macSecurityMode", macSecurityMode},
	{} /* Terminating entry */
};

/*
 * DESCRIPTION
 *  converts a string to its corresponding enumerated value
 *
 * RETURNS
 *  the enumerated value
 */
mac_pib_attribute_t mac_string_to_value (const char *string)
{
	const mac_string_value_t *entry;

	assert (string != NULL);

	entry = &mac_pib_attribute_string_values[0];
	while (entry->string != NULL) {
		if (!(strcmp (entry->string, string))) {
			return entry->value;
		}
		entry++;
	}
	assert (0);
	return -1;
}

/*
 * DESCRIPTION
 *  converts an enumerated value to its corresponding string
 *
 * RETURNS
 *  a pointer to the string
 */
const char *mac_value_to_string (mac_pib_attribute_t value)
{
	const mac_string_value_t *entry;

	entry = &mac_pib_attribute_string_values[0];
	while (entry->string != NULL) {
		if (value == entry->value) {
			return entry->string;
		}
		entry++;
	}
	assert (0);
	return NULL;
}

/*
 * DESCRIPTION
 *  gets the length in bytes of a PIB attribute
 *
 * RETURNS
 *  the length in bytes of the specified PIB attribute
 */
uint8_t mac_pib_attribute_length (
		mac_pib_attribute_t PIBAttribute
		)
{
	static const uint8_t mac_lengths[] = {
		1, /* macAckWaitDuration */
		1, /* macAssociationPermit */
		1, /* macAutoRequest */
		1, /* macBattLifeExt */
		1, /* macBattLifeExtPeriods */
		0, /* macBeaconPayload */
		1, /* macBeaconPayloadLength */
		1, /* macBeaconOrder */
		3, /* macBeaconTxTime */
		1, /* macBSN */
		8, /* macCoordExtendedAddress */
		2, /* macCoordShortAddress */
		1, /* macDSN */
		1, /* macGTSPermit */
		1, /* macMaxCSMABackoffs */
		1, /* macMinBE */
		2, /* macPANId */
		1, /* macPromiscuousMode */
		1, /* macRxOnWhenIdle */
		2, /* macShortAddress */
		1, /* macSuperframeOrder */
		2  /* macTransactionPersistenceTime */
	};

	static const uint8_t security_lengths[] = {
		0, /* macACLEntryDescriptorSet */
		1, /* macACLEntryDescriptorSetSize */
		1, /* macDefaultSecurity */
		1, /* macDefaultSecurityMaterialLength */
		0, /* macDefaultSecurityMaterial */
		1, /* macDefaultSecuritySuite */
		1  /* macSecurityMode */
	};

	static const uint8_t phy_lengths[] = {
		1, /* phyCurrentChannel */
		4, /* phyChannelsSupported */
		1, /* phyTransmitPower */
		1  /* phyCCAMode */
	};

	if ((PIBAttribute >= phyCurrentChannel) && (PIBAttribute <= phyCCAMode))
		return phy_lengths[PIBAttribute];
	else if ((PIBAttribute >= macAckWaitDuration) && (PIBAttribute <= macTransactionPersistenceTime))
		return mac_lengths[PIBAttribute - macAckWaitDuration];
	else if ((PIBAttribute >= macACLEntryDescriptorSet) && (PIBAttribute <= macSecurityMode))
		return security_lengths[PIBAttribute - macACLEntryDescriptorSet];
	else if (PIBAttribute == macIEEEAddress)
		return 8;

	/* Shouldn't reach here */
	assert (0);

	return 0;
}

/*
 * DESCRIPTION
 *  extracts a PAN descriptor from an primitive.
 *
 * RETURNS
 *  the number of bytes used by the PAN descriptor.
 */
static int extract_pan_descriptor (const uint8_t *data, mac_pan_descriptor_t *pan_descriptor)
{
	int i = 0;

	assert (data != NULL);
	assert (pan_descriptor != NULL);

	pan_descriptor->CoordAddrMode = data[i++];
	pan_descriptor->CoordPANId = (data[i+1] << 8) | data[i];
	i += 2;
	if (pan_descriptor->CoordAddrMode == mac_short_address) {
		pan_descriptor->CoordAddress.ShortAddress = (data[i+1] << 8) | data[i];
		i += 2;
	} else if (pan_descriptor->CoordAddrMode == mac_extended_address) {
		memcpy (pan_descriptor->CoordAddress.ExtendedAddress, &data[i], 8);
		i += 8;
	} else {
		return 0;
	}
	pan_descriptor->LogicalChannel = data[i++];
	pan_descriptor->SuperframeSpec = (data[i+1] << 8) | data[i];
	i += 2;
	pan_descriptor->GTSPermit = data[i++];
	pan_descriptor->LinkQuality = data[i++];
	pan_descriptor->TimeStamp = (data[i+2] << 16) | (data[i+1] << 8) | data[i];
	i += 3;
	pan_descriptor->SecurityUse = data[i] & 1;
	pan_descriptor->ACLEntry = (data[i] >> 1) & 0xf;
	pan_descriptor->SecurityFailure = (data[i] >> 5) & 1;
	i++;

	return i;
}

/* Create and send an MCPS-DATA.request to the MAC specfied by the file descriptor, session */
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
		)
{
	int i;
	uint8_t buffer[256];

	assert (session.fd > 0);
	assert ((SrcAddrMode == mac_no_address) || (SrcAddrMode == mac_short_address) || (SrcAddrMode == mac_extended_address));
	assert ((SrcAddrMode == mac_no_address) || (SrcAddr != NULL));
	assert ((DstAddrMode == mac_no_address) || (DstAddrMode == mac_short_address) || (DstAddrMode == mac_extended_address));
	assert ((DstAddrMode == mac_no_address) || (DstAddr != NULL));
	assert (msduLength <= aMaxMACFrameSize);
	assert ((msduLength == 0) || (msdu != NULL));
	assert ((TxOptions & 0xf0) == 0);

	i = 1;
	buffer[i++] = mac_mcps_data_request;
	buffer[i++] = SrcAddrMode;
	if (SrcAddrMode == mac_short_address) {
		buffer[i++] = SrcPANId & 0xff;
		buffer[i++] = SrcPANId >> 8;
		buffer[i++] = SrcAddr->ShortAddress & 0xff;
		buffer[i++] = SrcAddr->ShortAddress >> 8;
	} else if (SrcAddrMode == mac_extended_address) {
		buffer[i++] = SrcPANId & 0xff;
		buffer[i++] = SrcPANId >> 8;
		memcpy (&buffer[i], SrcAddr->ExtendedAddress, 8);
		i += 8;
	}
	buffer[i++] = DstAddrMode;
	if (DstAddrMode == mac_short_address) {
		buffer[i++] = DstPANId & 0xff;
		buffer[i++] = DstPANId >> 8;
		buffer[i++] = DstAddr->ShortAddress & 0xff;
		buffer[i++] = DstAddr->ShortAddress >> 8;
	} else if (DstAddrMode == mac_extended_address) {
		buffer[i++] = DstPANId & 0xff;
		buffer[i++] = DstPANId >> 8;
		memcpy (&buffer[i], DstAddr->ExtendedAddress, 8);
		i += 8;
	}
	buffer[i++] = msduLength;
	memcpy (&buffer[i], msdu, msduLength);
	i += msduLength;
	buffer[i++] = msduHandle;
	buffer[i++] = TxOptions;
	buffer[0] = i - 1;

	assert (i <= sizeof (buffer));

	return write (session.fd, buffer, i);
}

/* Create and send an MCPS-PURGE.request to the MAC specfied by the file descriptor, session */
int MCPS_PURGE_request (
		mac_session_handle_t session,
		uint8_t msduHandle
		)
{
	uint8_t buffer[3];

	assert (session.fd > 0);

	buffer[0] = 2;
	buffer[1] = mac_mcps_purge_request;
	buffer[2] = msduHandle;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-ASSOCIATE.request to the MAC specfied by the file descriptor, session */
int MLME_ASSOCIATE_request (
		mac_session_handle_t session,
		uint8_t LogicalChannel,
		mac_address_mode_t CoordAddrMode,
		mac_pan_id_t CoordPANId,
		mac_address_t *CoordAddr,
		uint8_t CapabilityInfo,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[16];
	int i;

	assert (session.fd > 0);
	assert(LogicalChannel <= 26);
	assert((CoordAddrMode == mac_short_address) || (CoordAddrMode == mac_extended_address));
	assert(CoordAddr != NULL);
	assert((CapabilityInfo & 0x30) == 0);

	i = 1;
	buffer[i++] = mac_mlme_associate_request;
	buffer[i++] = LogicalChannel;
	buffer[i++] = CoordAddrMode;
	buffer[i++] = CoordPANId & 0xff;
	buffer[i++] = CoordPANId >> 8;
	if (CoordAddrMode == mac_short_address) {
		buffer[i++] = CoordAddr->ShortAddress & 0xff;
		buffer[i++] = CoordAddr->ShortAddress >> 8;
	} else if (CoordAddrMode == mac_extended_address) {
		memcpy (&buffer[i], CoordAddr->ExtendedAddress, 8);
		i += 8;
	}
	buffer[i++] = CapabilityInfo;
	buffer[i++] = SecurityEnable;
	buffer[0] = i - 1;

	assert (i <= sizeof (buffer));

	return write (session.fd, buffer, i);
}

/* Create and send a MLME-ASSOCIATE.response to the MAC specfied by the file descriptor, session */
int MLME_ASSOCIATE_response (
		mac_session_handle_t session,
		uint8_t *DeviceAddress,
		uint16_t AssocShortAddress,
		mac_association_status_t Status,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[14];

	assert (session.fd > 0);
	assert (DeviceAddress != NULL);
	assert ((Status >= mac_association_successful) && (Status <= mac_pan_access_denied));

	buffer[0] = 13;
	buffer[1] = mac_mlme_associate_response;
	memcpy (&buffer[2], DeviceAddress, 8);
	buffer[10] = AssocShortAddress & 0xff;
	buffer[11] = AssocShortAddress >> 8;
	buffer[12] = Status;
	buffer[13] = SecurityEnable;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-DISASSOCIATE.request to the MAC specfied by the file descriptor, session */
int MLME_DISASSOCIATE_request (
		mac_session_handle_t session,
		uint8_t *DeviceAddress,
		mac_disassociate_reason_t DisassociateReason,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[12];

	assert (session.fd > 0);
	assert (DeviceAddress != NULL);

	buffer[0] = 11;
	buffer[1] = mac_mlme_disassociate_request;
	memcpy (&buffer[2], DeviceAddress, 8);
	buffer[10] = DisassociateReason;
	buffer[11] = SecurityEnable;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-GET.request to the MAC specfied by the file descriptor, session */
int MLME_GET_request (
		mac_session_handle_t session,
		mac_pib_attribute_t PIBAttribute
		)
{
	uint8_t buffer[3];

	assert (session.fd > 0);
	assert (   ((PIBAttribute >= macAckWaitDuration) && (PIBAttribute <= macTransactionPersistenceTime))
			|| (PIBAttribute == macIEEEAddress)
			|| ((PIBAttribute >= macACLEntryDescriptorSet) && (PIBAttribute <= macSecurityMode))
		   );

	buffer[0] = 2;
	buffer[1] = mac_mlme_get_request;
	buffer[2] = PIBAttribute;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-GTS.request to the MAC specfied by the file descriptor, session */
int MLME_GTS_request (
		mac_session_handle_t session,
		uint8_t GTSCharacteristics,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[4];

	assert (session.fd > 0);
	assert ((GTSCharacteristics & 0xc0) == 0);

	buffer[0] = 3;
	buffer[1] = mac_mlme_gts_request;
	buffer[2] = GTSCharacteristics;
	buffer[3] = SecurityEnable;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-ORPHAN.response to the MAC specfied by the file descriptor, session */
int MLME_ORPHAN_response (
		mac_session_handle_t session,
		uint8_t *OrphanAddress,
		uint16_t ShortAddress,
		_Bool AssociatedMember,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[13];

	assert (session.fd > 0);
	assert (OrphanAddress != NULL);

	buffer[0] = 12;
	buffer[1] = mac_mlme_orphan_response;
	memcpy (&buffer[2], OrphanAddress, 8);
	buffer[10] = ShortAddress & 0xff;
	buffer[11] = ShortAddress >> 8;
	buffer[12] = (SecurityEnable << 1) | AssociatedMember;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-RESET.request to the MAC specfied by the file descriptor, session */
int MLME_RESET_request (
		mac_session_handle_t session,
		_Bool SetDefaultPIB
		)
{
	uint8_t buffer[3];

	assert (session.fd > 0);

	buffer[0] = 2;
	buffer[1] = mac_mlme_reset_request;
	buffer[2] = SetDefaultPIB;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-RX-ENABLE.request to the MAC specfied by the file descriptor, session */
int MLME_RX_ENABLE_request (
		mac_session_handle_t session,
		_Bool DeferPermit,
		uint32_t RxOnTime,
		uint32_t RxOnDuration
		)
{
	uint8_t buffer[9];

	assert (session.fd > 0);
	assert ((RxOnTime & 0xff000000) == 0);
	assert ((RxOnDuration & 0xff000000) == 0);

	buffer[0] = 8;
	buffer[1] = mac_mlme_rx_enable_request;
	buffer[2] = DeferPermit;
	buffer[3] = RxOnTime & 0xff;
	buffer[4] = (RxOnTime >> 8) & 0xff;
	buffer[5] = (RxOnTime >> 16) & 0xff;
	buffer[6] = RxOnDuration & 0xff;
	buffer[7] = (RxOnDuration >> 8) & 0xff;
	buffer[8] = (RxOnDuration >> 16) & 0xff;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-SCAN.request to the MAC specfied by the file descriptor, session */
int MLME_SCAN_request (
		mac_session_handle_t session,
		mac_scan_type_t ScanType,
		uint32_t ScanChannels,
		uint8_t ScanDuration
		)
{
	uint8_t buffer[7];

	assert (session.fd > 0);
	assert (ScanType <= mac_orphan_scan);
	assert ((ScanChannels & 0xf8000000) == 0);
	assert (ScanDuration <= 14);

	buffer[0] = 6;
	buffer[1] = mac_mlme_scan_request;
	buffer[2] = ScanType;
	buffer[3] = ScanChannels & 0xff;
	buffer[4] = (ScanChannels >> 8) & 0xff;
	buffer[5] = (ScanChannels >> 16) & 0xff;
	buffer[6] = (ScanChannels >> 24) & 0xff;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-SET.request to the MAC specfied by the file descriptor, session */
int MLME_SET_request (
		mac_session_handle_t session,
		mac_pib_attribute_t PIBAttribute,
		void *PIBAttributeValue
		)
{
	static uint8_t beaconPayloadLength = 0;
	static uint8_t aclEntryDescriptorSetSize = 0;
	static uint8_t defaultSecurityMaterialLength = 0;
	uint8_t buffer[256];
	uint8_t length;

	assert (session.fd > 0);
	assert (   ((PIBAttribute >= phyCurrentChannel) && (PIBAttribute <= phyCCAMode))
			|| ((PIBAttribute >= macAckWaitDuration) && (PIBAttribute <= macTransactionPersistenceTime))
			|| (PIBAttribute == macIEEEAddress)
			|| ((PIBAttribute >= macACLEntryDescriptorSet) && (PIBAttribute <= macSecurityMode))
		   );

	/* We need to treat some PIB attributes as special cases, as their length is only known
	   if a previous MLME-SET.request has set it */
	if (PIBAttribute == macBeaconPayload) {
		length = beaconPayloadLength;
	} else if (PIBAttribute == macACLEntryDescriptorSet) {
		length = aclEntryDescriptorSetSize;
	} else if (PIBAttribute == macDefaultSecurityMaterial) {
		length = defaultSecurityMaterialLength;
	} else {
		length = mac_pib_attribute_length (PIBAttribute);
	}

	buffer[0] = length + 2;
	buffer[1] = mac_mlme_set_request;
	buffer[2] = PIBAttribute;
	if ((PIBAttribute == macBeaconPayload) || (PIBAttribute == macACLEntryDescriptorSet) || (PIBAttribute == macDefaultSecurityMaterial)) {
		memcpy (&buffer[3], PIBAttributeValue, length);
	} else if (length == 1) {
		buffer[3] = *(uint8_t *)PIBAttributeValue;
	} else if (length == 2) {
		uint16_t value;
		value = *(uint16_t *)PIBAttributeValue;
		buffer[3] = value & 0xff;
		buffer[4] = value >> 8;
	} else if (length == 4) {
		uint32_t value;
		value = *(uint32_t *)PIBAttributeValue;
		buffer[3] = value & 0xff;
		buffer[4] = (value >> 8) & 0xff;
		buffer[5] = (value >> 16) & 0xff;
		buffer[6] = (value >> 24) & 0xff;
	} else {
		memcpy (&buffer[3], PIBAttributeValue, length);
	}

	assert (length + 3 < sizeof (buffer));

	return write (session.fd, buffer, length + 3);
}

/* Create and send a MLME-START.request to the MAC specfied by the file descriptor, session */
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
		)
{
	uint8_t buffer[7];

	assert (session.fd > 0);
	assert (LogicalChannel <= 26);
	assert (BeaconOrder <= 15);
	assert ((SuperframeOrder <= BeaconOrder) || (SuperframeOrder == 15));

	buffer[0] = 6;
	buffer[1] = mac_mlme_start_request;
	buffer[2] = PANId & 0xff;
	buffer[3] = PANId >> 8;
	buffer[4] = LogicalChannel;
	buffer[5] = (SuperframeOrder << 4) | BeaconOrder;
	buffer[6] = (SecurityEnable << 3)
		| (CoordRealignment << 2)
		| (BatteryLifeExtension << 1)
		| PANCoordinator;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-SYNC.request to the MAC specfied by the file descriptor, session */
int MLME_SYNC_request (
		mac_session_handle_t session,
		uint8_t LogicalChannel,
		_Bool TrackBeacon
		)
{
	uint8_t buffer[4];

	assert (session.fd > 0);
	assert (LogicalChannel <= 26);

	buffer[0] = 3;
	buffer[1] = mac_mlme_sync_request;
	buffer[2] = LogicalChannel;
	buffer[3] = TrackBeacon;

	return write (session.fd, buffer, sizeof (buffer));
}

/* Create and send a MLME-POLL.request to the MAC specfied by the file descriptor, session */
int MLME_POLL_request (
		mac_session_handle_t session,
		mac_address_mode_t CoordAddrMode,
		mac_pan_id_t CoordPANId,
		mac_address_t *CoordAddress,
		_Bool SecurityEnable
		)
{
	uint8_t buffer[14];
	int i;

	assert (session.fd > 0);
	assert ((CoordAddrMode == mac_short_address) || (CoordAddrMode == mac_extended_address));
	assert (CoordPANId != 0xfffe);
	assert (CoordAddress != NULL);

	i = 1;
	buffer[i++] = mac_mlme_poll_request;
	buffer[i++] = CoordAddrMode;
	buffer[i++] = CoordPANId & 0xff;
	buffer[i++] = CoordPANId >> 8;
	if (CoordAddrMode == mac_short_address) {
		buffer[i++] = CoordAddress->ShortAddress & 0xff;
		buffer[i++] = CoordAddress->ShortAddress >> 8;
	} else {
		memcpy (&buffer[i], CoordAddress->ExtendedAddress, 8);
		i += 8;
	}
	buffer[i++] = SecurityEnable;
	buffer[0] = i - 1;

	assert (buffer[0] < sizeof (buffer));

	return write (session.fd, buffer, i);
}

/* Extract MCPS-DATA.confirm parameters and call callback */
static int process_mcps_data_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MCPS_DATA_confirm != NULL);
	assert (data != NULL);

	if (length == 2) {
		return handler->MCPS_DATA_confirm (session, data[0], data[1]);
	} else {
		return 0;
	}
}

/* Extract MCPS-DATA.indication parameters and call callback */
static int process_mcps_data_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	mac_address_mode_t SrcAddrMode;
	mac_pan_id_t SrcPANId;
	mac_address_t SrcAddr;
	mac_address_mode_t DstAddrMode;
	mac_pan_id_t DstPANId;
	mac_address_t DstAddr;
	uint8_t msduLength;
	uint8_t *msdu;
	uint8_t mpduLinkQuality;
	_Bool SecurityUse;
	mac_acl_entry_t ACLEntry;

	assert (handler != NULL);
	assert (handler->MCPS_DATA_indication != NULL);
	assert (data != NULL);

	if (length >= 5) {
		/* FIXME: Need to do more validation on length */
		SrcAddrMode = *data++;
		if (SrcAddrMode == mac_short_address) {
			SrcPANId = (data[1] << 8) | data[0];
			SrcAddr.ShortAddress = (data[3] << 8) | data[2];
			data += 4;
		} else if (SrcAddrMode == mac_extended_address) {
			SrcPANId = (data[1] << 8) | data[0];
			memcpy (&SrcAddr.ExtendedAddress[0], &data[2], 8);
			data += 10;
		} else if ((SrcAddrMode != mac_no_address)) {
			return 0;
		}
		DstAddrMode = *data++;
		if (DstAddrMode == mac_short_address) {
			DstPANId = (data[1] << 8) | data[0];
			DstAddr.ShortAddress = (data[3] << 8) | data[2];
			data += 4;
		} else if (DstAddrMode == mac_extended_address) {
			DstPANId = (data[1] << 8) | data[0];
			memcpy (&DstAddr.ExtendedAddress[0], &data[2], 8);
			data += 10;
		} else if ((DstAddrMode != mac_no_address)) {
			return 0;
		}
		msduLength = data[0];
		msdu = &data[1];
		data += msduLength + 1;
		mpduLinkQuality = data[0];
		SecurityUse = data[1] & 1;
		ACLEntry = (data[1] >> 1) & 0xf;
		return handler->MCPS_DATA_indication (
				session,
				SrcAddrMode,
				SrcPANId,
				&SrcAddr,
				DstAddrMode,
				DstPANId,
				&DstAddr,
				msduLength,
				msdu,
				mpduLinkQuality,
				SecurityUse,
				ACLEntry
				);
	} else {
		return 0;
	}
}

/* Extract MCPS-PURGE.confirm parameters and call callback */
static int process_mcps_purge_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MCPS_PURGE_confirm != NULL);
	assert (data != NULL);

	if (length == 2) {
		return handler->MCPS_PURGE_confirm (session, data[0], data[1]);
	} else {
		return 0;
	}
}

/* Extract MLME-ASSOCIATE.confirm parameters and call callback */
static int process_mlme_associate_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_ASSOCIATE_confirm != NULL);
	assert (data != NULL);

	if (length == 3) {
		return handler->MLME_ASSOCIATE_confirm (session, (data[1] << 8) | data[0], data[2]);
	} else {
		return 0;
	}
}

/* Extract MLME-ASSOCIATE.indication parameters and call callback */
static int process_mlme_associate_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_ASSOCIATE_indication != NULL);
	assert (data != NULL);

	if (length == 10) {
		return handler->MLME_ASSOCIATE_indication (session, &data[0], data[8], data[9] & 1, (data[9] >> 1) & 0xf);
	} else {
		return 0;
	}
}

/* Extract MLME-DISASSOCIATE.confirm parameters and call callback */
static int process_mlme_disassociate_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_DISASSOCIATE_confirm != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_DISASSOCIATE_confirm (session, data[0]);
	} else {
		return 0;
	}
}

/* Extract MLME-DISASSOCIATE.indication parameters and call callback */
static int process_mlme_disassociate_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_DISASSOCIATE_indication != NULL);
	assert (data != NULL);

	if (length == 10) {
		return handler->MLME_DISASSOCIATE_indication (session, &data[0], data[8], data[9] & 1, (data[9] >> 1) & 0xf);
	} else {
		return 0;
	}
}

/* Extract MLME-BEACON-NOTIFY.indication parameters and call callback */
static int process_mlme_beacon_notify_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	uint8_t BSN;
	mac_pan_descriptor_t PANDescriptor;
	uint8_t PendAddrSpec;
	uint8_t *AddrList;
	uint8_t sduLength;
	uint8_t *sdu;
	int i;

	assert (handler != NULL);
	assert (handler->MLME_BEACON_NOTIFY_indication != NULL);
	assert (data != NULL);

	if (length >= 17) {
		i = 0;
		BSN = data[i++];
		i += extract_pan_descriptor (&data[i], &PANDescriptor);
		if (i == 1) {
			/* PAN descriptor was invalid */
			return 0;
		}
		PendAddrSpec = data[i++];
		AddrList = &data[i];            /* FIXME: Should we convert short addresses to host endianness? */
		i += (PendAddrSpec & 0x3) * 2 + ((PendAddrSpec & 0x30) >> 4) * 8;
		sduLength = data[i++];
		sdu = &data[i];
		i += sduLength;
		if (i > length) {
			return 0;
		}
		return handler->MLME_BEACON_NOTIFY_indication (session, BSN, &PANDescriptor, PendAddrSpec, AddrList, sduLength, sdu);
	} else {
		return 0;
	}
}

/* Extract MLME-GET.confirm parameters and call callback */
static int process_mlme_get_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_GET_confirm != NULL);
	assert (data != NULL);

	return handler->MLME_GET_confirm (session, data[0], data[1], &data[2]);
}

/* Extract MLME-GTS.confirm parameters and call callback */
static int process_mlme_gts_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_GTS_confirm != NULL);
	assert (data != NULL);

	if (length == 2) {
		return handler->MLME_GTS_confirm (session, data[0], data[1]);
	} else {
		return 0;
	}
}

/* Extract MLME-GTS.indication parameters and call callback */
static int process_mlme_gts_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_GTS_indication != NULL);
	assert (data != NULL);

	if (length == 4) {
		return handler->MLME_GTS_indication (session, (data[1] << 8) | data[0], data[2], data[3] & 1, (data[3] >> 1) & 0xf);
	} else {
		return 0;
	}
}

/* Extract MLME-ORPHAN.indication parameters and call callback */
static int process_mlme_orphan_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_ORPHAN_indication != NULL);
	assert (data != NULL);

	if (length == 9) {
		return handler->MLME_ORPHAN_indication (session, &data[0], data[8] & 1, (data[8] >> 1) & 0xf);
	} else {
		return 0;
	}
}

/* Extract MLME-RESET.confirm parameters and call callback */
static int process_mlme_reset_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_RESET_confirm != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_RESET_confirm (session, data[0]);
	} else {
		return 0;
	}
}

/* Extract MLME-RX-ENABLE.confirm parameters and call callback */
static int process_mlme_rx_enable_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_RX_ENABLE_confirm != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_RX_ENABLE_confirm (session, data[0]);
	} else {
		return 0;
	}
}

/* Extract MLME-SCAN.confirm parameters and call callback */
static int process_mlme_scan_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	mac_status_t status;
	mac_scan_type_t ScanType;
	uint32_t UnscannedChannels;
	uint8_t ResultListSize;
	uint8_t *EnergyDetectList;
	mac_pan_descriptor_t *PANDescriptorList;
	mac_pan_descriptor_t PANDescriptors[256];
	int i, size;

	assert (handler != NULL);
	assert (handler->MLME_SCAN_confirm != NULL);
	assert (data != NULL);

	if (length >= 7) {
		status = data[0];
		ScanType = data[1];
		UnscannedChannels = (data[5] << 24) | (data[4] << 16) | (data[3] << 8) | data[2];
		ResultListSize = data[6];
		EnergyDetectList = NULL;
		PANDescriptorList = NULL;
		if (ResultListSize != 0) {
			if (length >= 8) {
				if (ScanType == mac_energy_detect_scan) {
					EnergyDetectList = &data[7];
				} else if ((ScanType == mac_active_scan) || (ScanType == mac_passive_scan)) {
					PANDescriptorList = &PANDescriptors[0];
					data = &data[7];
					for (i = 0; i < ResultListSize; i++) {
						size = extract_pan_descriptor (data, &PANDescriptors[i]);
						if (size == 0) {
							/* PAN descriptor was invalid */
							return 0;
						}
						data += size;
					}
				} else {
					/* Shouldn't have a result list for orphan scans */
					return 0;
				}
			} else {
				return 0;
			}
		}
		return handler->MLME_SCAN_confirm (
				session,
				status,
				ScanType,
				UnscannedChannels,
				ResultListSize,
				EnergyDetectList,
				PANDescriptorList
				);
	} else {
		return 0;
	}
}

/* Extract MLME-COMM-STATUS.indication parameters and call callback */
static int process_mlme_comm_status_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	mac_pan_id_t PANId;
	mac_address_mode_t SrcAddrMode;
	mac_address_t SrcAddr;
	mac_address_mode_t DstAddrMode;
	mac_address_t DstAddr;
	mac_status_t Status;
	int i;

	assert (handler != NULL);
	assert (handler->MLME_COMM_STATUS_indication != NULL);
	assert (data != NULL);

	if (length >= 5) {
		/* FIXME: Need to do more validation on length */
		i = 0;
		PANId = (data[1] << 8) | data[0];
		SrcAddrMode = data[3];
		if (SrcAddrMode == mac_short_address) {
			SrcAddr.ShortAddress = (data[5] << 8) | data[4];
			i = 6;
		} else if (SrcAddrMode == mac_extended_address) {
			memcpy (&SrcAddr.ExtendedAddress[0], &data[4], 8);
			i = 10;
		} else if ((SrcAddrMode != mac_no_address)) {
			return 0;
		}
		DstAddrMode = data[i++];
		if (DstAddrMode == mac_short_address) {
			DstAddr.ShortAddress = (data[i+1] << 8) | data[i];
			i += 2;
		} else if (DstAddrMode == mac_extended_address) {
			memcpy (&DstAddr.ExtendedAddress[0], &data[i], 8);
			i += 8;
		} else if ((DstAddrMode != mac_no_address)) {
			return 0;
		}
		Status = data[i];
		if (i > length) {
			return 0;
		}
		return handler->MLME_COMM_STATUS_indication (
				session,
				PANId, SrcAddrMode,
				&SrcAddr,
				DstAddrMode,
				&DstAddr,
				Status
				);
	} else {
		return 0;
	}
}

/* Extract MLME-SET.confirm parameters and call callback */
static int process_mlme_set_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_SET_confirm != NULL);
	assert (data != NULL);

	if (length == 2) {
		return handler->MLME_SET_confirm (session, data[0], data[1]);
	} else {
		return 0;
	}
}

/* Extract MLME-START.confirm parameters and call callback */
static int process_mlme_start_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_START_confirm != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_START_confirm (session, data[0]);
	} else {
		return 0;
	}
}

/* Extract MLME-SYNC-LOSS.indication parameters and call callback */
static int process_mlme_sync_loss_indication (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_SYNC_LOSS_indication != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_SYNC_LOSS_indication (session, data[0]);
	} else {
		return 0;
	}
}

/* Extract MLME-POLL.confirm parameters and call callback */
static int process_mlme_poll_confirm (mac_primitive_handler_t *handler, mac_session_handle_t session, uint8_t *data, uint8_t length)
{
	assert (handler != NULL);
	assert (handler->MLME_POLL_confirm != NULL);
	assert (data != NULL);

	if (length == 1) {
		return handler->MLME_POLL_confirm (session, data[0]);
	} else {
		return 0;
	}
}

#ifdef MAC_DEBUG
/* Print a primitives name and data in hex. */
static void mac_print_primitive (uint8_t *data, uint8_t length)
{
	static const char *mac_primitive_names[] = {
		"MCPS-DATA.request",
		"MCPS-DATA.confirm ",
		"MCPS-DATA.indication",
		"MCPS-PURGE.request",
		"MCPS-PURGE.confirm",
		"MLME-ASSOCIATE.request",
		"MLME-ASSOCIATE.confirm",
		"MLME-ASSOCIATE.indication",
		"MLME-ASSOCIATE.response",
		"MLME-DISASSOCIATE.request",
		"MLME-DISASSOCIATE.confirm",
		"MLME-DISASSOCIATE.indication",
		"MLME-BEACON-NOTIFY.ndication",
		"MLME-GET.request",
		"MLME-GET.confirm",
		"MLME-GTS.request",
		"MLME-GTS.confirm",
		"MLME-GTS.indication",
		"MLME-ORPHAN.indication",
		"MLME-ORPHAN.response",
		"MLME-RESET.request",
		"MLME-RESET.confirm",
		"MLME-RX-ENABLE.request",
		"MLME-RX-ENABLE.confirm",
		"MLME-SCAN.request",
		"MLME-SCAN.confirm",
		"MLME-COMM-STATUS.indication",
		"MLME-SET.request",
		"MLME-SET.confirm",
		"MLME-START.request",
		"MLME-START.confirm",
		"MLME-SYNC.request",
		"MLME-SYNC-LOSS.indication",
		"MLME-POLL.request",
		"MLME-POLL.confirm",
	};
	int i;

	if ((data[0] >= mac_mcps_data_request) && (data[0] <= mac_mlme_poll_confirm)) {
		printf ("%s: ", mac_primitive_names[data[0] - mac_mcps_data_request]);
		i = 1;
	} else {
		i = 0;
	}
	for (; i < length; i++) {
		printf ("%02x", data[i]);
	}
	printf ("\n");
}
#endif

/*
 * DESCRIPTION
 *  Receive and process a primitive.
 *
 * RETURNS
 *  n - If primitive is received and processed successfully, the return value is the return value of the user supplied handler function.
 *  1 - If primitive is received and processed successfully, but no handler has been provided.
 *  0 - If primitive is received, but is malformed or unsupported.
 *  -1 - If an error occurs while trying to read the primitive.
 */
int mac_receive (mac_primitive_handler_t *handler, mac_session_handle_t session)
{
	uint8_t buffer[256];
	uint8_t length;
	int retval;

	assert (handler != NULL);
	assert (session.fd > 0);

	/* Read datagram containing ieee802154 packet */
	socklen_t slen;
	retval = recvfrom(session.fd, buffer, sizeof(buffer), 0, (struct sockaddr*) &remote_addr, &slen);
	if(retval < 0)
		return -1;
	assert (buffer[0] > 0);
#ifdef MAC_DEBUG
	mac_print_primitive (&buffer[1], buffer[0]);
#endif
	length = buffer[0] - 1;
	switch (buffer[1]) {
		case mac_mcps_data_confirm:
			if (handler->MCPS_DATA_confirm != NULL) {
				return process_mcps_data_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mcps_data_indication:
			if (handler->MCPS_DATA_indication != NULL) {
				return process_mcps_data_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mcps_purge_confirm:
			if (handler->MCPS_PURGE_confirm != NULL) {
				return process_mcps_purge_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_associate_confirm:
			if (handler->MLME_ASSOCIATE_confirm != NULL) {
				return process_mlme_associate_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_associate_indication:
			if (handler->MLME_ASSOCIATE_indication != NULL) {
				return process_mlme_associate_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_disassociate_confirm:
			if (handler->MLME_DISASSOCIATE_confirm != NULL) {
				return process_mlme_disassociate_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_disassociate_indication:
			if (handler->MLME_DISASSOCIATE_indication != NULL) {
				return process_mlme_disassociate_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_beacon_notify_indication:
			if (handler->MLME_BEACON_NOTIFY_indication != NULL) {
				process_mlme_beacon_notify_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_get_confirm:
			if (handler->MLME_GET_confirm != NULL) {
				return process_mlme_get_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_gts_confirm:
			if (handler->MLME_GTS_confirm != NULL) {
				return process_mlme_gts_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_gts_indication:
			if (handler->MLME_GTS_indication != NULL) {
				return process_mlme_gts_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_orphan_indication:
			if (handler->MLME_ORPHAN_indication != NULL) {
				return process_mlme_orphan_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_reset_confirm:
			if (handler->MLME_RESET_confirm != NULL) {
				return process_mlme_reset_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_rx_enable_confirm:
			if (handler->MLME_RX_ENABLE_confirm != NULL) {
				return process_mlme_rx_enable_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_scan_confirm:
			if (handler->MLME_SCAN_confirm != NULL) {
				return process_mlme_scan_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_comm_status_indication:
			if (handler->MLME_COMM_STATUS_indication != NULL) {
				return process_mlme_comm_status_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_set_confirm:
			if (handler->MLME_SET_confirm != NULL) {
				return process_mlme_set_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_start_confirm:
			if (handler->MLME_START_confirm != NULL) {
				return process_mlme_start_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_sync_loss_indication:
			if (handler->MLME_SYNC_LOSS_indication != NULL) {
				return process_mlme_sync_loss_indication (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		case mac_mlme_poll_confirm:
			if (handler->MLME_POLL_confirm != NULL) {
				return process_mlme_poll_confirm (handler, session, &buffer[2], length);
			} else {
				return 1;
			}
		default:
			if (handler->unknown_primitive != NULL) {
				return handler->unknown_primitive (session, buffer[5], &buffer[2], length);
			} else {
				return 1;
			}
	}
}


/*
 * DESCRIPTION
 *  Receive a primitive and compare it against a user specified primitive.
 *
 * RETURNS
 *  1 - If primitive is received and matches given primitive.
 *  0 - If primitive is received, but does not match given primitive.
 *  -1 - If an error occurs while trying to read the primitive.
 */
int mac_receive_primitive (mac_session_handle_t session, const uint8_t *data, uint8_t length)
{
	uint8_t buffer[256];
	int retval;

	assert (session.fd > 0);
	assert (data != NULL);
	assert (length != 0);

	memset (buffer, 0, sizeof (buffer));
	/* Read datagram */
	socklen_t slen;
	retval = recvfrom(session.fd, buffer, sizeof(buffer), 0, (struct sockaddr*) &remote_addr, &slen);
	if(retval < 0)
		return -1;
	assert (buffer[0] > 0);
#ifdef MAC_DEBUG
	mac_print_primitive (&buffer[1], buffer[0]);
#endif
	/* Check received length matches what we are looking for */
	if (buffer[0] == length) {
		return memcmp (&buffer[1], data, length) == 0 ? 1 : 0;
	} else {
		/* Length read does match what we are looking for */
		return 0;
	}
}

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
void mac_sprintf (char *buffer, const char *format, ...)
{
	const char *f;
	char *b;
	va_list ap;
	int i;

	b = buffer;
	f = format;
	va_start (ap, format);

	while (*f != '\0') {
		if (*f == '%') {
			f++;
			switch (*f++) {
				case 'd':
					{
						int number = va_arg (ap, int);
						b += sprintf (b, "%d", number);
					}
					break;
				case 'x':
					{
						int number = va_arg (ap, int);
						b += sprintf (b, "%x", number);
					}
					break;
				case 'a':
					{
						mac_address_mode_t mode = va_arg (ap, mac_address_mode_t);
						uint16_t panid = va_arg (ap, int);
						mac_address_t *address = va_arg (ap, mac_address_t *);
						if (mode == mac_no_address) {
							strcpy (b, "0x00");
							b += 4;
						} else if (mode == mac_short_address) {
							b += sprintf (b, "0x%02x, 0x%04x, 0x%04x", mode, panid, address->ShortAddress);
						} else if (mode == mac_extended_address) {
							b += sprintf (b, "0x%02x, 0x%04x, 0x", mode, panid);
							for (i = 0; i < 8; i++) {
								b += sprintf (b, "%02x", address->ExtendedAddress[i]);
							}
						} else {
							assert (0);
						}
					}
					break;
				case 'q':
					{
						mac_address_mode_t mode = va_arg (ap, mac_address_mode_t);
						mac_address_t *address = va_arg (ap, mac_address_t *);
						if (mode == mac_no_address) {
							strcpy (b, "0x00");
							b += 4;
						} else if (mode == mac_short_address) {
							b += sprintf (b, "0x%02x, 0x%04x", mode, address->ShortAddress);
						} else if (mode == mac_extended_address) {
							b += sprintf (b, "0x%02x, 0x", mode);
							for (i = 0; i < 8; i++) {
								b += sprintf (b, "%02x", address->ExtendedAddress[i]);
							}
						} else {
							assert (0);
						}
					}
					break;
				case 's':
					{
						uint16_t address = va_arg (ap, int);
						b += sprintf (b, "0x%04x", address);
					}
					break;
				case 'e':
					{
						uint8_t *address = va_arg (ap, uint8_t *);
						for (i = 0; i < 8; i++) {
							b += sprintf (b, "%02x", address[i]);
						}
					}
					break;
				case 'b':
					{
						_Bool boolean = va_arg (ap, int);
						if (boolean) {
							strcpy (b, "true");
							b += 4;
						} else {
							strcpy (b, "false");
							b += 5;
						}
					}
					break;
				case 'A':
					{
						mac_association_status_t status = va_arg (ap, int);
						switch (status) {
							case mac_association_successful:
								b += sprintf (b, "association successful");
								break;
							case mac_pan_at_capacity:
								b += sprintf (b, "PAN at capacity");
								break;
							case mac_pan_access_denied:
								b += sprintf (b, "PAN access denied");
								break;
							default:
								b += sprintf (b, "0x%02x", status);
								break;
						}
					}
					break;
				case 'D':
					{
						mac_disassociate_reason_t reason = va_arg (ap, int);
						switch (reason) {
							case mac_coordinator_disassociate:
								b += sprintf (b, "coordinator disassociate");
								break;
							case mac_device_disassociate:
								b += sprintf (b, "device disassociate");
								break;
							default:
								b += sprintf (b, "0x%02x", reason);
								break;
						}
					}
					break;
				case 'S':
					{
						mac_scan_type_t scan_type = va_arg (ap, int);
						switch (scan_type) {
							case mac_energy_detect_scan:
								b += sprintf (b, "energy detect");
								break;
							case mac_active_scan:
								b += sprintf (b, "active scan");
								break;
							case mac_passive_scan:
								b += sprintf (b, "passive scan");
								break;
							case mac_orphan_scan:
								b += sprintf (b, "orphan scan");
								break;
							default:
								b += sprintf (b, "0x%02x", scan_type);
								break;
						}
					}
					break;
				case 'p':
					{
						mac_pib_attribute_t attribute = va_arg (ap, int);
						b += sprintf (b, mac_value_to_string (attribute));
					}
					break;
				case 'P':
					{
						mac_pib_attribute_t attribute = va_arg (ap, int);
						uint8_t *value = va_arg (ap, uint8_t *);
						b += sprintf (b, "%s, ", mac_value_to_string (attribute));
						for (i = 0; i < mac_pib_attribute_length (attribute); i++) {
							b += sprintf (b, "%02x", value[i]);
						}
					}
					break;
				case 'g':
					{
						uint8_t gts_characteristics = va_arg (ap, int);
						if (gts_characteristics & MAC_GTS_ALLOCATE) {
							b += sprintf (b, "allocate ");
						} else {
							b += sprintf (b, "deallocate ");
						}
						if (gts_characteristics & MAC_GTS_RECEIVE) {
							b += sprintf (b, "receive - ");
						} else {
							b += sprintf (b, "transmit - ");
						}
						b += sprintf (b, "length = %d", gts_characteristics & 0xf);
					}
					break;
				case 't':
					{
						uint8_t tx_options = va_arg (ap, int);
						if (tx_options & MAC_TX_OPTION_ACKNOWLEDGED) {
							b += sprintf (b, " acked");
						}
						if (tx_options & MAC_TX_OPTION_GTS) {
							b += sprintf (b, " gts");
						}
						if (tx_options & MAC_TX_OPTION_INDIRECT) {
							b += sprintf (b, " indirect");
						}
						if (tx_options & MAC_TX_OPTION_SECURITY_ENABLED) {
							b += sprintf (b, " secured");
						}
						if (tx_options == 0) {
							b += sprintf (b, " none");
						}
					}
					break;
				case 'm':
					{
						uint8_t length = va_arg (ap, unsigned);
						uint8_t *data = va_arg (ap, uint8_t *);
						b += sprintf (b, "0x%02x, ", length);
						for (i = 0; i < length; i++) {
							b += sprintf (b, "%02x", data[i]);
						}
					}
					break;
				case 'R':
					{
						mac_status_t status = va_arg (ap, int);
						const char *string = NULL;
						switch (status) {
							case mac_success:
								string = "success";
								break;
							case mac_beacon_lost:
								string = "beacon lost";
								break;
							case mac_channel_access_failure:
								string = "channel access failure";
								break;
							case mac_denied:
								string = "denied";
								break;
							case mac_disable_trx_failure:
								string = "disable TRX failure";
								break;
							case mac_failed_security_check:
								string = "failed security check";
								break;
							case mac_frame_too_long:
								string = "frame too long";
								break;
							case mac_invalid_gts:
								string = "invalid GTS";
								break;
							case mac_invalid_handle:
								string = "invalid handle";
								break;
							case mac_invalid_parameter:
								string = "invalid parameter";
								break;
							case mac_no_ack:
								string = "no ack";
								break;
							case mac_no_beacon:
								string = "no beacon";
								break;
							case mac_no_data:
								string = "no data";
								break;
							case mac_no_short_address:
								string = "no short address";
								break;
							case mac_out_of_cap:
								string = "out of CAP";
								break;
							case mac_pan_id_conflict:
								string = "PAN Id conflict";
								break;
							case mac_realignment:
								string = "realignment";
								break;
							case mac_transaction_expired:
								string = "transaction expired";
								break;
							case mac_transaction_overflow:
								string = "transaction overflow";
								break;
							case mac_tx_active:
								string = "tx active";
								break;
							case mac_unavailable_key:
								string = "unavailable key";
								break;
							case mac_unsupported_attribute:
								string = "unsupported attribute";
								break;
							default:
								b += sprintf (b, "0x%02x", status);
								break;
						}
						if (string != NULL) {
							b += sprintf (b, string);
						}
					}
					break;
				case 'c':
					{
						mac_acl_entry_t acl = va_arg (ap, int);
						const char *string = NULL;
						switch (acl) {
							case mac_acl_none:
								string = "none";
								break;
							case mac_acl_aes_ctr:
								string = "AES-CTR";
								break;
							case mac_acl_aes_ccm_128:
								string = "AES-CCM-128";
								break;
							case mac_acl_aes_ccm_64:
								string = "AES-CCM-64";
								break;
							case mac_acl_aes_ccm_32:
								string = "AES-CCM-32";
								break;
							case mac_acl_aes_cbc_mac_128:
								string = "AES-CBC-MAC-128";
								break;
							case mac_acl_aes_cbc_mac_64:
								string = "AES-CBC-MAC-64";
								break;
							case mac_acl_aes_cbc_mac_32:
								string = "AES-CBC-MAC-32";
								break;
							case mac_acl_not_found:
								string = "ACL not found";
								break;
							default:
								b += sprintf (b, "0x%02x", acl);
								break;
						}
						if (string != NULL) {
							b += sprintf (b, string);
						}
					}
					break;
				case 'n':
					{
						mac_pan_descriptor_t *descriptor = va_arg (ap, mac_pan_descriptor_t *);
						mac_sprintf (b, "%a, 0x%x, 0x%x, %b, 0x%x, 0x%x, %b, %c, %b", descriptor->CoordAddrMode, descriptor->CoordPANId, &descriptor->CoordAddress, descriptor->LogicalChannel, descriptor->SuperframeSpec, descriptor->GTSPermit, descriptor->LinkQuality, descriptor->TimeStamp, descriptor->SecurityUse, descriptor->ACLEntry, descriptor->SecurityFailure);
						b += strlen (b);
					}
					break;
				default:
					fprintf (stderr, "Unsupported format specifier %c\n", *--f);
					assert (0);
			}
		} else {
			/* Simply copy character from input to output */
			*b++ = *f++;
		}
	}
	*b = '\0';

	va_end (ap);
}

mac_session_handle_t mac_init(char* params) {
	mac_session_handle_t rv = {
		.fd = -1
	};

	int rport = 0;
	if(!(sscanf(params, "%d", &rport) == 1))
		return rv;

	remote_addr.sin_port = htons(rport);
	remote_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	rv.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	return rv;
}
