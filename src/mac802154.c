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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "mac802154.h"
#include "sn_status.h"

#pragma GCC diagnostic ignored "-Wenum-compare"
#pragma GCC diagnostic ignored "-Wformat-security"

#define defaultACLEntry_M {              \
    /*.ACLExtendedAddress        = {},*/ \
    .ACLShortAddress           = 0xFFFF, \
    /*.ACLPANId                  = 0, */ \
    .ACLSecurityMaterialLength = 21,     \
    /*.ACLSecurityMaterial       = {},*/ \
    /*.ACLSecuritySuite          = 0, */ \
}

const mac_acl_entry_descriptor_t mac_default_ACLEntry = defaultACLEntry_M;

const mac_mib_t mac_default_MIB = {
    .macAckWaitDuration               = 54,
    //.macAssociationPermit             = 0,
    .macAutoRequest                   = 1,
    //.macBattLifeExt                   = 0,
    .macBattLifeExtPeriods            = 6,
    //.macBeaconPayload                 = {},
    //.macBeaconPayloadLength           = 0,
    .macBeaconOrder                   = 15,
    //.macBeaconTxTime                  = 0,
    //.macBSN                           = 0, //GETME
    //.macCoordExtendedAddress          = {}, //SET_ON_ASSOC
    .macCoordShortAddress             = 0xFFFF, //SET_ON_ASSOC
    //.macDSN                           = 0, //GETME
    //.macGTSPermit                     = 0,
    .macMaxCSMABackoffs               = 4,
    .macMinBE                         = 3,
    .macPANId                         = 0xFFFF,
    //.macPromiscuousMode               = 0,
    //.macRxOnWhenIdle                  = 0,
    .macShortAddress                  = 0xFFFF, //SET_ON_ASSOC to 0xFFFE
    .macSuperframeOrder               = 15,
    .macTransactionPersistenceTime    = 0x01F4,
    //.macIEEEAddress                   = {}, //GETME
    .macACLEntryDescriptorSet         = {defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M, defaultACLEntry_M},
    //.macACLEntryDescriptorSetSize     = 0,
    //.macDefaultSecurity               = 0,
    //.macDefaultSecurityMaterialLength = 0,
    //.macDefaultSecurityMaterial       = {},
    //.macDefaultSecuritySuite          = 0,
    //.macSecurityMode                  = 0,
    //.macACLEntryDescriptorNumber      = 0,
};

/*
 * DESCRIPTION
 *  converts an enumerated value to its corresponding string
 *
 * RETURNS
 *  a pointer to the string
 */
const char* mac_value_to_string (mac_pib_attribute_t value)
{
    static const struct mac_string_value {
        const char*         string;
        mac_pib_attribute_t value;
    } mac_pib_attribute_string_values[] = {
        //TODO: fill me
        {"macAckWaitDuration",               macAckWaitDuration},
        {"macAssociationPermit",             macAssociationPermit},
        {"macAutoRequest",                   macAutoRequest},
        {"macBattLifeExt",                   macBattLifeExt},
        {"macBattLifeExtPeriods",            macBattLifeExtPeriods},
        {"macBeaconPayload",                 macBeaconPayload},
        {"macBeaconPayloadLength",           macBeaconPayloadLength},
        {"macBeaconOrder",                   macBeaconOrder},
        {"macBeaconTxTime",                  macBeaconTxTime},
        {"macBSN",                           macBSN},
        {"macCoordExtendedAddress",          macCoordExtendedAddress},
        {"macCoordShortAddress",             macCoordShortAddress},
        {"macDSN",                           macDSN},
        {"macGTSPermit",                     macGTSPermit},
        {"macMaxCSMABackoffs",               macMaxCSMABackoffs},
        {"macMinBE",                         macMinBE},
        {"macPANId",                         macPANId},
        {"macPromiscuousMode",               macPromiscuousMode},
        {"macRxOnWhenIdle",                  macRxOnWhenIdle},
        {"macShortAddress",                  macShortAddress},
        {"macSuperframeOrder",               macSuperframeOrder},
        {"macTransactionPersistenceTime",    macTransactionPersistenceTime},
        {"macIEEEAddress",                   macIEEEAddress},
        {"macACLEntryDescriptorSet",         macACLEntryDescriptorSet},
        {"macACLEntryDescriptorSetSize",     macACLEntryDescriptorSetSize},
        {"macDefaultSecurity",               macDefaultSecurity},
        {"macDefaultSecurityMaterialLength", macDefaultSecurityMaterialLength},
        {"macDefaultSecurityMaterial",       macDefaultSecurityMaterial},
        {"macDefaultSecuritySuite",          macDefaultSecuritySuite},
        {"macSecurityMode",                  macSecurityMode},
        {} /* Terminating entry */
    };

    for(const struct mac_string_value* entry = mac_pib_attribute_string_values; entry->string != NULL; entry++) {
        if (value == entry->value) {
            return entry->string;
        }
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
    //TODO: rewrite in the spirit of value_to_string
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
    else if (PIBAttribute == macACLEntryDescriptorNumber)
        return 1;

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
    pan_descriptor->GTSPermit = data[i++] == 0 ? 0 : 1;
    pan_descriptor->LinkQuality = data[i++];
    pan_descriptor->TimeStamp = (data[i+2] << 16) | (data[i+1] << 8) | data[i];
    i += 3;
    pan_descriptor->SecurityUse = data[i] & 1;
    pan_descriptor->ACLEntry = (data[i] >> 1) & 0xf;
    pan_descriptor->SecurityFailure = (data[i] >> 5) & 1;
    i++;

    return i;
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
        "MLME-BEACON-NOTIFY.indication",
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
    } else if (data[0] == mac_mlme_protocol_error_indication) {
        printf ("%s: ", "MLME-PROTOCOL_ERROR.indication");
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

#define GUARANTEE_STRUCT_SIZE(x, sz) _Static_assert(sizeof(x) == sz, #x " is the wrong size")

int mac_transmit(mac_session_handle_t session, mac_primitive_t* primitive) {
    uint8_t buffer[sizeof(mac_primitive_t) + 1]; //1 extra byte for the chunk size
    uint8_t chunk_size   = 2; //1 for the size byte, 1 for the type byte
    bool    copy_data_in = 1; //by default, assume the struct matches what the radio wants

    assert(MAC_IS_SESSION_VALID(session));
    if(!MAC_IS_SESSION_VALID(session))
        return -SN_ERR_NULL;
    assert(primitive != NULL);
    if(primitive == NULL)
        return -SN_ERR_NULL;


    switch(primitive->type) {
        case mac_mcps_data_request:
            {
                copy_data_in = 0;

#define SrcPANId    (primitive->MCPS_DATA_request.SrcPANId)
#define SrcAddrMode (primitive->MCPS_DATA_request.SrcAddrMode)
#define SrcAddr     (primitive->MCPS_DATA_request.SrcAddr)
#define DstPANId    (primitive->MCPS_DATA_request.DstPANId)
#define DstAddrMode (primitive->MCPS_DATA_request.DstAddrMode)
#define DstAddr     (primitive->MCPS_DATA_request.DstAddr)
#define msduLength  (primitive->MCPS_DATA_request.msduLength)
#define msduHandle  (primitive->MCPS_DATA_request.msduHandle)
#define TxOptions   (primitive->MCPS_DATA_request.TxOptions)
#define msdu        (primitive->MCPS_DATA_request.msdu)
                assert ((SrcAddrMode == mac_no_address) || (SrcAddrMode == mac_short_address) || (SrcAddrMode == mac_extended_address));
                assert ((DstAddrMode == mac_no_address) || (DstAddrMode == mac_short_address) || (DstAddrMode == mac_extended_address));
                assert (msduLength <= aMaxMACPayloadSize);
                assert ((TxOptions & 0xf0) == 0);

                //chunk_size = 2 here. remember, 0th byte is the block size, and 1st is type
                buffer[chunk_size++] = SrcAddrMode;
                buffer[chunk_size++] = SrcPANId & 0xff;
                buffer[chunk_size++] = SrcPANId >> 8;
                if (SrcAddrMode == mac_short_address) {
                    buffer[chunk_size++] = SrcAddr.ShortAddress & 0xff;
                    buffer[chunk_size++] = SrcAddr.ShortAddress >> 8;
                } else if (SrcAddrMode == mac_extended_address) {
                    memcpy (&buffer[chunk_size], SrcAddr.ExtendedAddress, 8);
                    chunk_size += 8;
                }
                buffer[chunk_size++] = DstAddrMode;
                buffer[chunk_size++] = DstPANId & 0xff;
                buffer[chunk_size++] = DstPANId >> 8;
                if (DstAddrMode == mac_short_address) {
                    buffer[chunk_size++] = DstAddr.ShortAddress & 0xff;
                    buffer[chunk_size++] = DstAddr.ShortAddress >> 8;
                } else if (DstAddrMode == mac_extended_address) {
                    memcpy (&buffer[chunk_size], DstAddr.ExtendedAddress, 8);
                    chunk_size += 8;
                }
                buffer[chunk_size++] = msduLength;
                memcpy (&buffer[chunk_size], msdu, msduLength);
                chunk_size += msduLength;
                buffer[chunk_size++] = msduHandle;
                buffer[chunk_size++] = TxOptions;
#undef SrcPANId
#undef SrcAddrMode
#undef SrcAddr
#undef DstPANId
#undef DstAddrMode
#undef DstAddr
#undef msduLength
#undef msduHandle
#undef TxOptions
#undef msdu

                break;
            }

        case mac_mcps_purge_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MCPS_PURGE_request, 1);
                chunk_size += sizeof(primitive->MCPS_PURGE_request);
                break;
            }

        case mac_mlme_associate_request:
            {
                copy_data_in = 0;

#define LogicalChannel (primitive->MLME_ASSOCIATE_request.LogicalChannel)
#define CoordAddrMode  (primitive->MLME_ASSOCIATE_request.CoordAddrMode)
#define CoordAddr      (primitive->MLME_ASSOCIATE_request.CoordAddr)
#define CoordPANId     (primitive->MLME_ASSOCIATE_request.CoordPANId)
#define CapabilityInfo (primitive->MLME_ASSOCIATE_request.CapabilityInfo)
#define SecurityEnable (primitive->MLME_ASSOCIATE_request.SecurityEnable)
                assert(LogicalChannel <= 26);
                assert((CoordAddrMode == mac_short_address) || (CoordAddrMode == mac_extended_address));
                assert((CapabilityInfo & 0x30) == 0);

                buffer[chunk_size++] = LogicalChannel;
                buffer[chunk_size++] = CoordAddrMode;
                buffer[chunk_size++] = CoordPANId & 0xff;
                buffer[chunk_size++] = CoordPANId >> 8;
                if (CoordAddrMode == mac_short_address) {
                    buffer[chunk_size++] = CoordAddr.ShortAddress & 0xff;
                    buffer[chunk_size++] = CoordAddr.ShortAddress >> 8;
                } else if (CoordAddrMode == mac_extended_address) {
                    memcpy (&buffer[chunk_size], CoordAddr.ExtendedAddress, 8);
                    chunk_size += 8;
                }
                buffer[chunk_size++] = CapabilityInfo;
                buffer[chunk_size++] = SecurityEnable;
#undef LogicalChannel
#undef CoordAddrMode
#undef CoordAddr
#undef CoordPANId
#undef CapabilityInfo
#undef SecurityEnable

                break;
            }

        case mac_mlme_associate_response:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_ASSOCIATE_response, 12);
                chunk_size += sizeof(primitive->MLME_ASSOCIATE_response);

#define Status primitive->MLME_ASSOCIATE_response.Status
                assert((Status >= mac_association_successful) && (Status <= mac_pan_access_denied));
#undef Status
                break;
            }

        case mac_mlme_disassociate_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_DISASSOCIATE_request, 10);
                chunk_size += sizeof(primitive->MLME_DISASSOCIATE_request);
                break;
            }

        case mac_mlme_get_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_GET_request, 1);
                chunk_size += sizeof(primitive->MLME_GET_request);

#define PIBAttribute primitive->MLME_GET_request.PIBAttribute
                assert(((PIBAttribute >= phyCurrentChannel) && (PIBAttribute <= phyCCAMode))
                     ||((PIBAttribute >= macAckWaitDuration) && (PIBAttribute <= macTransactionPersistenceTime))
                     || (PIBAttribute == macIEEEAddress)
                     ||((PIBAttribute >= macACLEntryDescriptorSet) && (PIBAttribute <= macSecurityMode))
                      );
#undef PIBAttribute
                break;
            }

        case mac_mlme_gts_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_GTS_request, 2);
                chunk_size += sizeof(primitive->MLME_GTS_request);

                assert((primitive->MLME_GTS_request.GTSCharacteristics & 0xc0) == 0);
                break;
            }

        case mac_mlme_orphan_response:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_ORPHAN_response, 11);
                chunk_size += sizeof(primitive->MLME_ORPHAN_response);
                break;
            }

        case mac_mlme_reset_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_RESET_request, 1);
                chunk_size += sizeof(primitive->MLME_RESET_request);
                break;
            }

        case mac_mlme_rx_enable_request:
            {
                copy_data_in = 0;

#define DeferPermit  (primitive->MLME_RX_ENABLE_request.DeferPermit)
#define RxOnTime     (primitive->MLME_RX_ENABLE_request.RxOnTime)
#define RxOnDuration (primitive->MLME_RX_ENABLE_request.RxOnDuration)
                assert ((RxOnTime & 0xff000000) == 0);
                assert ((RxOnDuration & 0xff000000) == 0);

                buffer[2] = DeferPermit;
                buffer[3] = RxOnTime & 0xff;
                buffer[4] = (RxOnTime >> 8) & 0xff;
                buffer[5] = (RxOnTime >> 16) & 0xff;
                buffer[6] = RxOnDuration & 0xff;
                buffer[7] = (RxOnDuration >> 8) & 0xff;
                buffer[8] = (RxOnDuration >> 16) & 0xff;
                chunk_size += 7; //see below for what's in here
#undef DeferPermit
#undef RxOnTime
#undef RxOnDuration

                break;
            }

        case mac_mlme_scan_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_SCAN_request, 6);
                chunk_size += sizeof(primitive->MLME_SCAN_request);

                assert( primitive->MLME_SCAN_request.ScanType <= mac_orphan_scan);
                assert((primitive->MLME_SCAN_request.ScanChannels & 0xf8000000) == 0);
                assert( primitive->MLME_SCAN_request.ScanDuration <= 14);
                break;
            }

        case mac_mlme_set_request:
            {
                copy_data_in = 0;

#define PIBAttribute      primitive->MLME_SET_request.PIBAttribute
#define PIBAttributeSize  primitive->MLME_SET_request.PIBAttributeSize
#define PIBAttributeValue primitive->MLME_SET_request.PIBAttributeValue
                assert ( ((PIBAttribute >= phyCurrentChannel) && (PIBAttribute <= phyCCAMode))
                      || ((PIBAttribute >= macAckWaitDuration) && (PIBAttribute <= macTransactionPersistenceTime))
                      ||  (PIBAttribute == macIEEEAddress)
                      || ((PIBAttribute >= macACLEntryDescriptorSet) && (PIBAttribute <= macSecurityMode))
                       );

                static uint8_t beaconPayloadLength = 0;
                static uint8_t aclEntryDescriptorSetSize = 0;
                static uint8_t defaultSecurityMaterialLength = 0;

                uint8_t attribute_length = 0;
                switch(PIBAttribute) {
                    case macBeaconPayload:
                        attribute_length = beaconPayloadLength;
                        break;

                    case macACLEntryDescriptorSet:
                        attribute_length = aclEntryDescriptorSetSize;
                        break;

                    case macDefaultSecurityMaterial:
                        attribute_length = defaultSecurityMaterialLength;
                        break;

                    default:
                        attribute_length = mac_pib_attribute_length(PIBAttribute);
                        break;
                }

                if(attribute_length != 0) {
                    if(PIBAttributeSize != 0) {
                        assert(attribute_length == PIBAttributeSize);

                        if(!(attribute_length == PIBAttributeSize))
                            return 0;
                    }
                } else {
                    assert(PIBAttributeSize != 0);
                    if(PIBAttributeSize == 0)
                        return 0;

                    attribute_length = PIBAttributeSize;
                }

                switch(PIBAttribute) {
                    case macBeaconPayloadLength:
                        beaconPayloadLength = PIBAttributeValue[0];
                        break;

                    case macACLEntryDescriptorSetSize:
                        aclEntryDescriptorSetSize  = PIBAttributeValue[0];
                        break;

                    case macDefaultSecurityMaterialLength:
                        defaultSecurityMaterialLength  = PIBAttributeValue[0];
                        break;
                }

                //chunk_size = 2 here. remember, 0th byte is the block size, and 1st is type
                buffer[chunk_size++] = PIBAttribute;
                memcpy(&buffer[chunk_size], PIBAttributeValue, attribute_length);
                chunk_size += attribute_length;
#undef PIBAttribute
#undef PIBAttributeSize
#undef PIBAttributeValue

                break;
            }

        case mac_mlme_start_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_START_request, 5);
                chunk_size += sizeof(primitive->MLME_START_request);

#define BeaconOrder     primitive->MLME_START_request.BeaconOrder
#define SuperframeOrder primitive->MLME_START_request.SuperframeOrder
                assert(primitive->MLME_START_request.LogicalChannel <= 26);
                assert(BeaconOrder <= 15);
                assert((SuperframeOrder <= BeaconOrder) || (SuperframeOrder == 15));
#undef BeaconOrder
#undef SuperframeOrder
                break;
            }

        case mac_mlme_sync_request:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_SYNC_request, 2);
                chunk_size += sizeof(primitive->MLME_SYNC_request);

                assert(primitive->MLME_SYNC_request.LogicalChannel <= 26);
                break;
            }

        case mac_mlme_poll_request:
            {
                copy_data_in = 0;

#define CoordAddrMode  (primitive->MLME_POLL_request.CoordAddrMode)
#define CoordAddress   (primitive->MLME_POLL_request.CoordAddress)
#define CoordPANId     (primitive->MLME_POLL_request.CoordPANId)
#define SecurityEnable (primitive->MLME_POLL_request.SecurityEnable)
                assert((CoordAddrMode == mac_short_address) || (CoordAddrMode == mac_extended_address));
                assert(CoordPANId != 0xfffe);

                buffer[chunk_size++] = CoordAddrMode;
                buffer[chunk_size++] = CoordPANId & 0xff;
                buffer[chunk_size++] = CoordPANId >> 8;
                if (CoordAddrMode == mac_short_address) {
                    buffer[chunk_size++] = CoordAddress.ShortAddress & 0xff;
                    buffer[chunk_size++] = CoordAddress.ShortAddress >> 8;
                } else {
                    memcpy (&buffer[chunk_size], CoordAddress.ExtendedAddress, 8);
                    chunk_size += 8;
                }
                buffer[chunk_size++] = SecurityEnable;
#undef CoordAddrMode
#undef CoordAddress
#undef CoordPANId
#undef SecurityEnable

                break;
            }

        default:
            return 0;
    }

    assert(chunk_size < sizeof(mac_primitive_t));
    buffer[0] = chunk_size - 1; //-1 so we don't count the size byte
    if(copy_data_in) {
        memcpy(buffer + 1, primitive, chunk_size - 1); //+ 1 to skip size byte
    } else {
        buffer[1] = primitive->type;
    }

#ifdef MAC_DEBUG
    printf("%s: ", __FUNCTION__);
    mac_print_primitive (buffer + 1, buffer[0]);
#endif

    int bytes_written = 0;
    while(bytes_written < chunk_size) {
        int retval = write(session.fd, buffer + bytes_written, chunk_size - bytes_written);
        assert(retval > 0);
        if(retval < 0) {
            return retval;
        }
        bytes_written += retval;
    }
    assert(bytes_written == chunk_size);

    return bytes_written;
}

int mac_receive(mac_session_handle_t session, mac_primitive_t* primitive) {
    uint8_t buffer[sizeof(mac_primitive_t)];

    assert(MAC_IS_SESSION_VALID(session));
    if(!MAC_IS_SESSION_VALID(session))
        return -SN_ERR_NULL;
    assert(primitive != NULL);
    if(primitive == NULL)
        return -SN_ERR_NULL;

    struct __attribute__((packed)) {
        uint32_t timestamp;
        uint8_t  length;
    } primitive_header;
    GUARANTEE_STRUCT_SIZE(primitive_header, 5);

    //Read header, which consists of 4B timestamp, and 1B length
    if(read(session.fd, &primitive_header, sizeof(primitive_header)) != sizeof(primitive_header)) {
        //Header read failed
        return 0;
    }

    //check data size, and abort if if would be too large or too small
    assert(primitive_header.length > 0);
    assert(primitive_header.length <= sizeof(mac_primitive_t));
    if(primitive_header.length == 0 || primitive_header.length > sizeof(mac_primitive_t))
        return 0;

    //Read primitive itself to a temporary buffer for decoding
    memset(buffer, 0, sizeof(mac_primitive_t));
    int bytes_read = 0;
    while(bytes_read < primitive_header.length) {
        int retval = read(session.fd, buffer + bytes_read, primitive_header.length - bytes_read);

        assert(retval > 0);
        if(retval < 0) {
            return 0;
        }

        bytes_read += retval;
    }
    assert(primitive_header.length == bytes_read);

#ifdef MAC_DEBUG
    printf("%s : ", __FUNCTION__);
    mac_print_primitive (buffer, primitive_header.length);
#endif

    //First byte identifies the primitive we've been sent
    primitive->type = buffer[0];

    switch(primitive->type) {
        //XXX: the code blocks with lots of CPP directives are copy-pasted from the old process_xxx functions
        case mac_mcps_data_indication:
            {
#define SrcPANId    (primitive->MCPS_DATA_indication.SrcPANId)
#define SrcAddrMode (primitive->MCPS_DATA_indication.SrcAddrMode)
#define SrcAddr     (primitive->MCPS_DATA_indication.SrcAddr)
#define DstPANId    (primitive->MCPS_DATA_indication.DstPANId)
#define DstAddrMode (primitive->MCPS_DATA_indication.DstAddrMode)
#define DstAddr     (primitive->MCPS_DATA_indication.DstAddr)
#define msduLength  (primitive->MCPS_DATA_indication.msduLength)
#define mpduLinkQuality (primitive->MCPS_DATA_indication.mpduLinkQuality)
#define SecurityUse (primitive->MCPS_DATA_indication.SecurityUse)
#define ACLEntry    (primitive->MCPS_DATA_indication.ACLEntry)
#define msdu        (primitive->MCPS_DATA_indication.msdu)
                uint8_t* data = buffer + 1;

                assert(primitive_header.length - 1 >= 5);
                //FIXME: Need to do more validation on length

                SrcAddrMode = *data++;
                SrcPANId = (data[1] << 8) | data[0];
                if (SrcAddrMode == mac_short_address) {
                    SrcAddr.ShortAddress = (data[3] << 8) | data[2];
                    data += 4;
                } else if (SrcAddrMode == mac_extended_address) {
                    memcpy(SrcAddr.ExtendedAddress, &data[2], 8);
                    data += 10;
                } else {
                    assert(SrcAddrMode == mac_no_address);
                    //if we get a weird address mode, die and send back the raw bytes
                    if(SrcAddrMode != mac_no_address) {
                        goto raw;
                    }
                }

                DstAddrMode = *data++;
                DstPANId = (data[1] << 8) | data[0];
                if (DstAddrMode == mac_short_address) {
                    DstAddr.ShortAddress = (data[3] << 8) | data[2];
                    data += 4;
                } else if (DstAddrMode == mac_extended_address) {
                    memcpy(DstAddr.ExtendedAddress, &data[2], 8);
                    data += 10;
                } else {
                    assert(DstAddrMode == mac_no_address);
                    //if we get a weird address mode, die and send back the raw bytes
                    if(DstAddrMode != mac_no_address) {
                        goto raw;
                    }
                }

                msduLength = data[0];
                assert(msduLength == primitive_header.length - ((data - buffer) + 1 + 2));
                if(msduLength != primitive_header.length - ((data - buffer) + 1 + 2)) {
                    //if this expression doesn't hold, we have a malformed packet. die and send back the raw bytes
                    goto raw;
                }
                memcpy(msdu, data + 1, msduLength);
                data += msduLength + 1;
                mpduLinkQuality = data[0];
                SecurityUse = data[1] & 1;
                ACLEntry = (data[1] >> 1) & 0xf;
                data += 2;

                assert(data - buffer == primitive_header.length);

#undef SrcPANId
#undef SrcAddrMode
#undef SrcAddr
#undef DstPANId
#undef DstAddrMode
#undef DstAddr
#undef msduLength
#undef mpduLinkQuality
#undef SecurityUse
#undef ACLEntry
#undef msdu

                break;
            }
        case mac_mlme_beacon_notify_indication:
            {
#define BSN           primitive->MLME_BEACON_NOTIFY_indication.BSN
#define PANDescriptor primitive->MLME_BEACON_NOTIFY_indication.PANDescriptor
#define PendAddrSpec  primitive->MLME_BEACON_NOTIFY_indication.PendAddrSpec
#define AddrList      primitive->MLME_BEACON_NOTIFY_indication.AddrList
#define sduLength     primitive->MLME_BEACON_NOTIFY_indication.sduLength
#define sdu           primitive->MLME_BEACON_NOTIFY_indication.sdu
                int i = 0;
                uint8_t* data = buffer + 1;

                if (primitive_header.length < 17) {
                    return 0;
                }

                i = 0;
                BSN = data[i++];
                i += extract_pan_descriptor (&data[i], &PANDescriptor);
                if (i == 1) {
                    /* PAN descriptor was invalid */
                    return 0;
                }
                PendAddrSpec.raw = data[i++];
                for(int j = 0; j < PendAddrSpec.Short; j++) {
                    memcpy(&AddrList.Short[j], &data[i], 2);
                    i += 2;
                }
                for(int j = 0; j < PendAddrSpec.Extended; j++) {
                    memcpy(&AddrList.Extended[j], &data[i], 8);
                    i += 8;
                }

                sduLength = data[i++];
                assert(sduLength <= primitive_header.length - i);
                if(sduLength > primitive_header.length - i) {
                    return 0;
                }
                memcpy(sdu, &data[i], sduLength);
#undef BSN
#undef PANDescriptor
#undef PendAddrSpec
#undef AddrList
#undef sduLength
#undef sdu

                break;
            }
        case mac_mlme_get_confirm:
            {
                assert(primitive_header.length - 1 >= 3);
                memcpy(&primitive->MLME_GET_confirm, buffer + 1, primitive_header.length - 1);
                unsigned int l = mac_pib_attribute_length(primitive->MLME_GET_confirm.PIBAttribute);
                if(l != 0) {
                    assert(primitive_header.length - 1 == 2 + l);
                }
                break;
            }
        case mac_mlme_scan_confirm:
            {
                //GUARANTEE_STRUCT_SIZE(primitive->MLME_SCAN_confirm.Header, 7);
                //TODO: some kind of static assertion regarding the thing's structure
                assert(primitive_header.length - 1 >= 7);
                memcpy(&primitive->MLME_SCAN_confirm, buffer + 1, 7);

                switch(primitive->MLME_SCAN_confirm.ScanType) {
                    case mac_active_scan:
                    case mac_passive_scan:
                        {
                            uint8_t* data = buffer + 8;
                            assert(primitive->MLME_SCAN_confirm.ResultListSize <= sizeof(primitive->MLME_SCAN_confirm.PANDescriptorList) / sizeof(mac_pan_descriptor_t));
                            for(int i = 0; i < primitive->MLME_SCAN_confirm.ResultListSize; i++) {
                                int size = extract_pan_descriptor(data, &primitive->MLME_SCAN_confirm.PANDescriptorList[i]);
                                assert(size != 0);
                                data += size;
                            }
                        }
                        break;

                    case mac_energy_detect_scan:
                        memcpy(primitive->MLME_SCAN_confirm.EnergyDetectList, buffer + 8, primitive->MLME_SCAN_confirm.ResultListSize);
                        break;

                    default:
                        //this should be impossible
                        assert(0);
                        return 0;
                }
                break;
            }
        case mac_mlme_comm_status_indication:
            {
#define PANId       primitive->MLME_COMM_STATUS_indication.PANId
#define SrcAddrMode primitive->MLME_COMM_STATUS_indication.SrcAddrMode
#define SrcAddr     primitive->MLME_COMM_STATUS_indication.SrcAddr
#define DstAddrMode primitive->MLME_COMM_STATUS_indication.DstAddrMode
#define DstAddr     primitive->MLME_COMM_STATUS_indication.DstAddr
#define Status      primitive->MLME_COMM_STATUS_indication.status
                uint8_t* data = buffer + 1;

                //XXX: this is pasted from the old process_XXX fn

                assert(primitive_header.length - 1 >= 5);
                assert(primitive_header.length - 1 <= 17);
                /* FIXME: Need to do more validation on length */
                PANId = (data[1] << 8) | data[0];
                data += 2;
                SrcAddrMode = *data++;
                if (SrcAddrMode == mac_short_address) {
                    SrcAddr.ShortAddress = (data[1] << 8) | data[0];
                    data += 2;
                } else if (SrcAddrMode == mac_extended_address) {
                    memcpy(SrcAddr.ExtendedAddress, &data[4], 8);
                    data += 8;
                } else {
                    //FIXME: more validation on SrcAddrMode
                    assert(SrcAddrMode == mac_no_address);
                }
                DstAddrMode = *data++;
                if (DstAddrMode == mac_short_address) {
                    DstAddr.ShortAddress = (data[1] << 8) | data[0];
                    data += 2;
                } else if (DstAddrMode == mac_extended_address) {
                    memcpy(DstAddr.ExtendedAddress, &data[4], 8);
                    data += 8;
                } else {
                    //FIXME: more validation on DstAddrMode
                    assert(DstAddrMode == mac_no_address);
                }
                Status = *data++;

                assert(data - buffer == primitive_header.length);
#undef PANId
#undef SrcAddrMode
#undef SrcAddr
#undef DstAddrMode
#undef DstAddr
#undef Status

                break;
            }
        case mac_mcps_data_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MCPS_DATA_confirm, 2);
                assert(primitive_header.length - 1 == sizeof(primitive->MCPS_DATA_confirm));
                memcpy(&primitive->MCPS_DATA_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mcps_purge_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MCPS_PURGE_confirm, 2);
                assert(primitive_header.length - 1 == sizeof(primitive->MCPS_PURGE_confirm));
                memcpy(&primitive->MCPS_PURGE_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_associate_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_ASSOCIATE_confirm, 3);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_ASSOCIATE_confirm));
                memcpy(&primitive->MLME_ASSOCIATE_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_associate_indication:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_ASSOCIATE_indication, 10);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_ASSOCIATE_indication));
                memcpy(&primitive->MLME_ASSOCIATE_indication, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_disassociate_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_DISASSOCIATE_confirm, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_DISASSOCIATE_confirm));
                memcpy(&primitive->MLME_DISASSOCIATE_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_disassociate_indication:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_DISASSOCIATE_indication, 10);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_DISASSOCIATE_indication));
                memcpy(&primitive->MLME_DISASSOCIATE_indication, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_gts_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_GTS_confirm, 2);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_GTS_confirm));
                memcpy(&primitive->MLME_GTS_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_gts_indication:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_GTS_indication, 4);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_GTS_indication));
                memcpy(&primitive->MLME_GTS_indication, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_orphan_indication:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_ORPHAN_indication, 9);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_ORPHAN_indication));
                memcpy(&primitive->MLME_ORPHAN_indication, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_reset_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_RESET_confirm, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_RESET_confirm));
                memcpy(&primitive->MLME_RESET_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_rx_enable_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_RX_ENABLE_confirm, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_RX_ENABLE_confirm));
                memcpy(&primitive->MLME_RX_ENABLE_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_set_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_SET_confirm, 2);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_SET_confirm));
                memcpy(&primitive->MLME_SET_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_start_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_START_confirm, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_START_confirm));
                memcpy(&primitive->MLME_START_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_sync_loss_indication:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_SYNC_LOSS_indication, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_SYNC_LOSS_indication));
                memcpy(&primitive->MLME_SYNC_LOSS_indication, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_poll_confirm:
            {
                //struct matches what we get from the radio
                GUARANTEE_STRUCT_SIZE(primitive->MLME_POLL_confirm, 1);
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_POLL_confirm));
                memcpy(&primitive->MLME_POLL_confirm, buffer + 1, primitive_header.length - 1);
                break;
            }
        case mac_mlme_protocol_error_indication:
            {
                GUARANTEE_STRUCT_SIZE(primitive->MLME_PROTOCOL_ERROR_indication, 1);
                //struct matches what we get from the radio
                assert(primitive_header.length - 1 == sizeof(primitive->MLME_PROTOCOL_ERROR_indication));
                memcpy(&primitive->MLME_PROTOCOL_ERROR_indication, buffer + 1, primitive_header.length - 1);
                break;
            }

        default:
            goto raw;
    }

    return primitive_header.length;

raw:
#ifdef MAC_DEBUG
    printf("%s: copying raw...\n", __FUNCTION__);
#endif
    memcpy(primitive->raw_data, buffer, primitive_header.length);
    return -primitive_header.length;
}


int mac_receive_primitive_type(mac_session_handle_t session, mac_primitive_t* primitive, mac_primitive_type_t type) {
    assert(primitive != NULL);

    int rev = mac_receive(session, primitive);

    if(rev == 0) //on error die
        return -1;

    if(primitive->type != type) { //if it doesn't match, try again
#ifdef MAC_DEBUG
        printf("%s: dropping non-matching primitive of type %d\n", __FUNCTION__, primitive->type);
#endif //MAC_DEBUG
        return mac_receive_primitive_type(session, primitive, type);
    } else
        return rev;
}

int mac_receive_primitive_types(mac_session_handle_t session, mac_primitive_t* primitive, const mac_primitive_type_t* primitive_types, unsigned int primitive_type_count) {
    assert(primitive != NULL);

    int rev = mac_receive(session, primitive);

    if(rev == 0) //on error die
        return -1;

    //if it matches any of the requested types, return
    for(int i = 0; i < primitive_type_count; i++)
        if(primitive->type == primitive_types[i])
            return rev;

#ifdef MAC_DEBUG
    printf("%s: dropping non-matching primitive of type %d\n", __FUNCTION__, primitive->type);
#endif //MAC_DEBUG

    //if it doesn't match, try again
    return mac_receive_primitive_types(session, primitive, primitive_types, primitive_type_count);
}

int mac_receive_primitive_exactly(mac_session_handle_t session, const mac_primitive_t* primitive) {
    assert(primitive != NULL);

    mac_primitive_t temp;
    int rev = mac_receive_primitive_type(session, &temp, primitive->type); //XXX: is this a bug?

    if(rev == 0) //on error die
        return -1;

    if(rev < 0) //if we don't understand the thing, who cares
        rev = -rev;

    if(memcmp(&temp, primitive, rev)) {
        //they're different
#ifdef MAC_DEBUG
        printf("wanted: ");
        mac_print_primitive((uint8_t*)primitive, rev);
        printf("got   : ");
        mac_print_primitive((uint8_t*)&temp, rev);
#endif
        return 0;

    } else {
        //they're the same
        return 1;
    }
}


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
                        mac_address_mode_t mode = va_arg (ap, unsigned int);
                        uint16_t panid = va_arg (ap, unsigned int);
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
                        mac_address_mode_t mode = va_arg (ap, unsigned int);
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
    mac_session_handle_t handle = {
        .fd = open(params, O_RDWR)
    };
    return handle;
}

void mac_destroy(mac_session_handle_t handle) {
    if(MAC_IS_SESSION_VALID(handle)) {
        close(handle.fd);
    }
}
