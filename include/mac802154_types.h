#ifndef __MAC802154_TYPES_H__
#define __MAC802154_TYPES_H__

#include <stdint.h>

/* MAC/PHY constants (using notation from the 802.15.4 spec) */
#define aMaxPHYPacketSize                       127
#define aTurnaroundTime                         12
#define aBaseSlotDuration                       60 /* in symbols */
#define aNumSuperframeSlots                     16
#define aBaseSuperframeDuration                 (aBaseSlotDuration * aNumSuperframeSlots) /* in symbols */
#define aGTSDescPersistenceTime                 4
#define aMaxBeaconOverhead                      75
#define aMaxBeaconPayloadSize                   (aMaxPHYPacketSize - aMaxBeaconOverhead)
#define aMaxLostBeacons                         4
#define aMaxMPDUUnsecuredOverhead               25
#define aMinMPDUOverhead                        9
#define aMaxMACSafePayloadSize                  (aMaxPHYPacketSize - aMaxMPDUUnsecuredOverhead)
#define aMaxMACPayloadSize                      (aMaxPHYPacketSize - aMinMPDUOverhead)
#define aMaxSIFSFrameSize                       18
#define aMinCAPLength                           440
#define aUnitBackoffPeriod                      20
#define aMaxACLEntries                          10
#define aMaxSecurityMaterialLength              0x1a
#define aSymbolsPerSecond_24                    62500
#define aMaxMACSecurityOverhead                 (5 /* AuxLen */ + 16 /* AuthLen for MIC-128 */)

/* Session object */
typedef union mac_session_handle {
    int   fd;
    void* meta;
} mac_session_handle_t;
#define MAC_IS_SAME_SESSION(s1, s2) ((s1).meta == (s2).meta)
#define MAC_IS_SESSION_VALID(s1)    ((s1).meta != NULL)

/* Addressing modes */
enum mac_address_mode {
    mac_no_address       = 0x0,
    mac_short_address    = 0x2,
    mac_extended_address = 0x3,
};
typedef uint8_t mac_address_mode_t;

/* Address */
typedef union mac_address {
    uint16_t ShortAddress;
    uint8_t  ExtendedAddress[8];
} mac_address_t;

/* PAN Identifier */
typedef uint16_t mac_pan_id_t;

/* PAN descriptor */
typedef struct mac_pan_descriptor {
    uint32_t           TimeStamp;
    uint16_t           SuperframeSpec;
    mac_pan_id_t       CoordPANId; //2B
    mac_address_t      CoordAddress; //8B
    mac_address_mode_t CoordAddrMode;
    uint8_t            LogicalChannel;
    uint8_t            LinkQuality;
    struct {
        uint8_t        SecurityFailure :1;
        uint8_t        SecurityUse     :1;
        uint8_t        GTSPermit       :1;
        uint8_t        ACLEntry        :4;
        uint8_t        mbz             :1;
    };
} mac_pan_descriptor_t;

/* ACL Entry Descriptor */
typedef struct mac_acl_entry_descriptor {
    mac_address_t ACLExtendedAddress;
    uint16_t      ACLShortAddress;
    mac_pan_id_t  ACLPANId;
    uint8_t       ACLSecurityMaterialLength;
    uint8_t       ACLSecurityMaterial[aMaxSecurityMaterialLength];
    uint8_t       ACLSecuritySuite;
} mac_acl_entry_descriptor_t;

typedef struct mac_mib {
    uint8_t                    macAckWaitDuration;
    uint8_t                    macAssociationPermit;
    uint8_t                    macAutoRequest;
    uint8_t                    macBattLifeExt;
    uint8_t                    macBattLifeExtPeriods;
    uint8_t                    macBeaconPayload[aMaxBeaconPayloadSize];
    uint8_t                    macBeaconPayloadLength;
    uint8_t                    macBeaconOrder;
    uint32_t                   macBeaconTxTime;
    uint8_t                    macBSN;
    uint8_t                    macCoordAddrMode;
    mac_address_t              macCoordExtendedAddress;
    uint16_t                   macCoordShortAddress;
    uint8_t                    macDSN;
    uint8_t                    macGTSPermit;
    uint8_t                    macMaxCSMABackoffs;
    uint8_t                    macMinBE;
    mac_pan_id_t               macPANId;
    uint8_t                    macPromiscuousMode;
    uint8_t                    macRxOnWhenIdle;
    uint16_t                   macShortAddress;
    uint8_t                    macSuperframeOrder;
    uint16_t                   macTransactionPersistenceTime;
    mac_address_t              macIEEEAddress;
    mac_acl_entry_descriptor_t macACLEntryDescriptorSet[aMaxACLEntries];
    uint8_t                    macACLEntryDescriptorSetSize;
    uint8_t                    macDefaultSecurity;
    uint8_t                    macDefaultSecurityMaterialLength;
    uint8_t                    macDefaultSecurityMaterial[aMaxSecurityMaterialLength];
    uint8_t                    macDefaultSecuritySuite;
    uint8_t                    macSecurityMode;
    uint8_t                    macACLEntryDescriptorNumber;
} mac_mib_t;

typedef struct mac_pib {
    uint8_t                    phyCurrentChannel;
    uint32_t                   phyChannelsSupported;
    uint8_t                    phyTransmitPower;
    uint8_t                    phyCCAMode;
} mac_pib_t;

#endif /* __MAC802154_TYPES_H__ */
