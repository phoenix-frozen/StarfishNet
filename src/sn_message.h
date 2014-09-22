#ifndef __SN_MESSAGE_H__
#define __SN_MESSAGE_H__

#include <sn_core.h>

typedef enum {
    //continues on from SN_Message_type_t
    SN_Associate_finalise          //respond to the challenge with a challenge of our own
            = SN_End_of_message_types,
    SN_Address_grant,              //used by a router to assign a short address to its child
    SN_Address_revoke,             //used by a router to revoke a short address from its child
    SN_Address_change_notify,      //inform a StarfishNet node that our short address has changed

    SN_End_of_internal_message_types
} SN_Message_internal_type_t;

typedef union SN_Message_internal {
    //XXX: if you change this, check that SN_Message_network_size is still safe
    uint8_t type;                //SN_Message_type_t

    struct __attribute__((packed)) SN_Data_message data;

    struct __attribute__((packed)) SN_Evidence_message evidence;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Public_key_t public_key;
    } associate_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint8_t         finalise_now;
        SN_Public_key_t public_key;
        SN_Hash_t       challenge1;
    } associate_reply;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_AES_key_id_t challenge2;
    } associate_finalise;

    struct __attribute__((packed)) {
        uint8_t type;             //SN_Message_type_t
        uint8_t is_block_request; //1 if it's a request for an address block, 0 if it's for a single address
    } address_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint8_t         block_size; //size of address block being granted. power of 2
        uint16_t        address;
    } address_grant;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint16_t        address;
    } address_message; //used for Address_release and Address_change

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        uint16_t        short_address;
        mac_address_t   long_address;
        SN_Public_key_t public_key;
    } node_details; //used for Node_details

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Signature_t  signature; //TODO: what does this signature cover?
    } dissociate_request;

    struct __attribute__((packed)) {
        uint8_t         type;    //SN_Message_type_t
        SN_Signature_t  signature;
    } authentication_message;
} SN_Message_internal_t;

int SN_Message_internal_size(SN_Message_internal_t* message);

#endif /* __SN_MESSAGE_H__ */
