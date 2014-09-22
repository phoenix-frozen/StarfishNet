#include <sn_status.h>

#include <assert.h>
#include <stddef.h>

#include "sn_message.h"

int SN_Message_internal_size(SN_Message_internal_t* message) {
    assert(message != NULL);
    //XXX: if you change this, check that SN_Message_network_size is still safe

    if(message == NULL)
        return -SN_ERR_NULL;

    switch(message->type) {
        case SN_Data_message:
            return sizeof(message->data)                    + message->data.payload_length;

        case SN_Evidence_message:
            return sizeof(message->evidence);

        case SN_Associate_request:
            return sizeof(message->associate_request);

        case SN_Associate_reply:
            return sizeof(message->associate_reply);

        case SN_Associate_finalise:
            return sizeof(message->associate_finalise);

        case SN_Address_request:
            return sizeof(message->address_request);

        case SN_Address_grant:
            return sizeof(message->address_grant);

        case SN_Address_release:
        case SN_Address_change_notify:
            return sizeof(message->address_message);

        case SN_Node_details:
            return sizeof(message->node_details);

        case SN_Dissociate_request:
            return sizeof(message->dissociate_request);

        case SN_Authentication_message:
            return sizeof(message->authentication_message);

        default:
            return 1;
    }
}

int SN_Message_network_size(SN_Message_t* message) {
    //XXX: this is currently safe by inspection
    return SN_Message_internal_size((SN_Message_internal_t*)message);
}

int SN_Message_memory_size(SN_Message_t* message) {
    assert(message != NULL);

    if(message == NULL)
        return -SN_ERR_NULL;

    switch(message->type) {
        case SN_Data_message:
            return sizeof(message->data)      + message->data.payload_length;

        case SN_Evidence_message:
            return sizeof(message->evidence);

        default:
            return 1;
    }
}

