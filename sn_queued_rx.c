#include <sn_status.h>
#include "sn_queued_rx.h"
#include <stddef.h>

#ifndef SN_QUEUE_EXPONENT
#define SN_QUEUE_EXPONENT 4 //power of 2
#endif

#define QUEUE_LENGTH   (1 << SN_QUEUE_EXPONENT)
#define QUEUE_MASK     (QUEUE_LENGTH - 1)

struct {
    struct {
        uint8_t valid :1;
        uint8_t mbz   :7;
    };
    SN_Session_t*   session;
    mac_primitive_t packet;
} queue[QUEUE_LENGTH];

uint8_t queue_head = 0; //first free index (raw)
uint8_t queue_tail = 0; // last used index (raw)


int SN_Enqueue(SN_Session_t* session, mac_primitive_t* packet) {
    if(session == NULL || packet == NULL) {
        return -SN_ERR_NULL;
    }

    //we only queue MCPS-DATA.indication
    if(packet->type != mac_mcps_data_indication) {
        return -SN_ERR_UNEXPECTED;
    }

    //queue size check
    if(queue_head - queue_tail == QUEUE_LENGTH) {
        return -SN_ERR_RESOURCES;
    }
    //modular arithmetic is easy in powers of two! :-D
    int idx = queue_head++ & QUEUE_MASK;

    queue[idx].packet = *packet;
    queue[idx].session = session;
    queue[idx].valid = 1;

    return SN_OK;
}

int SN_Dequeue(SN_Session_t* session, mac_primitive_t* packet, uint8_t primitive_type) {
    if(session == NULL || packet == NULL) {
        return -SN_ERR_NULL;
    }

    //we only queue MCPS-DATA.indication
    if(primitive_type != mac_mcps_data_indication) {
        return -SN_ERR_UNEXPECTED;
    }

    //queue size check
    if(queue_head == queue_tail) {
        return -SN_ERR_END_OF_DATA;
    }

    int ret = -SN_ERR_END_OF_DATA;

    //scroll through the queue until we find the next packet from this session
    for(int idx = queue_tail & QUEUE_MASK; idx != (queue_head & QUEUE_MASK); idx = (idx + 1) & QUEUE_MASK) {
        if(queue[idx].valid && queue[idx].session == session) {
            *packet = queue[idx].packet;
            queue[idx].valid = 0;
            ret = SN_OK;
            break;
        }
    }

    //scroll through again, moving the tail to the last used index
    //(this is necessary because we support queueing packets from multiple sessions)
    for(uint8_t idx = queue_tail; idx != queue_head; idx++) {
        if(queue[idx & QUEUE_MASK].valid) {
            queue_tail = idx;
            break;
        }
    }

    return ret;
}
