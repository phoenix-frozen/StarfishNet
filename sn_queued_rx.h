#ifndef __SN_QUEUED_RX_H__
#define __SN_QUEUED_RX_H__

#include "types.h"

int SN_Enqueue(SN_Session_t* session, mac_primitive_t* packet);
int SN_Dequeue(SN_Session_t* session, mac_primitive_t* packet, uint8_t primitive_type);

#endif //__SN_QUEUED_RX_H__
