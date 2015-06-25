#ifndef STARFISHNET_RECEIVE_H
#define STARFISHNET_RECEIVE_H

#include "packet.h"

void SN_Receive_data_packet(packet_t* packet, const linkaddr_t* from, uint8_t fromsize);

#endif //STARFISHNET_RECEIVE_H
