#ifndef STARFISHNET_NONQUEUED_TRANSMISSION_H
#define STARFISHNET_NONQUEUED_TRANSMISSION_H

#include "types.h"

/* Transmit the packet in the packetbuf, using
 * the routing subsystem to calculate the next hop address.
 */
int SN_TX_Packetbuf(uint16_t source, uint16_t destination);

#endif //STARFISHNET_NONQUEUED_TRANSMISSION_H
