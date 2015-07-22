#ifndef STARFISHNET_NONQUEUED_TRANSMISSION_H
#define STARFISHNET_NONQUEUED_TRANSMISSION_H

#include "types.h"
#include "node_table.h"

/* Transmit the packet in the packetbuf, using
 * the routing subsystem to calculate the next hop address.
 */
int8_t SN_Forward_Packetbuf(uint16_t source, uint16_t destination);
int8_t SN_Send_acknowledgements(SN_Table_entry_t* entry);

#endif //STARFISHNET_NONQUEUED_TRANSMISSION_H
