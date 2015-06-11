#ifndef __SN_DELAYED_TX_H__
#define __SN_DELAYED_TX_H__

#include "node_table.h"
#include "packet.h"

#include <stdbool.h>

//send a packet and then wait for acknowledgement
int SN_Transmission_enqueue(SN_Table_entry_t *table_entry, packet_t *packet, uint32_t counter);

//special hook for routing. does not invoke the retransmission/acknowledgement subsystem
int SN_Transmission_forward(uint16_t source, uint16_t destination, packet_t *packet);

//notify the retransmission system that an encrypted packet has been acknowledged
int SN_Transmission_acknowledge(SN_Table_entry_t *table_entry, uint32_t counter);

//acknowledgement notification function for special treatment of association packets
int SN_Transmission_acknowledge_special(SN_Table_entry_t *table_entry, packet_t *packet);

//tell the retransmission subsystem that a time tick has elapsed
void SN_Transmission_retry(bool count_towards_disconnection);

//inform the retransmission subsystem that a session is being cleared
void SN_Transmission_clear();

#endif /*  __SN_DELAYED_TX_H__ */