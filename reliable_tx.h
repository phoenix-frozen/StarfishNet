#ifndef __SN_DELAYED_TX_H__
#define __SN_DELAYED_TX_H__

#include "node_table.h"
#include "packet.h"

#include <stdbool.h>

/* Engage the transmission subsystem on a packet.
 *
 * This function will transmit it once, and wait for acknowledgement.
 * Further retransmissions will be handled automatically.
 *
 * It is assumed that the packet's data is in the packetbuf.
 */
int SN_Retransmission_send(SN_Table_entry_t* table_entry, packet_t* packet, uint32_t counter);

/* Notify the retransmission system that a data packet has been acknowledged,
 * and should no longer be retransmitted.
 */
int SN_Retransmission_acknowledge_data(SN_Table_entry_t* table_entry, uint32_t counter);

/* Notify the retransmission system that a non-data packet has been acknowledged,
 * and should no longer be retransmitted.
 *
 * (This is primarily for association packets, which are implicitly acknowledged.)
 */
int SN_Retransmission_acknowledge_implicit(SN_Table_entry_t* table_entry, packet_t* packet);

//tell the retransmission subsystem that a time tick has elapsed
void SN_Retransmission_retry(bool count_towards_disconnection);

//inform the retransmission subsystem that a session is being cleared
void SN_Retransmission_clear();

#endif /*  __SN_DELAYED_TX_H__ */
