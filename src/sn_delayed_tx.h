#ifndef __SN_DELAYED_TX_H__
#define __SN_DELAYED_TX_H__

#include <sn_table.h>
#include <mac802154.h>

#include "sn_txrx.h"

//send a packet and then wait for acknowledgement
int SN_Delayed_transmit(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet, uint32_t counter);

//notify the retransmission system that an encrypted packet has been acknowledged
int SN_Delayed_acknowledge_encrypted(SN_Table_entry_t* table_entry, uint32_t counter);

//notify the retransmission system that a signed packet has been acknowledged
int SN_Delayed_acknowledge_signed(SN_Table_entry_t* table_entry, SN_Signature_t* signature);

//acknowledgement notification function for special treatment of association packets
int SN_Delayed_acknowledge_special(SN_Table_entry_t* table_entry, packet_t* packet);

//tell the retransmission subsystem that a time tick has elapsed
void SN_Delayed_tick();

//inform the retransmission subsystem that a session is being cleared
void SN_Delayed_clear(SN_Session_t* session);

#endif /*  __SN_DELAYED_TX_H__ */
