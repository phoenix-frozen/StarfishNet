#ifndef __SN_DELAYED_TX_H__
#define __SN_DELAYED_TX_H__

#include <sn_table.h>
#include <mac802154.h>

#include "sn_txrx.h"

int SN_Delayed_transmit(SN_Session_t* session, SN_Table_entry_t* table_entry, packet_t* packet);

//TODO: SN_Delayed_receive
//TODO: SN_Delayed_acknowledge

#endif /*  __SN_DELAYED_TX_H__ */
