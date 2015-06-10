#include "sn_core.h"
#include "status.h"
#include "sn_table.h"
#include "logging.h"
#include "sn_delayed_tx.h"

#include <assert.h>
#include <string.h>

//network configuration defaults
#define DEFAULT_TX_RETRY_LIMIT 5
#define DEFAULT_TX_RETRY_TIMEOUT 2500

//other network-layer driver functions
int SN_Init(SN_Session_t* session, SN_Keypair_t* master_keypair, char* params) {
    SN_InfoPrintf("enter\n");

    if(session == NULL || master_keypair == NULL) {
        SN_ErrPrintf("session and master_keypair must be valid\n");
        return -SN_ERR_NULL;
    }

    //make sure the node table is clean
    SN_InfoPrintf("clearing node table...\n");
    SN_Table_clear(session);

    //allocate some stack space
    SN_Session_t protosession = {};

    //fill in the master keypair
    protosession.device_root_key = *master_keypair;

    //fill in some settings
    protosession.nib.tx_retry_limit      = DEFAULT_TX_RETRY_LIMIT;
    protosession.nib.tx_retry_timeout    = DEFAULT_TX_RETRY_TIMEOUT;

    //return results
    *session = protosession;

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
