#include <sn_core.h>
#include <sn_status.h>
#include <sn_table.h>
#include <sn_logging.h>
#include <mac802154.h>

#include "mac_util.h"

#include <assert.h>
#include <string.h>

//copies the configuration out of session into the space provided. anything but session can be NULL
int SN_Get_configuration(SN_Session_t* session, SN_Nib_t* nib, mac_mib_t* mib, mac_pib_t* pib) {
    //Assumption: config is kept current!
    mac_primitive_t packet;

    if(session == NULL) {
        return -SN_ERR_NULL;
    }

    if(nib != NULL) {
        memcpy(nib, &session->nib, sizeof(*nib));
    }

    if(mib != NULL) {
        //load macDSN
        packet.type                          = mac_mlme_get_request;
        packet.MLME_SET_request.PIBAttribute = macDSN;
        MAC_CALL(mac_transmit, session->mac_session, &packet);
        MAC_CALL(mac_receive_primitive_type, session->mac_session, &packet, mac_mlme_get_confirm);
        assert(packet.type == mac_mlme_get_confirm);
        assert(packet.MLME_GET_confirm.PIBAttribute == macDSN);
        memcpy(&session->mib.macDSN, packet.MLME_GET_confirm.PIBAttributeValue, mac_pib_attribute_length(packet.MLME_GET_confirm.PIBAttribute));

        memcpy(mib, &session->mib, sizeof(*mib));
    }

    if(pib != NULL) {
        memcpy(pib, &session->pib, sizeof(*pib));
    }

    return SN_OK;
}

//copies the configuration provided into session, updating lower layers as necessary. anything but session can be NULL
int SN_Set_configuration(SN_Session_t* session, SN_Nib_t* nib, mac_mib_t* mib, mac_pib_t* pib) {
    //Assumption: config is kept current!

    if(session == NULL) {
        return -SN_ERR_NULL;
    }

    //TODO: for each information base, check each member, and set the ones that have changed
    //      (obviously, ignoring the ones we're not supposed to set)

    return -SN_ERR_UNIMPLEMENTED;
}

//other network-layer driver functions
int SN_Init(SN_Session_t* session, SN_Keypair_t* master_keypair, char* params) {
    SN_InfoPrintf("enter\n");

    assert(session != NULL);

    if(session == NULL) {
        SN_ErrPrintf("session may not be NULL\n");
        return -SN_ERR_NULL;
    }

    //allocate some stack space
    SN_Session_t protosession;
    memset(&protosession, 0, sizeof(protosession));

    //init the mac layer
    SN_InfoPrintf("initialising MAC layer...\n");
    protosession.mac_session = mac_init(params);
    assert(MAC_IS_SESSION_VALID(protosession.mac_session));
    if(!MAC_IS_SESSION_VALID(protosession.mac_session)) {
        SN_ErrPrintf("MAC init failed\n");
        return -SN_ERR_RADIO;
    }

    //reset the radio
    mac_primitive_t packet;
    SN_InfoPrintf("resetting radio...\n");
    int ret = mac_reset_radio(&protosession, &packet);
    if(ret != SN_OK) {
        SN_ErrPrintf("radio reset failed: %d\n", -ret);
        return ret;
    }

    //fill in the master keypair
    protosession.device_root_key = *master_keypair;

    //return results
    *session = protosession;

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

void SN_Destroy(SN_Session_t* session) { //bring down this session, resetting the radio in the process
    mac_primitive_t packet;
    SN_InfoPrintf("enter\n");

    /*TODO: (operations on disconnect)
     * revoke all children's short-address allocations
     * release my short-address allocation(s)
     * terminate all SAs
     */

    //clean out the node table
    SN_InfoPrintf("clearing node table...\n");
    SN_Table_clear(session);

    //reset the radio
    SN_InfoPrintf("resetting radio...\n");
    mac_reset_radio(session, &packet);

    //close up the MAC-layer session
    SN_InfoPrintf("bringing down MAC layer...\n");
    mac_destroy(session->mac_session);

    //clean up I/O buffers
    memset(session, 0, sizeof(*session));
    SN_InfoPrintf("exit\n");
}

static void struct_checks() __attribute__((unused));

static void struct_checks() {
    SN_Message_t message;

    _Static_assert((uint8_t*)&message.type == (uint8_t*)&message.data_message.type,
        "SN_Message_t.data_message is misaligned");
    _Static_assert((uint8_t*)&message.type == (uint8_t*)&message.association_message.type,
        "SN_Message_t.association_message is misaligned");
    _Static_assert((uint8_t*)&message.type == (uint8_t*)&message.evidence_message.type,
        "SN_Message_t.evidence_message is misaligned");
}