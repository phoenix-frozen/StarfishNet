#include "nonqueued_transmission.h"
#include "config.h"
#include "status.h"
#include "routing_tree.h"

#include "net/linkaddr.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "logging.h"

#include <assert.h>

int SN_Forward_Packetbuf(uint16_t source, uint16_t destination) {
    linkaddr_t src_address, next_hop;
    int ret;

    if(source == SN_NO_SHORT_ADDRESS || destination == SN_NO_SHORT_ADDRESS) {
        SN_ErrPrintf("invalid route: %#06x -> %#06x\n", source, destination);
        return -SN_ERR_INVALID;
    }

    if(starfishnet_config.mib.macShortAddress == SN_NO_SHORT_ADDRESS) {
        SN_ErrPrintf("tried to route when addressing isn't correctly configured. aborting\n");
        return -SN_ERR_INVALID;
    }

    if(!starfishnet_config.nib.enable_routing) {
        SN_ErrPrintf("tried to route when routing was switched off. aborting\n");
        return -SN_ERR_INVALID;
    }

    src_address.u16 = starfishnet_config.mib.macShortAddress;
    ret = SN_Tree_route(source, destination, &next_hop.u16);
    if(ret != SN_OK) {
        return ret;
    }

    //set addresses in packetbuf
    packetbuf_set_attr(PACKETBUF_ATTR_SENDER_ADDR_SIZE, 2);
    packetbuf_set_attr(PACKETBUF_ATTR_RECEIVER_ADDR_SIZE, 2);
    packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &src_address);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &next_hop);

    NETSTACK_LLSEC.send(NULL, NULL);

    return SN_OK;
}
