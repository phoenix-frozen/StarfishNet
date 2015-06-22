#include "nonqueued_transmission.h"
#include "config.h"
#include "status.h"
#include "routing_tree.h"

#include "net/linkaddr.h"
#include "net/packetbuf.h"
#include "net/netstack.h"

#include <assert.h>

int SN_TX_Packetbuf(uint16_t source, uint16_t destination) {
    linkaddr_t src_address, next_hop;
    int ret;

    assert(starfishnet_config.nib.enable_routing);
    if(!starfishnet_config.nib.enable_routing) {
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
