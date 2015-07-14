#include "raw_tx.h"
#include "config.h"
#include "status.h"
#include "routing_tree.h"
#include "logging.h"

#include "net/linkaddr.h"
#include "net/packetbuf.h"
#include "net/netstack.h"

int8_t SN_Forward_Packetbuf(uint16_t source, uint16_t destination) {
    linkaddr_t src_address, next_hop;
    int8_t ret;
    uint16_t next_hop_short_address;

    if(source == FRAME802154_INVALIDADDR || destination == FRAME802154_INVALIDADDR) {
        SN_ErrPrintf("invalid route: 0x%04x -> 0x%04x\n", source, destination);
        return -SN_ERR_INVALID;
    }

    if(starfishnet_config.short_address == FRAME802154_INVALIDADDR) {
        SN_ErrPrintf("tried to route when addressing isn't correctly configured. aborting\n");
        return -SN_ERR_INVALID;
    }

    STORE_SHORT_ADDRESS(src_address.u8, starfishnet_config.short_address);
    ret = SN_Tree_route(source, destination, &next_hop_short_address);
    STORE_SHORT_ADDRESS(next_hop.u8, next_hop_short_address);
    if(ret != SN_OK) {
        SN_ErrPrintf("error trying to route packet: %d", -ret);
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
