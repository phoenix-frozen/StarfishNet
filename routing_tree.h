#ifndef __SN_ADDRESSING_H__
#define __SN_ADDRESSING_H__

#include "types.h"

//block: IN: whether you want a block; OUT: whether you got one
//address: OUT: if a block, the first address in it
int8_t SN_Tree_allocate_address(uint16_t *address, uint8_t *block);

int8_t SN_Tree_free_address(uint16_t address);

int8_t SN_Tree_determine_capacity(uint16_t *leaf, uint16_t *block);

int8_t SN_Tree_init();

//zero: yes. positive: yes, but no routing. negative: no.
int8_t SN_Tree_check_join(uint8_t tree_position, uint8_t tree_branching_factor);

/*
 * Given the origin of a packet, its destination, and the address of the previous hop, determines the next hop's address.
 *
 * @param src_addr The packet's origin.
 * @param dst_addr The packet's destination.
 * @param hop_addr The address of the node that forwarded the packet to us (its previous hop).
 * @param next_hop Will be filled with the address of the packet's next hop.
 * @return         Error code.
 */
int8_t SN_Tree_route(uint16_t src_addr, uint16_t dst_addr, uint16_t *next_hop);

#endif /* __SN_ADDRESSING_H__ */
