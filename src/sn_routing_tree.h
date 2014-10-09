#ifndef __SN_ADDRESSING_H__
#define __SN_ADDRESSING_H__

#include <sn_types.h>
#include <stdbool.h>
#include <sn_core.h>

//block: IN: whether you want a block; OUT: whether you got one
//address: OUT: if a block, the first address in it
int SN_Tree_allocate_address(SN_Session_t* session, uint16_t* address, bool* block);

int SN_Tree_free_address(SN_Session_t* session, uint16_t address);

int SN_Tree_determine_capacity(SN_Session_t* session, uint16_t* leaf, uint16_t* block);

int SN_Tree_configure(SN_Session_t* session);

//zero: yes. positive: yes, but no routing. negative: no.
int SN_Tree_check_join(uint8_t tree_position, uint8_t tree_branching_factor);

#endif /* __SN_ADDRESSING_H__ */
