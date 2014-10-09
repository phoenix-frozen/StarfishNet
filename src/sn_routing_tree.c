#include <sn_status.h>
#include <sn_logging.h>
#include <assert.h>
#include "sn_routing_tree.h"

int SN_Tree_allocate_address(SN_Session_t* session, uint16_t* address, bool* block) {
    if(session == NULL || address == NULL || block == NULL) {
        SN_ErrPrintf("session, address, and block must all be valid\n");
        return -SN_ERR_NULL;
    }

    assert(session->nib.tree_branching_factor < 16);
    assert(session->nib.tree_position < 16);
    assert((session->nib.tree_position + session->nib.tree_branching_factor + 1) <= 16);

    uint16_t total_blocks         = (uint16_t)(1 << session->nib.tree_branching_factor);
    uint16_t address_block_size   = (uint16_t)(1 << (16 - session->nib.tree_position * session->nib.tree_branching_factor));
    uint16_t total_leaf_blocks    = session->nib.leaf_blocks + (uint16_t)1;
    uint16_t total_leaf_addresses = (uint16_t)(total_leaf_blocks * address_block_size);

    if(*block) {
        if(session->nib.router_blocks_allocated < total_blocks - total_leaf_blocks) {
            *address = session->mib.macShortAddress + total_leaf_addresses + session->nib.router_blocks_allocated * address_block_size;

            session->nib.router_blocks_allocated++;
        } else {
            //no available blocks. allocate single address
            *block = 0;
        }
    }

    if(!*block) {
        if(session->nib.leaf_addresses_allocated < total_leaf_addresses) {
            //our short address is always at the start of our range, with leaf children right next to it
            *address = session->mib.macShortAddress + session->nib.leaf_addresses_allocated;

            session->nib.leaf_addresses_allocated++;
        } else {
            //no available addresses.
            return -SN_ERR_RESOURCES;
        }
    }

    return SN_OK;
}

int SN_Tree_free_address(SN_Session_t* session, uint16_t address) {
    //not implemented yet
    return SN_OK;
}

int SN_Tree_determine_capacity(SN_Session_t* session, uint16_t* leaf, uint16_t* block) {
    if(session == NULL || leaf == NULL || block == NULL) {
        SN_ErrPrintf("session, leaf, and block must all be valid\n");
        return -SN_ERR_NULL;
    }

    uint16_t total_blocks         = (uint16_t)(1 << session->nib.tree_branching_factor);
    uint16_t address_block_size   = (uint16_t)(1 << (16 - session->nib.tree_position * session->nib.tree_branching_factor));
    uint16_t total_leaf_blocks    = (uint16_t)(session->nib.leaf_blocks + 1);
    uint16_t total_leaf_addresses = (uint16_t)(total_leaf_blocks * address_block_size);

    *leaf  = total_leaf_addresses - session->nib.leaf_addresses_allocated;
    *block = total_blocks - total_leaf_blocks - session->nib.router_blocks_allocated;

    return SN_OK;
}


int SN_Tree_configure(SN_Session_t* session) {
    if(session == NULL) {
        SN_ErrPrintf("session must be valid\n");
        return -SN_ERR_NULL;
    }

    uint16_t total_blocks      = (uint16_t)(1 << session->nib.tree_branching_factor);
    int address_block_exponent = 16 - session->nib.tree_position * session->nib.tree_branching_factor;

    if(address_block_exponent < -session->nib.tree_branching_factor) {
        //we're trying to join a tree below the bottom. error
        return -SN_ERR_INVALID;
    } else if(address_block_exponent < 0) {
        //we're at the bottom of the tree. no children
        session->nib.enable_routing = 0;
        session->nib.leaf_blocks = (uint16_t)(total_blocks - 1);
    } else if(address_block_exponent < session->nib.tree_branching_factor) {
        //we're near the bottom of the tree. our children cannot route
        session->nib.leaf_blocks = (uint16_t)(total_blocks - 1);
    }

    session->nib.leaf_addresses_allocated = 1; //we always take the first address
    session->nib.router_blocks_allocated  = 0;

    return SN_OK;
}


int SN_Tree_check_join(uint8_t tree_position, uint8_t tree_branching_factor) {
    int address_block_exponent = 16 - tree_position * tree_branching_factor;

    if(address_block_exponent < -tree_branching_factor) {
        //we're trying to join a tree below the bottom. error
        return -SN_ERR_INVALID;
    }

    if(address_block_exponent < 0) {
        //we're near the bottom of the tree. no children
        return 1;
    }

    return 0;
}
