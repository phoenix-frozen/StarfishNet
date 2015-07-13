#include "status.h"
#include "logging.h"
#include "routing_tree.h"
#include "config.h"

#include <assert.h>

int8_t SN_Tree_allocate_address(uint16_t *address, uint8_t *block) {
    uint16_t total_blocks         = (uint16_t)(1 << starfishnet_config.tree_branching_factor);
    uint8_t  space_exponent       = (uint8_t )(16 - starfishnet_config.tree_position * starfishnet_config.tree_branching_factor);
    uint8_t  block_exponent       =            space_exponent - starfishnet_config.tree_branching_factor;
    uint16_t block_size           = (uint16_t)(1 << block_exponent);
    uint16_t total_leaf_blocks    = (uint16_t)(1 + starfishnet_config.leaf_blocks);
    uint16_t total_leaf_addresses = (uint16_t)(total_leaf_blocks * block_size);

    if(address == NULL || block == NULL) {
        SN_ErrPrintf("address, and block must all be valid\n");
        return -SN_ERR_NULL;
    }

    assert(starfishnet_config.tree_branching_factor <= 16);
    assert(starfishnet_config.tree_position * starfishnet_config.tree_branching_factor < 16);
    assert(starfishnet_config.enable_routing);

    if(*block) {
        if(starfishnet_config.router_blocks_allocated < total_blocks - total_leaf_blocks) {
            *address = starfishnet_config.short_address + total_leaf_addresses + starfishnet_config.router_blocks_allocated * block_size;

            starfishnet_config.router_blocks_allocated++;
        } else {
            //no available blocks. allocate single address
            *block = 0;
        }
    }

    if(!*block) {
        if(starfishnet_config.leaf_addresses_allocated < total_leaf_addresses) {
            //our short address is always at the start of our range, with leaf children right next to it
            *address = starfishnet_config.short_address + starfishnet_config.leaf_addresses_allocated;

            starfishnet_config.leaf_addresses_allocated++;
        } else {
            //no available addresses.
            return -SN_ERR_RESOURCES;
        }
    }

    return SN_OK;
}

int8_t SN_Tree_free_address(uint16_t address) {
    //not implemented yet
    (void)address; //shut up GCC
    return -SN_ERR_UNIMPLEMENTED;
}

int8_t SN_Tree_determine_capacity(uint16_t *leaf, uint16_t *block) {
    uint16_t total_blocks         = (uint16_t)(1 << starfishnet_config.tree_branching_factor);
    uint8_t  space_exponent       = (uint8_t )(16 - starfishnet_config.tree_position * starfishnet_config.tree_branching_factor);
    uint8_t  block_exponent       =            space_exponent - starfishnet_config.tree_branching_factor;
    uint16_t block_size           = (uint16_t)(1 << block_exponent);
    uint16_t total_leaf_blocks    = (uint16_t)(1 + starfishnet_config.leaf_blocks);
    uint16_t total_leaf_addresses = (uint16_t)(total_leaf_blocks * block_size);

    if(leaf == NULL || block == NULL) {
        SN_ErrPrintf("leaf and block must be valid\n");
        return -SN_ERR_NULL;
    }

    *leaf  = total_leaf_addresses - starfishnet_config.leaf_addresses_allocated;
    *block = total_blocks - total_leaf_blocks - starfishnet_config.router_blocks_allocated;

    return SN_OK;
}


int8_t SN_Tree_init() {
    uint16_t total_blocks      = (uint16_t)(1 << starfishnet_config.tree_branching_factor);
    int8_t address_block_exponent = (int8_t)16 - starfishnet_config.tree_position * starfishnet_config.tree_branching_factor;

    if(address_block_exponent < -starfishnet_config.tree_branching_factor) {
        //we're trying to join a tree below the bottom. error
        return -SN_ERR_INVALID;
    } else if(address_block_exponent < 0) {
        //we're at the bottom of the tree. no children
        starfishnet_config.enable_routing = 0;
        starfishnet_config.leaf_blocks = (uint16_t)(total_blocks - 1);
    } else if((uint8_t)address_block_exponent < starfishnet_config.tree_branching_factor) {
        //we're near the bottom of the tree. our children cannot route
        starfishnet_config.leaf_blocks = (uint16_t)(total_blocks - 1);
    }

    starfishnet_config.leaf_addresses_allocated = 1; //we always take the first address
    starfishnet_config.router_blocks_allocated  = 0;

    return SN_OK;
}


int8_t SN_Tree_check_join(uint8_t tree_position, uint8_t tree_branching_factor) {
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

/* StarfishNet simple routing rules:
 * 1. If dst_addr is an immediate child address, forward to it.
 * 2. If neither dst_addr nor src_addr is in my subtree, do not route.
 * 3. If dst_addr and src_addr are both in my subtree, but also both in some smaller subtree, do not route.
 *    (I probably shouldn't even have received this packet.)
 * 4. If dst_addr is in my subtree, it is also in the subtree of one of my children.
 *    Determine that child, and forward to it. Its address is the base address of the block in which dst_addr sits.
 * 5. If src_addr is in my subtree, and dst_addr is not, forward to my parent.
 *
 * TODO: StarfishNet "mesh-shortcut" routing rules
 *
 * Terminology:
 * * "My [address] space" means the section of the address space I was allocated by my parent.
 * * "My subtree" means the subtree of the routing tree with me at its head <-> whose nodes have addresses in my space.
 * * "My level" means the level of the routing tree on which I am situated.
 *   (0 for the coordinator, >0 for everyone else.)
 */

int8_t SN_Tree_route(uint16_t src_addr, uint16_t dst_addr, uint16_t *next_hop) {
    uint8_t  space_exponent       = (uint8_t )(16 - starfishnet_config.tree_position * starfishnet_config.tree_branching_factor);
    uint8_t  block_exponent       =            space_exponent - starfishnet_config.tree_branching_factor;

    uint16_t space_size           = (uint16_t)(1 << space_exponent);
    uint16_t block_size           = (uint16_t)(1 << block_exponent);

    uint16_t space_mask           = (uint16_t)(space_size - 1);
    uint16_t block_mask           = (uint16_t)(block_size - 1);

    uint16_t space_base           = (uint16_t)(starfishnet_config.short_address & ~space_mask);

    uint16_t total_leaf_blocks    = (uint16_t)(1 + starfishnet_config.leaf_blocks);
    uint16_t total_leaf_addresses = (uint16_t)(total_leaf_blocks * block_size);

    if(next_hop == NULL) {
        SN_ErrPrintf("next_hop must be valid\n");
        return -SN_ERR_NULL;
    }

    assert(starfishnet_config.tree_branching_factor < 16);

#ifdef SN_MESH_SHORTCUT_ROUTING
#error Mesh-shortcut routing not yet implemented.
#else //SN_MESH_SHORTCUT_ROUTING

    //Simple routing algorithm

    if((dst_addr & ~space_mask) == space_base) {
        //dst_addr is in my subtree.
        if((dst_addr & space_mask) < total_leaf_addresses) {
            //dst_addr is one of my leaf children.
            //Rule 1 applies. Forward directly to the node.
            *next_hop = dst_addr;
            SN_DebugPrintf("Rule 1: 0x%04x\n", *next_hop);
            return SN_OK;
            //XXX: in practice, this branch should never be taken, because it should be caught by Rule 1.
        }
        if ((dst_addr & block_mask) == 0) {
            //dst_addr is one of my router children.
            //Rule 1 applies. Forward directly to the node.
            *next_hop = dst_addr;
            SN_DebugPrintf("Rule 1: 0x%04x\n", *next_hop);
            return SN_OK;
            //XXX: in practice, this branch should never be taken, because it should be caught by Rule 1.
        }
        if((src_addr & ~space_mask) == space_base) {
            //dst_addr and src_addr are both in my subtree
            if((dst_addr & ~block_mask) == (src_addr & ~block_mask)) {
                //dst_addr and src_addr are both in the same smaller subtree
                //Rule 3 applies. Do not route.
                SN_DebugPrintf("Rule 3: Do not route.\n");
                return -SN_ERR_INVALID;
            }
        }
        //if we get to here, dst_addr is in my subtree, but is not my immediate child.
        //Rule 4 applies. Determine the child whose subtree it is in, and forward to it.
        *next_hop = dst_addr & ~block_mask;
        SN_DebugPrintf("Rule 4: 0x%04x\n", *next_hop);
        return SN_OK;

    }
    if((src_addr & ~space_mask) == space_base) {
        //src_addr is in my subtree, dst_addr is not
        //Rule 5 applies. Forward to my parent.
        *next_hop = starfishnet_config.parent_address;
        SN_DebugPrintf("Rule 5: 0x%04x\n", *next_hop);
        return SN_OK;
    }
    //neither src_addr nor dst_addr is in my subtree.
    //Rule 2 applies. Do not route.
    SN_DebugPrintf("Rule 2: Do not route.\n");
    return -SN_ERR_INVALID;

#endif //SN_MESH_SHORTCUT_ROUTING
}
