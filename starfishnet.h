/* Algorithms used.
 *
 * Signature:     ECDSA (with hash)
 * Key agreement: ECDH  (hashed)
 * Hash:          SHA1
 * ECC curve:     secp160r1
 *
 * Crypto libraries: micro-ecc, libsha1
 */

#ifndef __STARFISHNET_H__
#define __STARFISHNET_H__

#include "net/netstack.h"
#include "types.h"

extern const struct network_driver starfishnet_driver;

//primitives that send messages
int SN_Send(SN_Endpoint_t *dst_addr, SN_Message_t *message);
int SN_Associate(SN_Endpoint_t *dst_addr);
int SN_Dissociate(SN_Endpoint_t *dst_addr);

//primitive for configuring the reception of messages
typedef void (SN_Receive_callback_t)(SN_Endpoint_t* src_addr, SN_Message_t* message);
void SN_Receive(SN_Receive_callback_t* callback);

//primitive for performing a network scan
typedef void (SN_Discovery_callback_t) (SN_Network_descriptor_t* network, void* extradata);
int SN_Discover( //scan for StarfishNet networks. also serves as a nearest-neighbor scan. this call returns immediately
    SN_Discovery_callback_t* callback, //you get one callback for each network found
    uint32_t channel_mask,
    clock_time_t timeout,  //in ms
    bool show_full_networks, //0 gets you a callback only from networks with spare capacity
    void *extradata //will be passed to the callback
);

//start a new StarfishNet network as coordinator
int SN_Start(SN_Network_descriptor_t* network);

//tune the radio to a StarfishNet network and listen for packets with its PAN ID
int SN_Join(SN_Network_descriptor_t* network, bool disable_routing);


#endif //__STARFISHNET_H__
