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

//TODO: prototypes from sn_core.h will move in here as they're ported

extern const struct network_driver starfishnet_driver;

int SN_Send(SN_Endpoint_t *dst_addr, SN_Message_t *message);
int SN_Associate(SN_Endpoint_t *dst_addr);
int SN_Dissociate(SN_Endpoint_t *dst_addr);

typedef void (* SN_Receive_callback_t)(SN_Endpoint_t* src_addr, SN_Message_t* message);
void SN_Receive(SN_Receive_callback_t callback);

#endif //__STARFISHNET_H__
