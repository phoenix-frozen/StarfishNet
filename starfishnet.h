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

extern const struct network_driver starfishnet_driver;

#endif //__STARFISHNET_H__
