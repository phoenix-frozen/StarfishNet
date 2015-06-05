#ifndef __SN_CRYPTO_H__
#define __SN_CRYPTO_H__

/* Algorithms used.
 *
 * Signature:     ECDSA (with hash)
 * Key agreement: ECDH  (hashed)
 * Hash:          SHA1
 * ECC curve:     secp160r1
 *
 * Crypto library: micro-ecc
 */

#include "sn_types.h"

#include <stdint.h>

//API functions
int SN_Crypto_generate_keypair ( //generate a new ECC keypair, storing it in the buffer provided
    SN_Keypair_t* keypair
);

int SN_Crypto_sign ( //sign data into sigbuf
    SN_Private_key_t* private_key,
    uint8_t*          data,
    size_t            data_len,
    SN_Signature_t*   signature
);

int SN_Crypto_verify ( //verify signature of data in sigbuf
    SN_Public_key_t*  public_key,
    uint8_t*          data,
    size_t            data_len,
    SN_Signature_t*   signature
);

int SN_Crypto_key_agreement ( //do an authenticated key agreement into shared_secret
    SN_Public_key_t* identity_A,
    SN_Public_key_t* identity_B,
    SN_Public_key_t*  public_key,
    SN_Private_key_t* private_key,
    SN_Kex_result_t*  shared_secret
);

int SN_Crypto_encrypt ( //AEAD-encrypt a data block. tag is 16 bytes
    SN_AES_key_t*    key,
    SN_Public_key_t* key_agreement_key,
    uint32_t         counter,
    uint8_t*         ad,
    size_t           ad_len,
    uint8_t*         data,
    size_t           data_len,
    uint8_t*         tag,
    bool             pure_ack
);

int SN_Crypto_decrypt ( //AEAD-decrypt a data block. tag is 16 bytes
    SN_AES_key_t*    key,
    SN_Public_key_t* key_agreement_key,
    uint32_t         counter,
    uint8_t*         ad,
    size_t           ad_len,
    uint8_t*         data,
    size_t           data_len,
    uint8_t*         tag,
    bool             pure_ack
);

int SN_Crypto_check_certificate ( //check the signature on a certificate
    SN_Certificate_t*         certificate
);

void SN_Crypto_hash (
    uint8_t*   data,
    size_t     data_len,
    SN_Hash_t* hash,
    size_t     repeat_count
);

//TODO: certificate chain validation
//TODO: report generation

#endif /* __SN_CRYPTO_H__ */
