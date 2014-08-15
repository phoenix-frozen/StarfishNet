#ifndef __SN_CRYPTO_H__
#define __SN_CRYPTO_H__

/* Algorithms used.
 *
 * Signature:     ECDSA
 * Key agreement: ECDH
 * Hash:          SHA1
 * ECC curve:     secp160r1
 *
 * Crypto library: micro-ecc
 */

#include <stdint.h>

#define SN_ECC_key_size 160
#define SN_AES_key_size 128

//cryptographic types
typedef struct __attribute__((packed)) SN_ECC_public_key {
    uint8_t data[SN_ECC_key_size/8 + 1];
} SN_ECC_public_key_t;

typedef struct __attribute__((packed)) SN_ECC_private_key {
    uint8_t data[SN_ECC_key_size/8];
} SN_ECC_private_key_t;

typedef struct SN_ECC_keypair {
    SN_ECC_public_key_t  public_key;
    SN_ECC_private_key_t private_key;
} SN_ECC_keypair_t;

typedef struct __attribute__((packed)) SN_ECDSA_signature {
    uint8_t data[2*SN_ECC_key_size/8];
} SN_ECDSA_signature_t;

typedef struct SN_AES_key {
    uint8_t data[SN_AES_key_size/8];
} SN_AES_key_t;

//certificate-related types
typedef struct __attribute__((packed)) SN_Certificate {
    struct __attribute__((packed)) {
        SN_ECC_public_key_t subject;
        //TODO: assertion
    } protected_data;

    SN_ECDSA_signature_t signature;
    SN_ECC_public_key_t  endorser;
} SN_Certificate_t;

typedef struct SN_Certificate_storage {
    unsigned int     capacity; //number of certificates that can be stored in this structure, in total
    unsigned int     size;     //number of certificates that are currently stored in this structure
    SN_Certificate_t contents[];
} SN_Certificate_storage_t;

//API functions
int SN_Crypto_generate_keypair ( //generate a new ECC keypair, storing it in the buffer provided
    SN_ECC_keypair_t* keypair
);

int SN_Crypto_sign ( //generate an ECDSA signature of data into sigbuf
    SN_ECC_private_key_t* private_key,
    uint8_t*              data,
    int                   data_len,
    SN_ECDSA_signature_t* signature
);

int SN_Crypto_verify ( //verify an ECDSA signature of data in sigbuf
    SN_ECC_public_key_t*  public_key,
    uint8_t*              data,
    int                   data_len,
    SN_ECDSA_signature_t* signature
);

int SN_Crypto_keyexchange ( //perform an ECDH key agreement
    SN_ECC_public_key_t*  public_key,
    SN_ECC_private_key_t* private_key,
    SN_AES_key_t*         shared_secret
);

//TODO: certificate add/remove
//TODO: certificate chain validation
//TODO: report generation

#endif /* __SN_CRYPTO_H__ */

