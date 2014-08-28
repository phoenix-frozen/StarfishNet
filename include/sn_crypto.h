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

#include <stdint.h>

#define SN_PK_key_bits  160
#define SN_AES_key_bits 128 //mandated by IEEE 802.15.4
#define SN_Hash_bits    160

#define SN_PK_key_size    (SN_PK_key_bits/8)
#define SN_AES_block_size (128/8) //mandated by AES
#define SN_AES_key_size   (SN_AES_key_bits/8)
#define SN_Hash_size      (SN_Hash_bits/8)

//cryptographic types
typedef struct __attribute__((packed)) SN_Public_key {
    uint8_t data[SN_PK_key_size + 1]; //in packed format
} SN_Public_key_t;

typedef struct SN_Private_key {
    uint8_t data[SN_PK_key_size];
} SN_Private_key_t;

typedef struct SN_Keypair {
    SN_Public_key_t  public_key;
    SN_Private_key_t private_key;
} SN_Keypair_t;

typedef struct __attribute__((packed)) SN_Signature {
    uint8_t data[SN_PK_key_size * 2]; //size of ECDSA signature
} SN_Signature_t;

typedef struct __attribute__((packed)) SN_AES_key {
    uint8_t data[SN_AES_key_size];
} SN_AES_key_t;

typedef struct __attribute__((packed)) SN_AES_key_id {
    uint8_t data[SN_Hash_size - SN_AES_key_size];
} SN_AES_key_id_t;

typedef struct __attribute__((packed)) SN_Hash {
    uint8_t data[SN_Hash_size];
} SN_Hash_t;

typedef struct __attribute__((packed)) SN_Kex_result {
    union {
        SN_Hash_t raw;

        struct __attribute__((packed)) {
            SN_AES_key_t    key;
            SN_AES_key_id_t key_id;
        };
    };
} SN_Kex_result_t;

//certificate-related types
typedef struct __attribute__((packed)) SN_Certificate {
    struct __attribute__((packed)) {
        SN_Public_key_t subject;
        //TODO: assertion
    } protected_data;

    SN_Signature_t  signature;
    SN_Public_key_t endorser;
} SN_Certificate_t;

typedef struct SN_Certificate_storage {
    unsigned int     capacity; //number of certificates that can be stored in this structure, in total
    unsigned int     size;     //number of certificates that are currently stored in this structure
    SN_Certificate_t contents[];
} SN_Certificate_storage_t;

//API functions
int SN_Crypto_generate_keypair ( //generate a new ECC keypair, storing it in the buffer provided
    SN_Keypair_t* keypair
);

int SN_Crypto_sign ( //sign data into sigbuf
    SN_Private_key_t* private_key,
    uint8_t*          data,
    int               data_len,
    SN_Signature_t*   signature
);

int SN_Crypto_verify ( //verify signature of data in sigbuf
    SN_Public_key_t*  public_key,
    uint8_t*          data,
    int               data_len,
    SN_Signature_t*   signature
);

int SN_Crypto_key_agreement ( //do a key agreement into shared_secret
    SN_Public_key_t*  public_key,
    SN_Private_key_t* private_key,
    SN_Kex_result_t*  shared_secret
);

int SN_Crypto_key_challenge ( //issue a challenge based on the key ID
    SN_AES_key_id_t* shared_secret,
    uint8_t*         challenge_data,
    uint8_t*         challenge_data_len,
    SN_Hash_t*       challenge
);

int SN_Crypto_add_certificate( //add a certificate to a storage repository
    SN_Certificate_storage_t* storage,
    SN_Certificate_t*         certficate
);

int SN_Crypto_remove_certificate( //remove a certificate from a storage repository
    SN_Certificate_storage_t* storage,
    SN_Certificate_t*         certficate
);

//TODO: certificate chain validation
//TODO: report generation

#endif /* __SN_CRYPTO_H__ */

