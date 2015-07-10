#ifndef __SN_CRYPTO_H__
#define __SN_CRYPTO_H__

#include "types.h"

#include "sys/cc.h"

#include <stdbool.h>

//API functions
int8_t SN_Crypto_generate_keypair( //generate a new ECC keypair, storing it in the buffer provided
    SN_Keypair_t *keypair
);

int8_t SN_Crypto_sign( //sign data into sigbuf
    const SN_Private_key_t *private_key,
    const uint8_t *data,
    uint8_t data_len,
    SN_Signature_t *signature
);

int8_t SN_Crypto_verify( //verify signature of data in sigbuf
    const SN_Public_key_t *public_key,
    const uint8_t *data,
    uint8_t data_len,
    const SN_Signature_t *signature
);

int8_t SN_Crypto_key_agreement( //do an authenticated key agreement into shared_secret
    const SN_Public_key_t *identity_A,
    const SN_Public_key_t *identity_B,
    const SN_Public_key_t *public_key,
    const SN_Private_key_t *private_key,
    SN_Kex_result_t *shared_secret
);

int8_t SN_Crypto_encrypt( //AEAD-encrypt a data block. tag is 16 bytes
    const SN_AES_key_t *key,
    const SN_Public_key_t *key_agreement_key,
    uint32_t counter,
    const uint8_t *ad,
    uint8_t ad_len,
    uint8_t *data,
    uint8_t data_len,
    uint8_t *tag,
    bool pure_ack
);

int8_t SN_Crypto_decrypt( //AEAD-decrypt a data block. tag is 16 bytes
    const SN_AES_key_t *key,
    const SN_Public_key_t *key_agreement_key,
    uint32_t counter,
    const uint8_t *ad,
    uint8_t ad_len,
    uint8_t *data,
    uint8_t data_len,
    const uint8_t *tag,
    bool pure_ack
);


#define SN_Crypto_check_certificate(certificate) SN_Crypto_verify(&certificate->endorser, (void*)&certificate->protected_data, sizeof(certificate->protected_data), &certificate->signature)

void SN_Crypto_hash(const uint8_t *data, uint8_t data_len, SN_Hash_t *hash);

#endif /* __SN_CRYPTO_H__ */
