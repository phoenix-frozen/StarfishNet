#include <string.h>

#include "sn_crypto.h"
#include "sn_status.h"
#include "sn_logging.h"

//setup uECC
#define uECC_CURVE uECC_secp160r1
#define uECC_PLATFORM uECC_x86_64
#include "uECC.h"

//libsha1
#include "libsha1.h"

#if !(SN_ECC_key_size/8 == uECC_BYTES)
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //!(SN_ECC_key_size/8 == uECC_BYTES)

typedef struct SN_SHA1_hash {
    uint8_t data[SHA1_DIGEST_SIZE];
} SN_SHA1_hash_t;

typedef struct SN_ECC_unpacked_public_key {
    uint8_t data[2*SN_ECC_key_size/8];
} SN_ECC_unpacked_public_key_t;

int SN_Crypto_generate_keypair(SN_ECC_keypair_t* keypair) {
    SN_InfoPrintf("enter\n");

    if(keypair == NULL) {
        SN_ErrPrintf("keypair cannot be NULL\n");
        return -SN_ERR_NULL;
    }

    //generate keypair
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    int ret = uECC_make_key(unpacked_public_key.data, keypair->private_key.data);
    if(ret != 1) {
        SN_ErrPrintf("key generation failed\n");
        return -SN_ERR_KEYGEN;
    }

    //pack public key
    uECC_compress(unpacked_public_key.data, keypair->public_key.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_sign(SN_ECC_private_key_t* private_key, uint8_t* data, int data_len, SN_ECDSA_signature_t* signature) {
    SN_InfoPrintf("enter\n");

    if(private_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("private_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //hash data
    SN_SHA1_hash_t hashbuf;
    sha1(hashbuf.data, data, data_len);

    //generate signature
    //XXX: this works because the hash and keys are the same length
    int ret = uECC_sign(private_key->data, hashbuf.data, signature->data);
    if(ret == 0) {
        SN_ErrPrintf("error generating digital signature\n");
        return -SN_ERR_SIGNATURE;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_verify(SN_ECC_public_key_t* public_key, uint8_t* data, int data_len, SN_ECDSA_signature_t* signature) {
    SN_InfoPrintf("enter\n");

    if(public_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("public_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //unpack public key
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //hash data
    SN_SHA1_hash_t hashbuf;
    sha1(hashbuf.data, data, data_len);

    //verify signature
    //XXX: this works because the hash and keys are the same length
    int ret = uECC_verify(unpacked_public_key.data, hashbuf.data, signature->data);
    if(ret == 0) {
        SN_ErrPrintf("error verifying digital signature\n");
        return -SN_ERR_SIGNATURE;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_keyexchange(SN_ECC_public_key_t* public_key, SN_ECC_private_key_t* private_key, SN_AES_key_t* shared_secret) {
    SN_InfoPrintf("enter\n");

    if(public_key == NULL || private_key == NULL || shared_secret == NULL) {
        SN_ErrPrintf("public_key, private_key, and shared_secret must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //unpack public key
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //do ECDH
    SN_ECC_private_key_t raw_shared_secret;
    int ret = uECC_shared_secret(unpacked_public_key.data, private_key->data, raw_shared_secret.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    //hash resultant secret
    SN_SHA1_hash_t       hashed_shared_secret;
    sha1(hashed_shared_secret.data, raw_shared_secret.data, sizeof(raw_shared_secret.data));

    //output new shared secret
    memcpy(shared_secret->data, hashed_shared_secret.data, sizeof(shared_secret->data));

    SN_InfoPrintf("exit\n");
    return SN_OK;
}
