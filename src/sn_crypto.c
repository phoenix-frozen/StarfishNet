#include <sn_crypto.h>
#include <sn_status.h>
#include <sn_logging.h>

#include <string.h>
#include <assert.h>

//setup uECC
#include "uECC.h"

//polarssl sha1
#include "polarssl/sha1.h"
#include "aes-ccm.h"

#if !(SN_PK_key_size == uECC_BYTES)
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //!(SN_PK_key_size == uECC_BYTES)

typedef struct SN_ECC_unpacked_public_key {
    uint8_t data[SN_PK_key_size * 2];
} SN_ECC_unpacked_public_key_t;

int SN_Crypto_generate_keypair(SN_Keypair_t* keypair) {
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


int SN_Crypto_sign(SN_Private_key_t* private_key, uint8_t* data, int data_len, SN_Signature_t* signature) {
    SN_InfoPrintf("enter\n");

    if(private_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("private_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //hash data
    SN_Hash_t hashbuf;
    sha1(data, data_len, hashbuf.data);

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

int SN_Crypto_verify(SN_Public_key_t* public_key, uint8_t* data, int data_len, SN_Signature_t* signature) {
    SN_InfoPrintf("enter\n");

    if(public_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("public_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //unpack public key
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //hash data
    SN_Hash_t hashbuf;
    sha1(data, data_len, hashbuf.data);

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

int SN_Crypto_key_agreement(SN_Public_key_t* public_key, SN_Private_key_t* private_key, SN_Kex_result_t* shared_secret) {
    SN_InfoPrintf("enter\n");

    if(public_key == NULL || private_key == NULL || shared_secret == NULL) {
        SN_ErrPrintf("public_key, private_key, and shared_secret must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //unpack public key
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //do ECDH
    SN_Private_key_t raw_shared_secret; //use the private key type because that's the size of the ECDH result
    int ret = uECC_shared_secret(unpacked_public_key.data, private_key->data, raw_shared_secret.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    //hash and output resultant secret
    sha1(raw_shared_secret.data, sizeof(raw_shared_secret.data), shared_secret->raw.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_encrypt(SN_AES_key_t* key, SN_AES_key_id_t* key_id, uint16_t counter, uint8_t* ad, uint8_t ad_len, uint8_t* data, uint8_t data_len, uint8_t* tag) {
    SN_InfoPrintf("enter\n");

    if(key == NULL || key_id == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_id, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    aes_ccm_context ctx;
    int ret = aes_ccm_init(&ctx, key->data, SN_AES_key_bits);

    if(ret != 0) {
        SN_ErrPrintf("CCM initialisation failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    uint8_t iv[sizeof(key_id->data) + sizeof(counter) + 1]; //CCM IV must be greater than 7
    memcpy(iv, key_id->data, sizeof(key_id->data));
    memcpy(iv + sizeof(key_id->data), &counter, sizeof(counter));

    ret = aes_ccm_encrypt_and_tag(&ctx, data_len, iv, sizeof(iv), ad, ad_len, data, data, tag, SN_Tag_size);

    aes_ccm_free(&ctx);

    if(ret != 0) {
        SN_ErrPrintf("CCM encryption failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_decrypt(SN_AES_key_t* key, SN_AES_key_id_t* key_id, uint16_t counter, uint8_t* ad, uint8_t ad_len, uint8_t* data, uint8_t data_len, uint8_t* tag) {
    SN_InfoPrintf("enter\n");

    if(key == NULL || key_id == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_id, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    aes_ccm_context ctx;
    int ret = aes_ccm_init(&ctx, key->data, SN_AES_key_bits);

    if(ret != 0) {
        SN_ErrPrintf("CCM initialisation failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    uint8_t iv[sizeof(key_id->data) + sizeof(counter) + 1]; //CCM IV must be greater than 7
    memcpy(iv, key_id->data, sizeof(key_id->data));
    memcpy(iv + sizeof(key_id->data), &counter, sizeof(counter));

    ret = aes_ccm_auth_decrypt(&ctx, data_len, iv, sizeof(iv), ad, ad_len, data, data, tag, SN_Tag_size);

    aes_ccm_free(&ctx);

    if(ret != 0) {
        SN_ErrPrintf("CCM decryption failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_add_certificate(SN_Certificate_storage_t* storage, SN_Certificate_t* certificate) {
    SN_InfoPrintf("enter\n");

    if(storage == NULL || certificate == NULL) {
        SN_ErrPrintf("storage and certificate must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    if(SN_Crypto_verify(&certificate->endorser, (void*)&certificate->protected_data, sizeof(certificate->protected_data), &certificate->signature) != SN_OK) {
        SN_ErrPrintf("certificate signature verification failed. not adding to repository\n");
        return -SN_ERR_SIGNATURE;
    }

    assert(storage->size <= storage->capacity);
    if(storage->size == storage->capacity) {
        SN_ErrPrintf("certificate repository is full\n");
        return -SN_ERR_RESOURCES;
    }

    storage->contents[storage->size++] = *certificate;

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


