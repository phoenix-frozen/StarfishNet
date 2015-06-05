#include <sn_crypto.h>
#include <sn_status.h>
#include <sn_logging.h>

#include <assert.h>

#include <stdint.h>

//setup uECC
#include <uECC.h>

//polarssl sha1
#include <libsha1.h>

#if SN_PK_key_size != uECC_BYTES
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //SN_PK_key_size != uECC_BYTES

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
    int                          ret = uECC_make_key(unpacked_public_key.data, keypair->private_key.data);
    if(ret != 1) {
        SN_ErrPrintf("key generation failed\n");
        return -SN_ERR_KEYGEN;
    }

    //pack public key
    uECC_compress(unpacked_public_key.data, keypair->public_key.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_sign(SN_Private_key_t* private_key, uint8_t* data, size_t data_len, SN_Signature_t* signature) {
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

int SN_Crypto_verify(SN_Public_key_t* public_key, uint8_t* data, size_t data_len, SN_Signature_t* signature) {
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


int SN_Crypto_key_agreement(SN_Public_key_t* identity_A, SN_Public_key_t* identity_B, SN_Public_key_t* public_key, SN_Private_key_t* private_key, SN_Kex_result_t* shared_secret) {
    SN_InfoPrintf("enter\n");

    if(public_key == NULL || private_key == NULL || shared_secret == NULL) {
        SN_ErrPrintf("identity_A, identity_B, public_key, private_key, and shared_secret must all be non-NULL\n");
        return -SN_ERR_NULL;
    }
    if(identity_A == NULL || identity_B == NULL) {
        SN_WarnPrintf("doing unauthenticated key agreement (no identity %s%s%s). ARE YOU SURE?\n", identity_A == NULL ? "A" : "", identity_A == NULL && identity_B == NULL ? " or " : "" , identity_B == NULL ? "B" : "");
    }

    //unpack public key
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //do ECDH
    SN_Private_key_t raw_shared_secret; //use the private key type because that's the size of the ECDH result
    int              ret = uECC_shared_secret(unpacked_public_key.data, private_key->data, raw_shared_secret.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    //hash resultant secret together with identities of parties involved
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_starts(&ctx);
    sha1_update(&ctx, raw_shared_secret.data, sizeof(raw_shared_secret.data) );
    if(identity_A != NULL) {
        sha1_update(&ctx, identity_A->data, sizeof(identity_A->data));
    }
    if(identity_B != NULL) {
        sha1_update(&ctx, identity_B->data, sizeof(identity_B->data));
    }

    //output resultant link key
    sha1_finish(&ctx, shared_secret->raw.data);
    sha1_free(&ctx);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

void SN_Crypto_hash(uint8_t* data, size_t data_len, SN_Hash_t* hash, size_t repeat_count) {
    sha1(hash->data, data, data_len);

    while(repeat_count-- > 0) {
        sha1(hash->data, hash->data, sizeof(hash->data));
    }
}

#define CCM_MAX_IV_LENGTH 12

int SN_Crypto_encrypt(SN_AES_key_t* key, SN_Public_key_t* key_agreement_key, uint32_t counter, uint8_t* ad, size_t ad_len, uint8_t* data, size_t data_len, uint8_t* tag, bool pure_ack) {
    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    aes_ccm_context ctx;
    int             ret = aes_ccm_init(&ctx, key->data, SN_AES_key_bits);

    if(ret != 0) {
        SN_ErrPrintf("CCM initialisation failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_Hash_t iv;
    sha1_ctx iv_ctx;
    memset(&iv_ctx, 0, sizeof(iv_ctx));
    sha1_begin(&iv_ctx);
    sha1_hash(key_agreement_key->data, sizeof(key_agreement_key->data), &iv_ctx);
    sha1_hash((uint8_t*)&counter, sizeof(counter), &iv_ctx);
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_hash((uint8_t*)"ACK", 3, &iv_ctx);
    }
    sha1_finish(iv.data, &iv_ctx);

    //XXX assumption: CCM_MAX_IV_LENGTH < sizeof(SN_Hash_t)
    ret = aes_ccm_encrypt_and_tag(&ctx, data_len, iv.data, CCM_MAX_IV_LENGTH, ad, ad_len, data, data, tag, SN_Tag_size);

    aes_ccm_free(&ctx);

    if(ret != 0) {
        SN_ErrPrintf("CCM encryption failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_decrypt(SN_AES_key_t* key, SN_Public_key_t* key_agreement_key, uint32_t counter, uint8_t* ad, size_t ad_len, uint8_t* data, size_t data_len, uint8_t* tag, bool pure_ack) {
    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    aes_ccm_context ctx;
    int             ret = aes_ccm_init(&ctx, key->data, SN_AES_key_bits);

    if(ret != 0) {
        SN_ErrPrintf("CCM initialisation failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_Hash_t iv;
    sha1_context iv_ctx;
    sha1_init( &iv_ctx );
    sha1_starts( &iv_ctx );
    sha1_update( &iv_ctx, key_agreement_key->data, sizeof(key_agreement_key->data));
    sha1_update( &iv_ctx, (uint8_t*)&counter, sizeof(counter));
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_update( &iv_ctx, (uint8_t*)"ACK", 3);
    }
    sha1_finish( &iv_ctx, iv.data );
    sha1_free( &iv_ctx );

    //XXX assumption: CCM_MAX_IV_LENGTH < sizeof(SN_Hash_t)
    ret = aes_ccm_auth_decrypt(&ctx, data_len, iv.data, CCM_MAX_IV_LENGTH, ad, ad_len, data, data, tag, SN_Tag_size);

    aes_ccm_free(&ctx);

    if(ret != 0) {
        SN_ErrPrintf("CCM decryption failed with error %d\n", ret);
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_check_certificate(SN_Certificate_t* certificate) {
    SN_InfoPrintf("enter\n");

    if(certificate == NULL) {
        SN_ErrPrintf("certificate must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    return
        SN_Crypto_verify(&certificate->endorser, (void*)&certificate->protected_data, sizeof(certificate->protected_data), &certificate->signature) !=
        SN_OK;
}