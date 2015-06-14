#include "crypto.h"
#include "status.h"
#include "logging.h"

#include "lib/ccm-star.h"

#include "uECC.h"
#include "libsha1.h"

#if SN_PK_key_size != uECC_BYTES
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //SN_PK_key_size != uECC_BYTES

#if SN_Hash_size != SHA1_DIGEST_SIZE
#error "libsha1 and StarfishNet disagree on hash size!"
#endif //SN_Hash_size != SHA1_DIGEST_SIZE

typedef struct SN_ECC_unpacked_public_key {
    uint8_t data[SN_PK_key_size * 2];
} SN_ECC_unpacked_public_key_t;

int SN_Crypto_generate_keypair(SN_Keypair_t* keypair) {
    int ret;
    SN_ECC_unpacked_public_key_t unpacked_public_key;

    SN_InfoPrintf("enter\n");

    if(keypair == NULL) {
        SN_ErrPrintf("keypair cannot be NULL\n");
        return -SN_ERR_NULL;
    }

    //generate keypair
    ret = uECC_make_key(unpacked_public_key.data, keypair->private_key.data);
    if(ret != 1) {
        SN_ErrPrintf("key generation failed\n");
        return -SN_ERR_KEYGEN;
    }

    //pack public key
    uECC_compress(unpacked_public_key.data, keypair->public_key.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_sign ( //sign data into sigbuf
    const SN_Private_key_t* private_key,
    const uint8_t*          data,
    size_t            data_len,
    SN_Signature_t*   signature
) {
    SN_Hash_t hashbuf;
    int ret;

    SN_InfoPrintf("enter\n");

    if(private_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("private_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //hash data
    sha1(hashbuf.data, data, data_len);

    //generate signature
    //XXX: this works because the hash and keys are the same length
    ret = uECC_sign(private_key->data, hashbuf.data, signature->data);
    if(ret == 0) {
        SN_ErrPrintf("error generating digital signature\n");
        return -SN_ERR_SIGNATURE;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_verify ( //verify signature of data in sigbuf
    const SN_Public_key_t*  public_key,
    const uint8_t*          data,
    size_t            data_len,
    const SN_Signature_t*   signature
) {
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    SN_Hash_t hashbuf;
    int ret;

    SN_InfoPrintf("enter\n");

    if(public_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("public_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //unpack public key
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //hash data
    sha1(hashbuf.data, data, data_len);

    //verify signature
    //XXX: this works because the hash and keys are the same length
    ret = uECC_verify(unpacked_public_key.data, hashbuf.data, signature->data);
    if(ret == 0) {
        SN_ErrPrintf("error verifying digital signature\n");
        return -SN_ERR_SIGNATURE;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_key_agreement ( //do an authenticated key agreement into shared_secret
    const SN_Public_key_t* identity_A,
    const SN_Public_key_t* identity_B,
    const SN_Public_key_t*  public_key,
    const SN_Private_key_t* private_key,
    SN_Kex_result_t*  shared_secret
) {
    SN_Private_key_t raw_shared_secret; //use the private key type because that's the size of the ECDH result
    SN_ECC_unpacked_public_key_t unpacked_public_key;
    sha1_ctx ctx;
    int ret;

    SN_InfoPrintf("enter\n");

    if(public_key == NULL || private_key == NULL || shared_secret == NULL) {
        SN_ErrPrintf("identity_A, identity_B, public_key, private_key, and shared_secret must all be non-NULL\n");
        return -SN_ERR_NULL;
    }
    if(identity_A == NULL || identity_B == NULL) {
        SN_WarnPrintf("doing unauthenticated key agreement (no identity %s%s%s). ARE YOU SURE?\n", identity_A == NULL ? "A" : "", identity_A == NULL && identity_B == NULL ? " or " : "" , identity_B == NULL ? "B" : "");
    }

    //unpack public key
    uECC_decompress(public_key->data, unpacked_public_key.data);

    //do ECDH
    ret = uECC_shared_secret(unpacked_public_key.data, private_key->data, raw_shared_secret.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    //hash resultant secret together with identities of parties involved
    memset(&ctx, 0, sizeof(ctx));
    sha1_begin(&ctx);
    sha1_hash(raw_shared_secret.data, sizeof(raw_shared_secret.data), &ctx);
    if(identity_A != NULL) {
        sha1_hash(identity_A->data, sizeof(identity_A->data), &ctx);
    }
    if(identity_B != NULL) {
        sha1_hash(identity_B->data, sizeof(identity_B->data), &ctx);
    }

    //output resultant link key
    sha1_end(shared_secret->raw.data, &ctx);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

void SN_Crypto_hash (
    const uint8_t*   data,
    size_t     data_len,
    SN_Hash_t* hash,
    size_t     repeat_count
) {
    sha1(hash->data, data, data_len);

    while(repeat_count-- > 0) {
        sha1(hash->data, hash->data, sizeof(hash->data));
    }
}

#define CCM_MAX_IV_LENGTH 12

int SN_Crypto_encrypt ( //AEAD-encrypt a data block. tag is 16 bytes
    const SN_AES_key_t*    key,
    const SN_Public_key_t* key_agreement_key,
    uint32_t         counter,
    const uint8_t*   ad,
    size_t           ad_len,
    uint8_t*         data,
    size_t           data_len,
    uint8_t*         tag,
    bool             pure_ack
) {
    SN_Hash_t iv;
    sha1_ctx iv_ctx;

    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    memset(&iv_ctx, 0, sizeof(iv_ctx));
    sha1_begin(&iv_ctx);
    sha1_hash(key_agreement_key->data, sizeof(key_agreement_key->data), &iv_ctx);
    sha1_hash((uint8_t*)&counter, sizeof(counter), &iv_ctx);
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_hash((uint8_t*)"ACK", 3, &iv_ctx);
    }
    sha1_end(iv.data, &iv_ctx);

    //XXX assumption: CCM_MAX_IV_LENGTH < sizeof(SN_Hash_t)
    CCM_STAR.set_key(key->data);
    CCM_STAR.mic(data, data_len, iv.data, CCM_MAX_IV_LENGTH, ad, ad_len, tag, SN_Tag_size);
    CCM_STAR.ctr(data, data_len, iv.data, CCM_MAX_IV_LENGTH);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int SN_Crypto_decrypt ( //AEAD-decrypt a data block. tag is 16 bytes
    const SN_AES_key_t*    key,
    const SN_Public_key_t* key_agreement_key,
    uint32_t         counter,
    const uint8_t*   ad,
    size_t           ad_len,
    uint8_t*         data,
    size_t           data_len,
    const uint8_t*   tag,
    bool             pure_ack
) {
    SN_Hash_t iv;
    sha1_ctx iv_ctx;
    uint8_t prototag[SN_Tag_size];
    int ret;

    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    memset(&iv_ctx, 0, sizeof(iv_ctx));
    sha1_begin(&iv_ctx);
    sha1_hash(key_agreement_key->data, sizeof(key_agreement_key->data), &iv_ctx);
    sha1_hash((uint8_t*)&counter, sizeof(counter), &iv_ctx);
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_hash((uint8_t*)"ACK", 3, &iv_ctx);
    }
    sha1_end(iv.data, &iv_ctx);

    //XXX assumption: CCM_MAX_IV_LENGTH < sizeof(SN_Hash_t)
    CCM_STAR.set_key(key->data);
    CCM_STAR.ctr(data, data_len, iv.data, CCM_MAX_IV_LENGTH);
    CCM_STAR.mic(data, data_len, iv.data, CCM_MAX_IV_LENGTH, ad, ad_len, prototag, SN_Tag_size);

    ret = memcmp(prototag, tag, SN_Tag_size);
    if(ret != 0) {
        SN_ErrPrintf("CCM MIC verification failed.\n");
        return -SN_ERR_SECURITY;
    }

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_check_certificate(const SN_Certificate_t* certificate) {
    SN_InfoPrintf("enter\n");

    if(certificate == NULL) {
        SN_ErrPrintf("certificate must be non-NULL\n");
        return -SN_ERR_NULL;
    }

    return SN_Crypto_verify(
        &certificate->endorser,
        (void*)&certificate->protected_data,
        sizeof(certificate->protected_data),
        &certificate->signature
    ) != SN_OK;
}
