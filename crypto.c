#include "crypto.h"
#include "status.h"
#include "logging.h"
#include "sha1.h"
#include "uECC.h"

#include "lib/random.h"
#include "lib/ccm-star.h"

#if SN_PK_key_size != uECC_BYTES
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //SN_PK_key_size != uECC_BYTES

//some temporary buffers to store intermediate values
static union {
    uint8_t        unpacked_public_key[SN_PK_key_size * 2];
    sha1_context_t ctx;
} temp;

static int generate_random_number(uint8_t *dest, unsigned size) {
    uint16_t rand;

    for(; size > 1; size -= 2, dest += 2) {
        rand = random_rand();
        memcpy(dest, &rand, 2);
    }

    if(size > 0) {
        rand = random_rand();
        memcpy(dest, &rand, 1);
    }

    return 1;
}

int SN_Crypto_generate_keypair(SN_Keypair_t* keypair) {
    SN_InfoPrintf("enter\n");

    if(keypair == NULL) {
        SN_ErrPrintf("keypair cannot be NULL\n");
        return -SN_ERR_NULL;
    }

    do {
        //generate uECC_BYTES random bytes
        generate_random_number(keypair->private_key.data, sizeof(keypair->private_key.data));

        SN_InfoPrintf("attempting key generation...\n");
        //generate keypair
    } while(uECC_make_key(temp.unpacked_public_key, keypair->private_key.data) != 1);

    //pack public key
    uECC_compress(temp.unpacked_public_key, keypair->public_key.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int SN_Crypto_sign ( //sign data into sigbuf
    const SN_Private_key_t* private_key,
    const uint8_t*          data,
    size_t            data_len,
    SN_Signature_t*   signature
) {
    static SN_Hash_t hashbuf;
    int ret;

    SN_InfoPrintf("enter\n");

    if(private_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("private_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //hash data
    SN_Crypto_hash(data, data_len, &hashbuf, 0);

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
    static SN_Hash_t hashbuf;
    int ret;

    SN_InfoPrintf("enter\n");

    if(public_key == NULL || (data == NULL && data_len > 0) || signature == NULL) {
        SN_ErrPrintf("public_key, data, and signature must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    //hash data
    SN_Crypto_hash(data, data_len, &hashbuf, 0);

    //unpack public key
    uECC_decompress(public_key->data, temp.unpacked_public_key);

    //verify signature
    //XXX: this works because the hash and keys are the same length
    ret = uECC_verify(temp.unpacked_public_key, hashbuf.data, signature->data);
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
    static SN_Private_key_t raw_shared_secret; //use the private key type because that's the size of the ECDH result
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
    uECC_decompress(public_key->data, temp.unpacked_public_key);

    //do ECDH
    ret = uECC_shared_secret(temp.unpacked_public_key, private_key->data, raw_shared_secret.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    //hash resultant secret together with identities of parties involved
    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, raw_shared_secret.data, sizeof(raw_shared_secret.data));
    if(identity_A != NULL) {
        sha1_update(&temp.ctx, identity_A->data, sizeof(identity_A->data));
    }
    if(identity_B != NULL) {
        sha1_update(&temp.ctx, identity_B->data, sizeof(identity_B->data));
    }

    //output resultant link key
    sha1_finish(&temp.ctx, shared_secret->raw.data);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

void SN_Crypto_hash (
    const uint8_t*   data,
    size_t     data_len,
    SN_Hash_t* hash,
    size_t     repeat_count
) {
    SN_InfoPrintf("enter\n");

    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, data, data_len);
    sha1_finish(&temp.ctx, hash->data);

    while(repeat_count-- > 0) {
        sha1_starts(&temp.ctx);
        sha1_update(&temp.ctx, hash->data, SN_Hash_size);
        sha1_finish(&temp.ctx, hash->data);
    }

    SN_InfoPrintf("exit\n");
}

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

    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, key_agreement_key->data, sizeof(key_agreement_key->data));
    sha1_update(&temp.ctx, (uint8_t*)&counter, sizeof(counter));
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_update(&temp.ctx, "ACK", 3);
    }
    sha1_finish(&temp.ctx, iv.data);

    //XXX assumption: SN_Hash_size >= 13
    CCM_STAR.set_key(key->data);
    CCM_STAR.mic(data, data_len, iv.data, ad, ad_len, tag, SN_Tag_size);
    CCM_STAR.ctr(data, data_len, iv.data);

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
    uint8_t prototag[SN_Tag_size];
    int ret;

    SN_InfoPrintf("enter\n");

    if(key == NULL || key_agreement_key == NULL || (ad == NULL && ad_len > 0) || (data == NULL && data_len > 0) || tag == NULL) {
        SN_ErrPrintf("key, key_agreement_key, ad, data, and tag must all be non-NULL\n");
        return -SN_ERR_NULL;
    }

    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, key_agreement_key->data, sizeof(key_agreement_key->data));
    sha1_update(&temp.ctx, (uint8_t*)&counter, sizeof(counter));
    if(pure_ack) {
        //this is to prevent IV reuse without requiring retransmission of pure-ack packets
        sha1_update(&temp.ctx, "ACK", 3);
    }
    sha1_finish(&temp.ctx, iv.data);

    //XXX assumption: SN_Hash_size >= 13
    CCM_STAR.set_key(key->data);
    CCM_STAR.ctr(data, data_len, iv.data);
    CCM_STAR.mic(data, data_len, iv.data, ad, ad_len, prototag, SN_Tag_size);

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
