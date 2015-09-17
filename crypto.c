#include "crypto.h"
#include "status.h"
#include "logging.h"
#include "sha1.h"
#include "uECC.h"

#include "lib/random.h"
#include "lib/aes-128.h"
#include "lib/ccm-star.h"

#if SN_PK_key_size != uECC_BYTES
#error "uECC and StarfishNet disagree on ECC key size!"
#endif //SN_PK_key_size != uECC_BYTES

#if SN_AES_block_size != AES_128_BLOCK_SIZE
#error "Contiki and StarfishNet disagree on AES block size!"
#endif //SN_AES_block_size != AES_128_BLOCK_SIZE

#if SN_AES_key_size != AES_128_KEY_LENGTH
#error "Contiki and StarfishNet disagree on AES key size!"
#endif //SN_AES_key_size != AES_128_KEY_LENGTH

#if SN_Hash_size < SN_AES_key_size
#error "Hashes need to be bigger than or equal to AES keys!"
#endif //SN_Hash_size < SN_AES_key_size

#if SN_Hash_size != SN_PK_key_size
#error "We assume that hashes and private keys are the same size!"
#endif //SN_Hash_size != SN_PK_key_size

//some temporary buffers to store intermediate values
static union {
    uint8_t        unpacked_public_key[SN_PK_key_size * 2];
    sha1_context_t ctx;
} temp;

static int8_t generate_random_number(uint8_t *dest, unsigned size) {
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

static void do_key_gen(SN_Keypair_t *keypair) {
    do {
        //generate uECC_BYTES random bytes
        generate_random_number(keypair->private_key.data, sizeof(keypair->private_key.data));

        SN_InfoPrintf("attempting key generation...\n");
        //generate keypair
    } while (uECC_make_key(temp.unpacked_public_key, keypair->private_key.data) != 1);

    //pack public key
    uECC_compress(temp.unpacked_public_key, keypair->public_key.data);
}

#define KEY_POOL_SIZE 4
static SN_Keypair_t key_pool[KEY_POOL_SIZE];
static uint8_t key_pool_idx = KEY_POOL_SIZE;

int8_t SN_Crypto_generate_keypair(SN_Keypair_t *keypair) {
    SN_InfoPrintf("enter\n");

    if(keypair == NULL) {
        SN_ErrPrintf("keypair cannot be NULL\n");
        return -SN_ERR_NULL;
    }

    if(key_pool_idx < KEY_POOL_SIZE) {
        memcpy(keypair, key_pool + key_pool_idx, sizeof(*keypair));
        key_pool_idx++;
        SN_InfoPrintf("exit (fast)\n");
        return SN_OK;
    }

    for(key_pool_idx = 0; key_pool_idx < KEY_POOL_SIZE; key_pool_idx++) {
        do_key_gen(key_pool + key_pool_idx);
    }
    key_pool_idx = 0;

    do_key_gen(keypair);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}


int8_t SN_Crypto_sign(
    const SN_Private_key_t *private_key,
    const uint8_t *data,
    uint8_t data_len,
    SN_Signature_t *signature
) {
    static SN_Hash_t hashbuf;
    static uint8_t k[uECC_BYTES + uECC_FUDGE_FACTOR];

    SN_InfoPrintf("enter\n");

    if(private_key == NULL || data == NULL || data_len == 0 || signature == NULL) {
        SN_ErrPrintf("key, data, and signature must all be valid\n");
        return -SN_ERR_NULL;
    }
    //hash data
    SN_Crypto_hash(data, data_len, &hashbuf);

    do {
        //generate k
        generate_random_number(k, uECC_BYTES + uECC_FUDGE_FACTOR);
#if (uECC_CURVE == uECC_secp160r1)
        k[uECC_BYTES] &= 0x01;
#endif

        //generate signature
        SN_InfoPrintf("attempting signature...\n");
    } while (uECC_sign(private_key->data, hashbuf.data, k, signature->data) != 1);

    SN_InfoPrintf("exit\n");
    return SN_OK;
}

int8_t SN_Crypto_verify(
    const SN_Public_key_t *public_key,
    const uint8_t *data,
    uint8_t data_len,
    const SN_Signature_t *signature
) {
    static SN_Hash_t hashbuf;
    int8_t ret;

    SN_InfoPrintf("enter\n");

    if(public_key == NULL || data == NULL || data_len == 0 || signature == NULL) {
        SN_ErrPrintf("key, data, and signature must all be valid\n");
        return -SN_ERR_NULL;
    }

    //hash data
    SN_Crypto_hash(data, data_len, &hashbuf);

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


int8_t SN_Crypto_key_agreement( //do an authenticated key agreement into shared_secret
    const SN_Public_key_t *identity_A,
    const SN_Public_key_t *identity_B,
    const SN_Public_key_t *public_key,
    const SN_Private_key_t *private_key,
    SN_Kex_result_t *shared_secret
) {
    int8_t ret;

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
    ret = uECC_shared_secret(temp.unpacked_public_key, private_key->data, shared_secret->raw.data);
    if(ret == 0) {
        SN_ErrPrintf("error performing key agreement\n");
        return -SN_ERR_KEYGEN;
    }

    SN_InfoPrintf("ECDH complete\n");

    //hash resultant secret together with identities of parties involved
    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, shared_secret->raw.data, sizeof(shared_secret->raw.data));
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

void SN_Crypto_hash(const uint8_t *data, uint8_t data_len, SN_Hash_t *hash) {
    SN_InfoPrintf("enter\n");

    sha1_starts(&temp.ctx);
    sha1_update(&temp.ctx, data, data_len);
    sha1_finish(&temp.ctx, hash->data);

    SN_InfoPrintf("exit\n");
}

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
) {
    static SN_Hash_t iv;

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
) {
    static SN_Hash_t iv;
    static uint8_t prototag[SN_Tag_size];
    int8_t ret;

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
