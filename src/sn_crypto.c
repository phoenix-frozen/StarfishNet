#include "sn_crypto.h"
#include "sn_status.h"
#include "sn_logging.h"

//setup uECC
#define uECC_CURVE uECC_secp160r1
#define uECC_PLATFORM uECC_x86_64
#include "uECC.h"

int SN_Crypto_generate_keypair(SN_ECC_keypair_t* keypair) {
    SN_InfoPrintf("enter\n");

    if(keypair == NULL) {
        SN_ErrPrintf("keypair cannot be NULL\n");
        return -SN_ERR_NULL;
    }

    uint8_t public_key_data[2*SN_ECC_key_size/8];

    int ret = uECC_make_key(public_key_data, keypair->private_key.data);
    if(ret != 1) {
        SN_ErrPrintf("key generation failed\n");
        return -SN_ERR_KEYGEN;
    }

    uECC_compress(public_key_data, keypair->public_key.data);

    return SN_OK;
}


int SN_Crypto_sign(SN_ECC_private_key_t* private_key, uint8_t* data, int data_len, SN_ECDSA_signature_t* signature);

int SN_Crypto_verify(SN_ECC_public_key_t* key, uint8_t* data, int data_len, SN_ECDSA_signature_t* signature);
