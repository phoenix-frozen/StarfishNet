/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _MICRO_ECC_H_
#define _MICRO_ECC_H_

#include <stdint.h>

/* Platform selection options.
If uECC_PLATFORM is not defined, the code will try to guess it based on compiler macros.
Possible values for uECC_PLATFORM are defined below: */
#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_avr        5
#define uECC_arm_thumb2 6

/* If desired, you can define uECC_WORD_SIZE as appropriate for your platform (1, 4, or 8 bytes).
If uECC_WORD_SIZE is not explicitly defined then it will be automatically set based on your
platform. */

/* Inline assembly options.
uECC_asm_none  - Use standard C99 only.
uECC_asm_small - Use GCC inline assembly for the target platform (if available), optimized for
                 minimum size.
uECC_asm_fast  - Use GCC inline assembly optimized for maximum speed. */
#define uECC_asm_none  0
#define uECC_asm_small 1
#define uECC_asm_fast  2
#ifndef uECC_ASM
    #define uECC_ASM uECC_asm_fast
#endif

/* Curve selection options. */
#define uECC_secp160r1 1
#define uECC_secp192r1 2
#define uECC_secp256r1 3
#define uECC_secp256k1 4
#define uECC_secp224r1 5
#ifndef uECC_CURVE
    #define uECC_CURVE uECC_secp160r1
#endif

/* uECC_SQUARE_FUNC - If enabled (defined as nonzero), this will cause a specific function to be
used for (scalar) squaring instead of the generic multiplication function. This will make things
faster by about 8% but increases the code size. */
#ifndef uECC_SQUARE_FUNC
    #define uECC_SQUARE_FUNC 1
#endif

#define uECC_CONCAT1(a, b) a##b
#define uECC_CONCAT(a, b) uECC_CONCAT1(a, b)

#define uECC_size_1 20 /* secp160r1 */
#define uECC_size_2 24 /* secp192r1 */
#define uECC_size_3 32 /* secp256r1 */
#define uECC_size_4 32 /* secp256k1 */
#define uECC_size_5 28 /* secp224r1 */

#define uECC_FUDGE_FACTOR_1 1 /* secp160r1 */
#define uECC_FUDGE_FACTOR_2 0 /* secp192r1 */
#define uECC_FUDGE_FACTOR_3 0 /* secp256r1 */
#define uECC_FUDGE_FACTOR_4 0 /* secp256k1 */
#define uECC_FUDGE_FACTOR_5 0 /* secp224r1 */

#define uECC_BYTES uECC_CONCAT(uECC_size_, uECC_CURVE)
#define uECC_FUDGE_FACTOR uECC_CONCAT(uECC_FUDGE_FACTOR_, uECC_CURVE)

#ifdef __cplusplus
extern "C"
{
#endif

/* uECC_make_key() function.
Create a public/private key pair.

Outputs:
    public_key  - Will be filled in with the public key.
    private_key - Should be filled with uECC_BYTES random bytes.

Returns 1 if the key pair was generated successfully, 0 if an error occurred.
*/
uint8_t uECC_make_key(uint8_t public_key[uECC_BYTES * 2], const uint8_t private_key[uECC_BYTES]);

/* uECC_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key.
Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
symmetric encryption or HMAC.

Inputs:
    public_key  - The public key of the remote party.
    private_key - Your private key.

Outputs:
    secret - Will be filled in with the shared secret value.

Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
*/
uint8_t uECC_shared_secret(const uint8_t public_key[uECC_BYTES * 2],
                           const uint8_t private_key[uECC_BYTES],
                           uint8_t secret[uECC_BYTES]);

/* uECC_sign() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key.

Inputs:
    private_key  - Your private key.
    message_hash - The hash of the message to sign.

Outputs:
    signature - Will be filled in with the signature value.

Returns 1 if the signature generated successfully, 0 if an error occurred.

EDIT: this takes a K in, in order to eliminate the RNG and HMAC code
*/
uint8_t uECC_sign(const uint8_t private_key[uECC_BYTES],
                  const uint8_t message_hash[uECC_BYTES],
                  uint8_t k[uECC_BYTES + uECC_FUDGE_FACTOR],
                  uint8_t signature[uECC_BYTES*2]);

/* uECC_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    public_key - The signer's public key
    hash       - The hash of the signed data.
    signature  - The signature value.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
uint8_t uECC_verify(const uint8_t private_key[uECC_BYTES * 2],
                    const uint8_t hash[uECC_BYTES],
                    const uint8_t signature[uECC_BYTES * 2]);

/* uECC_compress() function.
Compress a public key.

Inputs:
    public_key - The public key to compress.

Outputs:
    compressed - Will be filled in with the compressed public key.
*/
void uECC_compress(const uint8_t public_key[uECC_BYTES*2], uint8_t compressed[uECC_BYTES+1]);

/* uECC_decompress() function.
Decompress a compressed public key.

Inputs:
    compressed - The compressed public key.

Outputs:
    public_key - Will be filled in with the decompressed public key.
*/
void uECC_decompress(const uint8_t compressed[uECC_BYTES+1], uint8_t public_key[uECC_BYTES*2]);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _MICRO_ECC_H_ */
