#ifndef STARFISHNET_SHA1_H
#define STARFISHNET_SHA1_H

// Code by: B-Con (http://b-con.us)
// Released under the GNU GPL
// MD5 Hash Digest implementation (little endian byte order)

#include <stdint.h>
#include <stddef.h>

//modified from version found at http://bradconte.com/sha1_c

typedef struct {
    uint8_t data[64]; //current block
    uint8_t datalen;  //number of bytes in block

    uint32_t bitlen[2];
    uint32_t state[5];
    uint32_t k[4];
} sha1_context_t;

void sha1_starts(sha1_context_t *ctx);
void sha1_update(sha1_context_t *ctx, const uint8_t* data, size_t len);
void sha1_finish(sha1_context_t *ctx, uint8_t hash[]);

#endif //STARFISHNET_SHA1_H
