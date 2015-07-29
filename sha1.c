// Code by: Brad Conte (http://bradconte.com)
// Released under the GNU GPL
// SHA1 Hash Digest implementation (little endian byte order)
// Modified by: Justin King-Lacroix <justin.king-lacroix@cs.ox.ac.uk>

#include "sha1.h"

#include <string.h>

#define ROTLEFT(a,b) ((a << b) | (a >> (32-b)))
#define LEFT_RIGHT_SHUFFLE(a, b, c, d, e, t, M, K) {\
    t = ROTLEFT(a,5) + e + M + K;\
    e = d;\
    d = c;\
    c = ROTLEFT(b,30);\
    b = a;\
    a = t;\
}

static const sha1_context_t default_ctx = {
    .datalen = 0,
    .blocks  = 0,
    .state   = { 0x67452301,
                 0xEFCDAB89,
                 0x98BADCFE,
                 0x10325476,
                 0xc3d2e1f0 },
    .k       = { 0x5a827999,
                 0x6ed9eba1,
                 0x8f1bbcdc,
                 0xca62c1d6 },
};

static void sha1_transform(sha1_context_t *ctx)
{
    uint8_t i, j;
    static uint32_t a,b,c,d,e,t;
    static uint32_t m[80];
    for (i=0,j=0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)ctx->data[j] << 24) | ((uint32_t)ctx->data[j+1] << 16) | ((uint32_t)ctx->data[j+2] << 8) | ((uint32_t)ctx->data[j+3]);
    }
    for ( ; i < 80; ++i) {
        m[i] = (m[i-3] ^ m[i-8] ^ m[i-14] ^ m[i-16]);
        m[i] = ROTLEFT(m[i], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i=0; i < 20; ++i) {
        LEFT_RIGHT_SHUFFLE(a, b, c, d, e, t, m[i], ctx->k[0] + ((b & c) ^ (~b & d)));
    }
    for ( ; i < 40; ++i) {
        LEFT_RIGHT_SHUFFLE(a, b, c, d, e, t, m[i], ctx->k[1] + (b ^ c ^ d));
    }
    for ( ; i < 60; ++i) {
        LEFT_RIGHT_SHUFFLE(a, b, c, d, e, t, m[i], ctx->k[2] + ((b & c) ^ (b & d) ^ (c & d)));
    }
    for ( ; i < 80; ++i) {
        LEFT_RIGHT_SHUFFLE(a, b, c, d, e, t, m[i], ctx->k[3] + (b ^ c ^ d));
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_starts(sha1_context_t *ctx)
{
    memcpy(ctx, &default_ctx, sizeof(sha1_context_t));
}

void sha1_update(sha1_context_t *ctx, const uint8_t* data, uint8_t len)
{
    while(len-- > 0) {
        ctx->data[ctx->datalen++] = *data++;
        if (ctx->datalen == 64) {
            sha1_transform(ctx);
            ctx->datalen = 0;
            ctx->blocks++;
        }
    }
}

void sha1_finish(sha1_context_t *ctx, uint8_t hash[])
{
    uint8_t i = ctx->datalen;

    // Pad whatever data is left in the buffer.
    if (i < 56) {
        ctx->data[i++] = 0x80;
        memset(ctx->data + i, 0, (uint8_t)56 - i);
    }
    else {
        ctx->data[i++] = 0x80;
        memset(ctx->data + i, 0, (uint8_t)64 - i);
        sha1_transform(ctx);
        memset(ctx->data,0,56);
    }

    // Append to the padding the total message's length in bits and transform.
    memset(ctx->data + 56, 0, 6);
    ctx->data[63] = ctx->datalen << 3; //convert to bits <-> multiply by 8 <-> lshift by 3
    ctx->data[62] = ctx->blocks; //datalen is a 5-bit quantity (2^^6 = 64), so it's entirely expressed in the LSB
    sha1_transform(ctx);

    // Since this implementation uses little endian byte ordering and MD uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i=0; i < 4; ++i) {
        hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff;
        hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff;
        hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
        hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
        hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
    }
}
