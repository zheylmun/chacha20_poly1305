#include "poly1305.h"
#include <string.h>

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32])
{
    /* r = key[0..15], clamped */
    uint32_t t0 = load32_le(key + 0);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    ctx->r[0] =  t0                         & 0x03ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6))    & 0x03ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12))   & 0x03ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18))   & 0x03f03fff;
    ctx->r[4] =  (t3 >> 8)                  & 0x000fffff;

    /* s = key[16..31] */
    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    ctx->buf_len = 0;
}

static void poly1305_process_block(poly1305_ctx *ctx, const uint8_t *block,
                                   size_t block_len, uint32_t hibit)
{
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3], h4 = ctx->h[4];

    /* Add message block to accumulator */
    uint8_t padded[17];
    memset(padded, 0, sizeof(padded));
    memcpy(padded, block, block_len);
    padded[block_len] = 1; /* Set the high bit */

    uint32_t t0 = load32_le(padded + 0);
    uint32_t t1 = load32_le(padded + 4);
    uint32_t t2 = load32_le(padded + 8);
    uint32_t t3 = load32_le(padded + 12);

    h0 +=  t0                        & 0x03ffffff;
    h1 += ((t0 >> 26) | (t1 << 6))  & 0x03ffffff;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    h4 +=  (t3 >> 8)                 | (hibit << 24);

    /* Multiply h by r */
    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3
                + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4
                + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0
                + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1
                + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2
                + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    /* Partial reduction mod 2^130 - 5 */
    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff; h0 += c * 5;
    c = h0 >> 26;             h0 &= 0x03ffffff;                h1 += c;

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void poly1305_update(poly1305_ctx *ctx, const uint8_t *msg, size_t len)
{
    /* Fill buffer first */
    if (ctx->buf_len > 0) {
        size_t want = 16 - ctx->buf_len;
        if (want > len) want = len;
        memcpy(ctx->buf + ctx->buf_len, msg, want);
        ctx->buf_len += want;
        msg += want;
        len -= want;
        if (ctx->buf_len == 16) {
            poly1305_process_block(ctx, ctx->buf, 16, 1);
            ctx->buf_len = 0;
        }
    }

    /* Process full blocks */
    while (len >= 16) {
        poly1305_process_block(ctx, msg, 16, 1);
        msg += 16;
        len -= 16;
    }

    /* Buffer remaining */
    if (len > 0) {
        memcpy(ctx->buf, msg, len);
        ctx->buf_len = len;
    }
}

void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16])
{
    /* Process final partial block (if any) */
    if (ctx->buf_len > 0) {
        poly1305_process_block(ctx, ctx->buf, ctx->buf_len, 0);
    }

    /* Full reduction mod 2^130 - 5 */
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;

    c = h1 >> 26; h1 &= 0x03ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x03ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x03ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x03ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x03ffffff; h1 += c;

    /* Compute h + -(2^130 - 5) = h - 2^130 + 5 */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x03ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x03ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x03ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x03ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    /* Select h or g based on carry: if g4 didn't underflow, g < 2^130-5 */
    uint32_t mask = (g4 >> 31) - 1; /* 0xffffffff if no underflow (use g), 0 if underflow (use h) */
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Reassemble into 4 x 32-bit words */
    uint32_t f0 = h0 | (h1 << 26);
    uint32_t f1 = (h1 >> 6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 << 8);

    /* Add pad (s) */
    uint64_t t;
    t = (uint64_t)f0 + ctx->pad[0];             f0 = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)f1 + ctx->pad[1] + c;         f1 = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)f2 + ctx->pad[2] + c;         f2 = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)f3 + ctx->pad[3] + c;         f3 = (uint32_t)t;

    store32_le(tag + 0,  f0);
    store32_le(tag + 4,  f1);
    store32_le(tag + 8,  f2);
    store32_le(tag + 12, f3);

    /* Wipe sensitive state */
    memset(ctx, 0, sizeof(*ctx));
}
