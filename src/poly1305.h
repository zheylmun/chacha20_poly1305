#ifndef POLY1305_INTERNAL_H
#define POLY1305_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t r[5];     /* clamped key, radix 2^26 */
    uint32_t h[5];     /* accumulator, radix 2^26 */
    uint32_t pad[4];   /* final addition key (s) */
    uint8_t  buf[16];  /* partial block buffer */
    size_t   buf_len;  /* bytes in partial buffer */
} poly1305_ctx;

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *ctx, const uint8_t *msg, size_t len);
void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16]);

#endif
