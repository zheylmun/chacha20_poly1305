/**
@file poly1305.h
@brief Poly1305 one-time authenticator (RFC 7539, internal).

@details
Poly1305 computes a 128-bit authentication tag over a message using a
one-time 256-bit key.  The key must never be reused.  In the AEAD
construction the key is derived from ChaCha20 block 0.

## Key Layout

The 32-byte key is split into two halves:

```mermaid
block-beta
  columns 2
  R["r (16 bytes) — clamped multiplier"]
  S["s (16 bytes) — final addition pad"]
```

The `r` half is clamped: certain bits are forced to zero to ensure the
multiplier has a restricted form required for security.  Specifically,
the top 4 bits of bytes 3, 7, 11, 15 and the bottom 2 bits of bytes
4, 8, 12 are cleared.

## Internal Representation

Both `r` and the accumulator `h` are stored in radix 2^26 (five 26-bit
limbs in uint32_t), which keeps intermediate products within uint64_t
range during the multiply-and-reduce step.

```mermaid
block-beta
  columns 5
  A["limb 0 (bits 0-25)"]
  B["limb 1 (bits 26-51)"]
  C["limb 2 (bits 52-77)"]
  D["limb 3 (bits 78-103)"]
  E["limb 4 (bits 104-129)"]
```

## Processing Flow

The message is processed in 16-byte blocks.  Each block is read as a
little-endian 128-bit integer, a high bit is set (bit 128 for full
blocks, bit 8*len for the final partial block), and the result is
added to the accumulator then multiplied by `r` modulo 2^130 - 5.

```mermaid
flowchart LR
  subgraph "For each 16-byte block"
    Read["Read block as LE 128-bit"]
    HiBit["Set bit 128 (or 8*len)"]
    Add["h += block"]
    Mul["h = (h * r) mod 2^130 - 5"]
    Read --> HiBit --> Add --> Mul
  end
```

## Finalization

After all blocks are processed, `h` is fully reduced modulo 2^130 - 5,
then the pad `s` is added modulo 2^128.  The lower 128 bits are output
as the 16-byte tag in little-endian order.

```mermaid
flowchart LR
  Reduce["Fully reduce h mod 2^130 - 5"]
  AddS["tag = (h + s) mod 2^128"]
  Out["Output 16 LE bytes"]
  Reduce --> AddS --> Out
```

@see RFC 7539 Sections 2.5-2.6
**/
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
