/**
@file chacha20.h
@brief ChaCha20 stream cipher (RFC 7539, internal).

@details
ChaCha20 generates a keystream from a 256-bit key, 32-bit block counter,
and 96-bit nonce.  The keystream is XORed with plaintext to produce
ciphertext (and vice versa).

## State Layout

The core operates on a 4x4 matrix of 32-bit words (512 bits total),
initialized from fixed constants, the key, a counter, and a nonce.
All multi-byte values are little-endian.

```mermaid
block-beta
  columns 4
  A["'expa' 0x61707865"] B["'nd 3' 0x3320646e"] C["'2-by' 0x79622d32"] D["'te k' 0x6b206574"]
  E["Key[0..3]"]  F["Key[4..7]"]  G["Key[8..11]"]  H["Key[12..15]"]
  I["Key[16..19]"] J["Key[20..23]"] K["Key[24..27]"] L["Key[28..31]"]
  M["Counter"]    N["Nonce[0..3]"] O["Nonce[4..7]"] P["Nonce[8..11]"]
```

## Quarter Round

The quarter round is the primitive mixing operation.  It takes four words
(a, b, c, d) and applies four add-xor-rotate steps:

    a += b;  d ^= a;  d <<<= 16;
    c += d;  b ^= c;  b <<<= 12;
    a += b;  d ^= a;  d <<<=  8;
    c += d;  b ^= c;  b <<<=  7;

## Block Function

Each block produces 64 bytes of keystream.  The block function initializes
the state, applies 20 rounds (10 iterations of column + diagonal quarter
rounds), adds the original state back, and serializes the result as
little-endian bytes.

```mermaid
flowchart LR
  Init["Initialize\n4x4 state from\nkey, counter, nonce"]
  Rounds["20 rounds\n(10x column QR +\n10x diagonal QR)"]
  Add["Add original\nstate back"]
  Ser["Serialize to\n64 LE bytes"]
  Init --> Rounds --> Add --> Ser
```

### Column vs Diagonal Quarter Rounds

Each double-round applies quarter rounds to columns then diagonals
of the 4x4 state matrix:

```mermaid
flowchart TB
  subgraph Columns
    direction LR
    C0["QR(0, 4,  8, 12)"]
    C1["QR(1, 5,  9, 13)"]
    C2["QR(2, 6, 10, 14)"]
    C3["QR(3, 7, 11, 15)"]
  end
  subgraph Diagonals
    direction LR
    D0["QR(0, 5, 10, 15)"]
    D1["QR(1, 6, 11, 12)"]
    D2["QR(2, 7,  8, 13)"]
    D3["QR(3, 4,  9, 14)"]
  end
  Columns --> Diagonals
```

## Encryption

To encrypt a message of arbitrary length, the block function is called
repeatedly with an incrementing counter.  Each 64-byte keystream block
is XORed with the corresponding plaintext chunk.  The final block may
be partial.

```mermaid
flowchart LR
  subgraph "For each 64-byte chunk"
    Block["chacha20_block\n(key, counter++, nonce)"]
    XOR["output = input XOR keystream"]
    Block --> XOR
  end
```

@see RFC 7539 Sections 2.1-2.4
**/
#ifndef CHACHA20_INTERNAL_H
#define CHACHA20_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/** Quarter round operation (exposed for testing). */
void chacha20_quarter_round(uint32_t *a, uint32_t *b,
                            uint32_t *c, uint32_t *d);

/* Compute one 64-byte keystream block. */
void chacha20_block(uint32_t out[16],
                    const uint8_t key[32],
                    uint32_t counter,
                    const uint8_t nonce[12]);

/* XOR plaintext with keystream starting at the given counter value. */
void chacha20_encrypt(uint8_t *output,
                      const uint8_t *input,
                      size_t len,
                      const uint8_t key[32],
                      const uint8_t nonce[12],
                      uint32_t counter);

#endif
