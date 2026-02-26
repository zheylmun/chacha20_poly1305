# Cha Cha20 Poly1305

This library implements the ChaCha20 stream cipher and Poly1305 message authentication code (MAC) as defined in [RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539).
It provides a high-level API for authenticated encryption and decryption using the ChaCha20-Poly1305 AEAD construction.
It provides only the high-level API, and does not expose the underlying primitives (e.g. quarter round, block function) as public APIs.
> [!WARNING]
> This library is intended for educational purposes and should not be used in production environments without thorough review and validation.
> Further development and support is not planned.
> It has not been audited and may contain vulnerabilities.
> Use at your own risk.

## ChaCha20-Poly1305 AEAD Construction

Authenticated Encryption with Associated Data (AEAD) combining ChaCha20 for
encryption and Poly1305 for authentication.
Provides confidentiality for the plaintext and integrity for both the plaintext
and additional authenticated data (AAD).
The only public API of this library.

### Parameters

```mermaid
block-beta
  columns 3
  A["Key (32 bytes)"] B["Nonce (12 bytes)"] C["Tag (16 bytes)"]
```

- **Key**: 256-bit secret key, must be random and unique per context.
- **Nonce**: 96-bit value, must be unique per (key, message) pair.
- **Tag**: 128-bit authentication tag produced during encryption and
  verified during decryption.
- **AAD**: Arbitrary-length additional data authenticated but not encrypted
  (may be empty).

### Encryption

```mermaid
flowchart TB
  KeyGen["ChaCha20 block (counter=0) → Poly1305 one-time key"]
  Enc["ChaCha20 encrypt (counter=1) → ciphertext"]
  Mac["Poly1305 MAC over padded AAD + ciphertext + lengths → tag"]
  KeyGen --> Enc --> Mac
```

### Decryption

```mermaid
flowchart TB
  KeyGen["ChaCha20 block (counter=0) → Poly1305 one-time key"]
  Mac["Poly1305 MAC over padded AAD + ciphertext + lengths → expected tag"]
  Verify{"Constant-time\ntag compare"}
  Dec["ChaCha20 decrypt (counter=1) → plaintext"]
  Fail["Zero output, return error"]
  KeyGen --> Mac --> Verify
  Verify -- "match" --> Dec
  Verify -- "mismatch" --> Fail
```

### MAC Input Construction

The Poly1305 MAC is computed over a specific padded layout:

```mermaid
block-beta
  columns 1
  A["AAD (aad_len bytes)"]
  B["Zero padding to 16-byte boundary"]
  C["Ciphertext (ct_len bytes)"]
  D["Zero padding to 16-byte boundary"]
  E["aad_len as 64-bit LE || ct_len as 64-bit LE"]
```

Reference: [RFC 7539-section2.8](https://datatracker.ietf.org/doc/html/rfc7539#section-2.8)

## Chacha20 Stream Cypher Algorithm

ChaCha20 generates a keystream from a 256-bit key, 32-bit block counter,
and 96-bit nonce.  The keystream is XORed with plaintext to produce
ciphertext (and vice versa).

### State Layout

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

### Quarter Round

The quarter round is the primitive mixing operation.  It takes four words
(a, b, c, d) and applies four add-xor-rotate steps:

    a += b;  d ^= a;  d <<<= 16;
    c += d;  b ^= c;  b <<<= 12;
    a += b;  d ^= a;  d <<<=  8;
    c += d;  b ^= c;  b <<<=  7;

### Block Function

Each block produces 64 bytes of keystream.  The block function initializes
the state, applies 20 rounds (10 iterations of column + diagonal quarter
rounds), adds the original state back, and serializes the result as
little-endian bytes.

```mermaid
flowchart LR
  Init["Initialize 4x4 state from key, counter, nonce"]
  Rounds["20 rounds (10x column QR + 10x diagonal QR)"]
  Add["Add original state back"]
  Ser["Serialize to 64 LE bytes"]
  Init --> Rounds --> Add --> Ser
```

#### Column vs Diagonal Quarter Rounds

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

### Encryption

To encrypt a message of arbitrary length, the block function is called
repeatedly with an incrementing counter.  Each 64-byte keystream block
is XORed with the corresponding plaintext chunk.  The final block may
be partial.

```mermaid
flowchart LR
  subgraph "For each 64-byte chunk"
    Block["chacha20_block (key, counter++, nonce)"]
    XOR["output = input XOR keystream"]
    Block --> XOR
  end
```

Reference: [RFC 7539-section2.1](https://datatracker.ietf.org/doc/html/rfc7539#section-2.1)

## Poly1305 MAC Algorithm

Poly1305 computes a 128-bit authentication tag over a message using a
one-time 256-bit key.  The key must never be reused.  In the AEAD
construction the key is derived from ChaCha20 block 0.

### Key Layout

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

### Internal Representation

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

### Processing Flow

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

### Finalization

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

Reference: [RFC 7539-section2.5](https://datatracker.ietf.org/doc/html/rfc7539#section-2.5))
