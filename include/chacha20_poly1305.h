/**
@file chacha20_poly1305.h
@brief ChaCha20-Poly1305 AEAD (RFC 7539).

@details
Authenticated Encryption with Associated Data (AEAD) combining ChaCha20 for
encryption and Poly1305 for authentication.
Provides confidentiality for the plaintext and integrity for both the plaintext
and additional authenticated data (AAD).
The only public API of this library.

## Parameters

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

## Encryption

```mermaid
flowchart TB
  KeyGen["ChaCha20 block (counter=0) → Poly1305 one-time key"]
  Enc["ChaCha20 encrypt (counter=1) → ciphertext"]
  Mac["Poly1305 MAC over padded AAD + ciphertext + lengths → tag"]
  KeyGen --> Enc --> Mac
```

## Decryption

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

## MAC Input Construction

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

@see RFC 7539 Section 2.8
**/
#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_POLY1305_KEY_SIZE   32
#define CHACHA20_POLY1305_NONCE_SIZE 12
#define CHACHA20_POLY1305_TAG_SIZE   16

/**
@brief Encrypt and authenticate.

Encrypts the plaintext with ChaCha20 and computes a Poly1305
authentication tag over the AAD and ciphertext.

@param[out] ciphertext  Output buffer for encrypted data.
                        Must be at least @p plaintext_len bytes.
                        May be NULL when @p plaintext_len is 0.
@param[out] tag         Output buffer for the 16-byte authentication tag.
@param[in]  plaintext   Input data to encrypt.
                        May be NULL when @p plaintext_len is 0.
@param[in]  plaintext_len Length of @p plaintext in bytes.
@param[in]  aad         Additional authenticated data (not encrypted).
                        May be NULL when @p aad_len is 0.
@param[in]  aad_len     Length of @p aad in bytes.
@param[in]  key         32-byte encryption key.
@param[in]  nonce       12-byte nonce, must be unique per (key, message) pair.
@return 0 on success, nonzero on error.
**/
int chacha20_poly1305_encrypt(
    uint8_t       *ciphertext,
    uint8_t        tag[16],
    const uint8_t *plaintext,
    size_t         plaintext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12]);

/**
@brief Decrypt and verify.

Verifies the Poly1305 authentication tag and, only on success, decrypts
the ciphertext with ChaCha20.  On tag mismatch the output buffer is
zeroed and a nonzero error code is returned.

@param[out] plaintext      Output buffer for decrypted data.
                           Must be at least @p ciphertext_len bytes.
                           Zeroed on authentication failure.
                           May be NULL when @p ciphertext_len is 0.
@param[in]  ciphertext     Input encrypted data.
                           May be NULL when @p ciphertext_len is 0.
@param[in]  ciphertext_len Length of @p ciphertext in bytes.
@param[in]  aad            Additional authenticated data used during encryption.
                           May be NULL when @p aad_len is 0.
@param[in]  aad_len        Length of @p aad in bytes.
@param[in]  tag            16-byte authentication tag to verify.
@param[in]  key            32-byte encryption key (same key used to encrypt).
@param[in]  nonce          12-byte nonce (same nonce used to encrypt).
@return 0 on success, nonzero on tag mismatch.
**/
int chacha20_poly1305_decrypt(
    uint8_t       *plaintext,
    const uint8_t *ciphertext,
    size_t         ciphertext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  tag[16],
    const uint8_t  key[32],
    const uint8_t  nonce[12]);

#endif
