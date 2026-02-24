#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_POLY1305_KEY_SIZE   32
#define CHACHA20_POLY1305_NONCE_SIZE 12
#define CHACHA20_POLY1305_TAG_SIZE   16

/* Encrypt and authenticate.
 * Returns 0 on success, nonzero on error. */
int chacha20_poly1305_encrypt(
    uint8_t       *ciphertext,      /* out: plaintext_len bytes */
    uint8_t        tag[16],         /* out: authentication tag  */
    const uint8_t *plaintext,
    size_t         plaintext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12]);

/* Decrypt and verify.
 * Returns 0 on success, nonzero on tag mismatch. */
int chacha20_poly1305_decrypt(
    uint8_t       *plaintext,       /* out: ciphertext_len bytes */
    const uint8_t *ciphertext,
    size_t         ciphertext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  tag[16],
    const uint8_t  key[32],
    const uint8_t  nonce[12]);

#endif
