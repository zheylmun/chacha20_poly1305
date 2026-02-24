#include "chacha20_poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include <string.h>

/** @brief Store a 64-bit word as 8 bytes in little-endian order. */
static void store64_le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/** @brief Store a 32-bit word as 4 bytes in little-endian order. */
static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
@brief Compute the Poly1305 authentication tag for the AEAD construction.

Feeds padded AAD, padded ciphertext, and the two 64-bit LE lengths into
a Poly1305 instance keyed with the one-time key.

@param[out] tag     16-byte output tag.
@param[in]  aad     Additional authenticated data (may be NULL if @p aad_len is 0).
@param[in]  aad_len Length of @p aad in bytes.
@param[in]  ct      Ciphertext (may be NULL if @p ct_len is 0).
@param[in]  ct_len  Length of @p ct in bytes.
@param[in]  otk     32-byte Poly1305 one-time key.
**/
static void poly1305_compute_tag(uint8_t tag[16],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct,  size_t ct_len,
                                 const uint8_t otk[32])
{
    poly1305_ctx ctx;
    uint8_t zeros[16] = {0};
    uint8_t len_block[16];

    poly1305_init(&ctx, otk);

    /* AAD + padding */
    if (aad_len > 0) {
        poly1305_update(&ctx, aad, aad_len);
    }
    size_t pad_aad = (16 - (aad_len % 16)) % 16;
    if (pad_aad > 0) {
        poly1305_update(&ctx, zeros, pad_aad);
    }

    /* Ciphertext + padding */
    if (ct_len > 0) {
        poly1305_update(&ctx, ct, ct_len);
    }
    size_t pad_ct = (16 - (ct_len % 16)) % 16;
    if (pad_ct > 0) {
        poly1305_update(&ctx, zeros, pad_ct);
    }

    /* Lengths as little-endian 64-bit */
    store64_le(len_block, (uint64_t)aad_len);
    store64_le(len_block + 8, (uint64_t)ct_len);
    poly1305_update(&ctx, len_block, 16);

    poly1305_finish(&ctx, tag);
}

int chacha20_poly1305_encrypt(
    uint8_t       *ciphertext,
    uint8_t        tag[16],
    const uint8_t *plaintext,
    size_t         plaintext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12])
{
    /* 1. Generate Poly1305 one-time key: block 0 */
    uint32_t block0[16];
    uint8_t otk[32];
    chacha20_block(block0, key, 0, nonce);
    for (int i = 0; i < 8; i++) {
        store32_le(otk + 4 * i, block0[i]);
    }

    /* 2. Encrypt plaintext with counter starting at 1 */
    chacha20_encrypt(ciphertext, plaintext, plaintext_len, key, nonce, 1);

    /* 3. Compute authentication tag */
    poly1305_compute_tag(tag, aad, aad_len, ciphertext, plaintext_len, otk);

    /* Wipe one-time key */
    memset(otk, 0, sizeof(otk));
    memset(block0, 0, sizeof(block0));

    return 0;
}

/**
@brief Constant-time comparison of two byte buffers.

Compares all @p len bytes regardless of where a difference occurs,
preventing timing side-channels.

@param[in] a   First buffer.
@param[in] b   Second buffer.
@param[in] len Number of bytes to compare.
@return 0 if equal, nonzero if different.
**/
static int ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)diff;
}

int chacha20_poly1305_decrypt(
    uint8_t       *plaintext,
    const uint8_t *ciphertext,
    size_t         ciphertext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  tag[16],
    const uint8_t  key[32],
    const uint8_t  nonce[12])
{
    /* 1. Generate Poly1305 one-time key: block 0 */
    uint32_t block0[16];
    uint8_t otk[32];
    chacha20_block(block0, key, 0, nonce);
    for (int i = 0; i < 8; i++) {
        store32_le(otk + 4 * i, block0[i]);
    }

    /* 2. Compute expected tag over ciphertext */
    uint8_t expected_tag[16];
    poly1305_compute_tag(expected_tag, aad, aad_len,
                         ciphertext, ciphertext_len, otk);

    /* 3. Constant-time tag comparison */
    if (ct_compare(expected_tag, tag, 16) != 0) {
        memset(plaintext, 0, ciphertext_len);
        memset(otk, 0, sizeof(otk));
        memset(block0, 0, sizeof(block0));
        return -1;
    }

    /* 4. Decrypt */
    chacha20_encrypt(plaintext, ciphertext, ciphertext_len, key, nonce, 1);

    memset(otk, 0, sizeof(otk));
    memset(block0, 0, sizeof(block0));

    return 0;
}
