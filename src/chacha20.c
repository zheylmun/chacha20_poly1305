#include "chacha20.h"
#include <string.h> // memcpy

/** @brief Load a 32-bit word from 4 bytes in little-endian order. */
static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/** @brief Store a 32-bit word as 4 bytes in little-endian order. */
static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/** @brief Rotate a 32-bit word left by @p n bits. */
static uint32_t rotl32(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

void chacha20_quarter_round(uint32_t *a, uint32_t *b,
                            uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

void chacha20_block(uint32_t out[16],
                    const uint8_t key[32],
                    uint32_t counter,
                    const uint8_t nonce[12])
{
    /* "expand 32-byte k" */
    uint32_t state[16];
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;

    state[4]  = load32_le(key + 0);
    state[5]  = load32_le(key + 4);
    state[6]  = load32_le(key + 8);
    state[7]  = load32_le(key + 12);
    state[8]  = load32_le(key + 16);
    state[9]  = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);

    state[12] = counter;

    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    memcpy(out, state, sizeof(uint32_t) * 16);

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        chacha20_quarter_round(&out[0], &out[4], &out[8],  &out[12]);
        chacha20_quarter_round(&out[1], &out[5], &out[9],  &out[13]);
        chacha20_quarter_round(&out[2], &out[6], &out[10], &out[14]);
        chacha20_quarter_round(&out[3], &out[7], &out[11], &out[15]);
        /* Diagonal rounds */
        chacha20_quarter_round(&out[0], &out[5], &out[10], &out[15]);
        chacha20_quarter_round(&out[1], &out[6], &out[11], &out[12]);
        chacha20_quarter_round(&out[2], &out[7], &out[8],  &out[13]);
        chacha20_quarter_round(&out[3], &out[4], &out[9],  &out[14]);
    }

    for (int i = 0; i < 16; i++) {
        out[i] += state[i];
    }
}

void chacha20_encrypt(uint8_t *output,
                      const uint8_t *input,
                      size_t len,
                      const uint8_t key[32],
                      const uint8_t nonce[12],
                      uint32_t counter)
{
    uint32_t block[16];
    uint8_t keystream[64];

    while (len > 0) {
        chacha20_block(block, key, counter, nonce);

        for (int i = 0; i < 16; i++) {
            store32_le(keystream + 4 * i, block[i]);
        }

        size_t chunk = len < 64 ? len : 64;
        for (size_t i = 0; i < chunk; i++) {
            output[i] = input[i] ^ keystream[i];
        }

        counter++;
        input  += chunk;
        output += chunk;
        len    -= chunk;
    }
}
