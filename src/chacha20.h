#ifndef CHACHA20_INTERNAL_H
#define CHACHA20_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/* Quarter round operation (exposed for testing). */
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
