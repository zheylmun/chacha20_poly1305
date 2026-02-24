#include "unity.h"
#include "chacha20_poly1305.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void setUp(void) {}
void tearDown(void) {}

// Test various plaintext and AAD sizes, including boundary conditions.
static const size_t pt_sizes[] = {
    0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 100, 127, 128, 255, 256, 1000, 1023, 1024, 4095,4096, 10000, 65535, 65536, 100000, 1048575, 1048576, 9999999
};
#define NUM_PT_SIZES (sizeof(pt_sizes) / sizeof(pt_sizes[0]))

static const size_t aad_sizes[] = { 0, 1, 15, 16, 17, 127, 128, 129, 255, 256 };
#define NUM_AAD_SIZES (sizeof(aad_sizes) / sizeof(aad_sizes[0]))

#define ITERATIONS 100

static uint8_t *random_buf(size_t len)
{
    if (len == 0) return NULL;
    uint8_t *buf = malloc(len);
    TEST_ASSERT_NOT_NULL_MESSAGE(buf, "malloc failed");
    randombytes_buf(buf, len);
    return buf;
}

/*
 * For each plaintext size, generate 1000 random buffers.
 * Each iteration: random key, nonce, AAD (random length 0-256).
 *   1) Encrypt with ours   -> decrypt with libsodium -> compare
 *   2) Encrypt with libsodium -> decrypt with ours   -> compare
 */
void test_round_trip(void)
{
    char msg[128];

    for (size_t i = 0; i < NUM_PT_SIZES; i++) {
        size_t pt_len = pt_sizes[i];

        for (int iter = 0; iter < ITERATIONS; iter++) {
            size_t aad_len = randombytes_uniform(257);

            snprintf(msg, sizeof(msg),
                     "pt_len=%zu aad_len=%zu iter=%d", pt_len, aad_len, iter);

            uint8_t key[32], nonce[12];
            randombytes_buf(key, sizeof(key));
            randombytes_buf(nonce, sizeof(nonce));

            uint8_t *pt  = random_buf(pt_len);
            uint8_t *aad = random_buf(aad_len);
            uint8_t *ct  = pt_len ? malloc(pt_len) : NULL;
            uint8_t tag[16];
            uint8_t *recovered;

            /* --- Ours -> libsodium --- */
            int ret = chacha20_poly1305_encrypt(
                ct, tag, pt, pt_len, aad, aad_len, key, nonce);
            TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

            recovered = pt_len ? malloc(pt_len) : NULL;
            ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                recovered, NULL,
                ct, pt_len,
                tag,
                aad, aad_len,
                nonce, key);
            TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
            if (pt_len > 0)
                TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(
                    pt, recovered, pt_len, msg);
            free(recovered);

            /* --- libsodium -> ours --- */
            unsigned long long maclen = 16;
            ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                ct, tag, &maclen,
                pt, pt_len,
                aad, aad_len,
                NULL, nonce, key);
            TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

            recovered = pt_len ? malloc(pt_len) : NULL;
            ret = chacha20_poly1305_decrypt(
                recovered, ct, pt_len, aad, aad_len, tag, key, nonce);
            TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
            if (pt_len > 0)
                TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(
                    pt, recovered, pt_len, msg);
            free(recovered);

            free(pt);
            free(aad);
            free(ct);
        }
    }
}

/* Fixed 256-byte plaintext x all AAD sizes: parity + cross-decrypt */
void test_aad_boundary_sweep(void)
{
    const size_t pt_len = 256;
    char msg[128];

    for (size_t j = 0; j < NUM_AAD_SIZES; j++) {
        size_t aad_len = aad_sizes[j];

        snprintf(msg, sizeof(msg),
                 "pt_len=%zu aad_len=%zu", pt_len, aad_len);

        uint8_t key[32], nonce[12];
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));

        uint8_t *pt  = random_buf(pt_len);
        uint8_t *aad = random_buf(aad_len);

        uint8_t *ct_ours   = malloc(pt_len);
        uint8_t *ct_sodium = malloc(pt_len);
        uint8_t tag_ours[16], tag_sodium[16];
        unsigned long long maclen = 16;

        int ret = chacha20_poly1305_encrypt(
            ct_ours, tag_ours, pt, pt_len, aad, aad_len, key, nonce);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

        ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ct_sodium, tag_sodium, &maclen,
            pt, pt_len,
            aad, aad_len,
            NULL, nonce, key);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

        /* Parity */
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(ct_sodium, ct_ours, pt_len, msg);
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(tag_sodium, tag_ours, 16, msg);

        /* Cross-decrypt: ours -> libsodium */
        uint8_t *rec1 = malloc(pt_len);
        ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            rec1, NULL,
            ct_ours, pt_len,
            tag_ours,
            aad, aad_len,
            nonce, key);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(pt, rec1, pt_len, msg);

        /* Cross-decrypt: libsodium -> ours */
        uint8_t *rec2 = malloc(pt_len);
        ret = chacha20_poly1305_decrypt(
            rec2, ct_sodium, pt_len, aad, aad_len, tag_sodium, key, nonce);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(pt, rec2, pt_len, msg);

        free(pt);
        free(aad);
        free(ct_ours);
        free(ct_sodium);
        free(rec1);
        free(rec2);
    }
}

/* Fixed 256-byte AAD x all PT sizes: parity + cross-decrypt */
void test_pt_boundary_sweep(void)
{
    const size_t aad_len = 256;
    char msg[128];

    for (size_t i = 0; i < NUM_PT_SIZES; i++) {
        size_t pt_len = pt_sizes[i];

        snprintf(msg, sizeof(msg),
                 "pt_len=%zu aad_len=%zu", pt_len, aad_len);

        uint8_t key[32], nonce[12];
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));

        uint8_t *pt  = random_buf(pt_len);
        uint8_t *aad = random_buf(aad_len);

        uint8_t *ct_ours   = pt_len ? malloc(pt_len) : NULL;
        uint8_t *ct_sodium = pt_len ? malloc(pt_len) : NULL;
        uint8_t tag_ours[16], tag_sodium[16];
        unsigned long long maclen = 16;

        int ret = chacha20_poly1305_encrypt(
            ct_ours, tag_ours, pt, pt_len, aad, aad_len, key, nonce);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

        ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ct_sodium, tag_sodium, &maclen,
            pt, pt_len,
            aad, aad_len,
            NULL, nonce, key);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);

        /* Parity */
        if (pt_len > 0)
            TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(
                ct_sodium, ct_ours, pt_len, msg);
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(tag_sodium, tag_ours, 16, msg);

        /* Cross-decrypt: ours -> libsodium */
        uint8_t *rec1 = pt_len ? malloc(pt_len) : NULL;
        ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            rec1, NULL,
            ct_ours, pt_len,
            tag_ours,
            aad, aad_len,
            nonce, key);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
        if (pt_len > 0)
            TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(pt, rec1, pt_len, msg);

        /* Cross-decrypt: libsodium -> ours */
        uint8_t *rec2 = pt_len ? malloc(pt_len) : NULL;
        ret = chacha20_poly1305_decrypt(
            rec2, ct_sodium, pt_len, aad, aad_len, tag_sodium, key, nonce);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, msg);
        if (pt_len > 0)
            TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(pt, rec2, pt_len, msg);

        free(pt);
        free(aad);
        free(ct_ours);
        free(ct_sodium);
        free(rec1);
        free(rec2);
    }
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init() failed\n");
        return 1;
    }

    UNITY_BEGIN();
    RUN_TEST(test_round_trip);
    RUN_TEST(test_aad_boundary_sweep);
    RUN_TEST(test_pt_boundary_sweep);
    return UNITY_END();
}
