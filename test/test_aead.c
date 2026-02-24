#include "unity.h"
#include "chacha20_poly1305.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Shared test vector data from RFC 7539 Section 2.8.2 */
static const uint8_t aead_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const uint8_t aead_nonce[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};

static const uint8_t aead_aad[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};

static const uint8_t aead_expected_ct[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
    0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
    0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
    0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
    0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
    0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};

static const uint8_t aead_expected_tag[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

/* RFC 7539 Section 2.8.2: AEAD Encrypt */
void test_aead_encrypt(void)
{
    const char *pt_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    const uint8_t *plaintext = (const uint8_t *)pt_str;
    size_t pt_len = strlen(pt_str);

    TEST_ASSERT_EQUAL(114, pt_len);

    uint8_t ciphertext[114];
    uint8_t tag[16];

    int ret = chacha20_poly1305_encrypt(
        ciphertext, tag,
        plaintext, pt_len,
        aead_aad, sizeof(aead_aad),
        aead_key, aead_nonce);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(aead_expected_ct, ciphertext, 114);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(aead_expected_tag, tag, 16);
}

/* RFC 7539 Section 2.8.2: AEAD Decrypt */
void test_aead_decrypt(void)
{
    uint8_t plaintext[114];

    int ret = chacha20_poly1305_decrypt(
        plaintext,
        aead_expected_ct, 114,
        aead_aad, sizeof(aead_aad),
        aead_expected_tag,
        aead_key, aead_nonce);

    TEST_ASSERT_EQUAL(0, ret);

    const char *expected_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";

    TEST_ASSERT_EQUAL_HEX8_ARRAY(
        (const uint8_t *)expected_str, plaintext, 114);
}

/* Tag mismatch: corrupt tag -> nonzero return, zeroed output */
void test_aead_decrypt_tag_mismatch(void)
{
    uint8_t bad_tag[16];
    memcpy(bad_tag, aead_expected_tag, 16);
    bad_tag[0] ^= 0x01; /* flip one bit */

    uint8_t plaintext[114];
    memset(plaintext, 0xff, sizeof(plaintext));

    int ret = chacha20_poly1305_decrypt(
        plaintext,
        aead_expected_ct, 114,
        aead_aad, sizeof(aead_aad),
        bad_tag,
        aead_key, aead_nonce);

    TEST_ASSERT_NOT_EQUAL(0, ret);

    /* Output must be zeroed */
    uint8_t zeros[114];
    memset(zeros, 0, sizeof(zeros));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zeros, plaintext, 114);
}

/* Empty plaintext: AAD-only authentication */
void test_aead_empty_plaintext(void)
{
    uint8_t tag[16];

    int ret = chacha20_poly1305_encrypt(
        NULL, tag,
        NULL, 0,
        aead_aad, sizeof(aead_aad),
        aead_key, aead_nonce);
    TEST_ASSERT_EQUAL(0, ret);

    /* Decrypt with the tag should succeed */
    int ret2 = chacha20_poly1305_decrypt(
        NULL,
        NULL, 0,
        aead_aad, sizeof(aead_aad),
        tag,
        aead_key, aead_nonce);
    TEST_ASSERT_EQUAL(0, ret2);
}

/* Empty AAD */
void test_aead_empty_aad(void)
{
    const char *pt_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    const uint8_t *plaintext = (const uint8_t *)pt_str;
    size_t pt_len = strlen(pt_str);

    uint8_t ciphertext[114];
    uint8_t tag[16];

    int ret = chacha20_poly1305_encrypt(
        ciphertext, tag,
        plaintext, pt_len,
        NULL, 0,
        aead_key, aead_nonce);
    TEST_ASSERT_EQUAL(0, ret);

    /* Decrypt should succeed and recover plaintext */
    uint8_t recovered[114];
    int ret2 = chacha20_poly1305_decrypt(
        recovered,
        ciphertext, pt_len,
        NULL, 0,
        tag,
        aead_key, aead_nonce);
    TEST_ASSERT_EQUAL(0, ret2);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext, recovered, pt_len);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aead_encrypt);
    RUN_TEST(test_aead_decrypt);
    RUN_TEST(test_aead_decrypt_tag_mismatch);
    RUN_TEST(test_aead_empty_plaintext);
    RUN_TEST(test_aead_empty_aad);
    return UNITY_END();
}
