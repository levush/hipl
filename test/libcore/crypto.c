/*
 * Copyright (c) 2011-2012 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_EC_CRYPTO
#include <openssl/ecdh.h>
#endif

#include "libcore/crypto.h"
#include "config.h"
#include "test_suites.h"

#ifdef HAVE_EC_CRYPTO

static const int TEST_ECDH_PRIV_A = 0;
static const int TEST_ECDH_PUBX_A = 1;
static const int TEST_ECDH_PUBY_A = 2;
static const int TEST_ECDH_PRIV_B = 3;
static const int TEST_ECDH_PUBX_B = 4;
static const int TEST_ECDH_PUBY_B = 5;
static const int TEST_ECDH_SHARED = 6;

/* An example for testing from RFC5903, section 8.1 */
static unsigned char TEST_ECDH_NIST_P_256[] = {
    0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2,
    0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5, 0x44, 0xE9, 0xAA, 0xB8,
    0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D,
    0x14, 0x33,

    0xDA, 0xD0, 0xB6, 0x53, 0x94, 0x22, 0x1C, 0xF9, 0xB0, 0x51,
    0xE1, 0xFE, 0xCA, 0x57, 0x87, 0xD0, 0x98, 0xDF, 0xE6, 0x37,
    0xFC, 0x90, 0xB9, 0xEF, 0x94, 0x5D, 0x0C, 0x37, 0x72, 0x58,
    0x11, 0x80,

    0x52, 0x71, 0xA0, 0x46, 0x1C, 0xDB, 0x82, 0x52, 0xD6, 0x1F,
    0x1C, 0x45, 0x6F, 0xA3, 0xE5, 0x9A, 0xB1, 0xF4, 0x5B, 0x33,
    0xAC, 0xCF, 0x5F, 0x58, 0x38, 0x9E, 0x05, 0x77, 0xB8, 0x99,
    0x0B, 0xB3,

    0xC6, 0xEF, 0x9C, 0x5D, 0x78, 0xAE, 0x01, 0x2A, 0x01, 0x11,
    0x64, 0xAC, 0xB3, 0x97, 0xCE, 0x20, 0x88, 0x68, 0x5D, 0x8F,
    0x06, 0xBF, 0x9B, 0xE0, 0xB2, 0x83, 0xAB, 0x46, 0x47, 0x6B,
    0xEE, 0x53,

    0xD1, 0x2D, 0xFB, 0x52, 0x89, 0xC8, 0xD4, 0xF8, 0x12, 0x08,
    0xB7, 0x02, 0x70, 0x39, 0x8C, 0x34, 0x22, 0x96, 0x97, 0x0A,
    0x0B, 0xCC, 0xB7, 0x4C, 0x73, 0x6F, 0xC7, 0x55, 0x44, 0x94,
    0xBF, 0x63,

    0x56, 0xFB, 0xF3, 0xCA, 0x36, 0x6C, 0xC2, 0x3E, 0x81, 0x57,
    0x85, 0x4C, 0x13, 0xC5, 0x8D, 0x6A, 0xAC, 0x23, 0xF0, 0x46,
    0xAD, 0xA3, 0x0F, 0x83, 0x53, 0xE7, 0x4F, 0x33, 0x03, 0x98,
    0x72, 0xAB,

    0xD6, 0x84, 0x0F, 0x6B, 0x42, 0xF6, 0xED, 0xAF, 0xD1, 0x31,
    0x16, 0xE0, 0xE1, 0x25, 0x65, 0x20, 0x2F, 0xEF, 0x8E, 0x9E,
    0xCE, 0x7D, 0xCE, 0x03, 0x81, 0x24, 0x64, 0xD0, 0x4B, 0x94,
    0x42, 0xDE,
};

/* An example for testing from RFC5903, section 8.2 */
static unsigned char TEST_ECDH_NIST_P_384[] = {
    0x09, 0x9F, 0x3C, 0x70, 0x34, 0xD4, 0xA2, 0xC6, 0x99, 0x88,
    0x4D, 0x73, 0xA3, 0x75, 0xA6, 0x7F, 0x76, 0x24, 0xEF, 0x7C,
    0x6B, 0x3C, 0x0F, 0x16, 0x06, 0x47, 0xB6, 0x74, 0x14, 0xDC,
    0xE6, 0x55, 0xE3, 0x5B, 0x53, 0x80, 0x41, 0xE6, 0x49, 0xEE,
    0x3F, 0xAE, 0xF8, 0x96, 0x78, 0x3A, 0xB1, 0x94,

    0x66, 0x78, 0x42, 0xD7, 0xD1, 0x80, 0xAC, 0x2C, 0xDE, 0x6F,
    0x74, 0xF3, 0x75, 0x51, 0xF5, 0x57, 0x55, 0xC7, 0x64, 0x5C,
    0x20, 0xEF, 0x73, 0xE3, 0x16, 0x34, 0xFE, 0x72, 0xB4, 0xC5,
    0x5E, 0xE6, 0xDE, 0x3A, 0xC8, 0x08, 0xAC, 0xB4, 0xBD, 0xB4,
    0xC8, 0x87, 0x32, 0xAE, 0xE9, 0x5F, 0x41, 0xAA,

    0x94, 0x82, 0xED, 0x1F, 0xC0, 0xEE, 0xB9, 0xCA, 0xFC, 0x49,
    0x84, 0x62, 0x5C, 0xCF, 0xC2, 0x3F, 0x65, 0x03, 0x21, 0x49,
    0xE0, 0xE1, 0x44, 0xAD, 0xA0, 0x24, 0x18, 0x15, 0x35, 0xA0,
    0xF3, 0x8E, 0xEB, 0x9F, 0xCF, 0xF3, 0xC2, 0xC9, 0x47, 0xDA,
    0xE6, 0x9B, 0x4C, 0x63, 0x45, 0x73, 0xA8, 0x1C,

    0x41, 0xCB, 0x07, 0x79, 0xB4, 0xBD, 0xB8, 0x5D, 0x47, 0x84,
    0x67, 0x25, 0xFB, 0xEC, 0x3C, 0x94, 0x30, 0xFA, 0xB4, 0x6C,
    0xC8, 0xDC, 0x50, 0x60, 0x85, 0x5C, 0xC9, 0xBD, 0xA0, 0xAA,
    0x29, 0x42, 0xE0, 0x30, 0x83, 0x12, 0x91, 0x6B, 0x8E, 0xD2,
    0x96, 0x0E, 0x4B, 0xD5, 0x5A, 0x74, 0x48, 0xFC,

    0xE5, 0x58, 0xDB, 0xEF, 0x53, 0xEE, 0xCD, 0xE3, 0xD3, 0xFC,
    0xCF, 0xC1, 0xAE, 0xA0, 0x8A, 0x89, 0xA9, 0x87, 0x47, 0x5D,
    0x12, 0xFD, 0x95, 0x0D, 0x83, 0xCF, 0xA4, 0x17, 0x32, 0xBC,
    0x50, 0x9D, 0x0D, 0x1A, 0xC4, 0x3A, 0x03, 0x36, 0xDE, 0xF9,
    0x6F, 0xDA, 0x41, 0xD0, 0x77, 0x4A, 0x35, 0x71,

    0xDC, 0xFB, 0xEC, 0x7A, 0xAC, 0xF3, 0x19, 0x64, 0x72, 0x16,
    0x9E, 0x83, 0x84, 0x30, 0x36, 0x7F, 0x66, 0xEE, 0xBE, 0x3C,
    0x6E, 0x70, 0xC4, 0x16, 0xDD, 0x5F, 0x0C, 0x68, 0x75, 0x9D,
    0xD1, 0xFF, 0xF8, 0x3F, 0xA4, 0x01, 0x42, 0x20, 0x9D, 0xFF,
    0x5E, 0xAA, 0xD9, 0x6D, 0xB9, 0xE6, 0x38, 0x6C,

    0x11, 0x18, 0x73, 0x31, 0xC2, 0x79, 0x96, 0x2D, 0x93, 0xD6,
    0x04, 0x24, 0x3F, 0xD5, 0x92, 0xCB, 0x9D, 0x0A, 0x92, 0x6F,
    0x42, 0x2E, 0x47, 0x18, 0x75, 0x21, 0x28, 0x7E, 0x71, 0x56,
    0xC5, 0xC4, 0xD6, 0x03, 0x13, 0x55, 0x69, 0xB9, 0xE9, 0xD0,
    0x9C, 0xF5, 0xD4, 0xA2, 0x70, 0xF5, 0x97, 0x46
};

/* An example for testing from RFC5903, section 8.3 */
static unsigned char TEST_ECDH_NIST_P_521[] = {
    0x00, 0x37, 0xAD, 0xE9, 0x31, 0x9A, 0x89, 0xF4, 0xDA, 0xBD,
    0xB3, 0xEF, 0x41, 0x1A, 0xAC, 0xCC, 0xA5, 0x12, 0x3C, 0x61,
    0xAC, 0xAB, 0x57, 0xB5, 0x39, 0x3D, 0xCE, 0x47, 0x60, 0x81,
    0x72, 0xA0, 0x95, 0xAA, 0x85, 0xA3, 0x0F, 0xE1, 0xC2, 0x95,
    0x2C, 0x67, 0x71, 0xD9, 0x37, 0xBA, 0x97, 0x77, 0xF5, 0x95,
    0x7B, 0x26, 0x39, 0xBA, 0xB0, 0x72, 0x46, 0x2F, 0x68, 0xC2,
    0x7A, 0x57, 0x38, 0x2D, 0x4A, 0x52,

    0x00, 0x15, 0x41, 0x7E, 0x84, 0xDB, 0xF2, 0x8C, 0x0A, 0xD3,
    0xC2, 0x78, 0x71, 0x33, 0x49, 0xDC, 0x7D, 0xF1, 0x53, 0xC8,
    0x97, 0xA1, 0x89, 0x1B, 0xD9, 0x8B, 0xAB, 0x43, 0x57, 0xC9,
    0xEC, 0xBE, 0xE1, 0xE3, 0xBF, 0x42, 0xE0, 0x0B, 0x8E, 0x38,
    0x0A, 0xEA, 0xE5, 0x7C, 0x2D, 0x10, 0x75, 0x64, 0x94, 0x18,
    0x85, 0x94, 0x2A, 0xF5, 0xA7, 0xF4, 0x60, 0x17, 0x23, 0xC4,
    0x19, 0x5D, 0x17, 0x6C, 0xED, 0x3E,

    0x01, 0x7C, 0xAE, 0x20, 0xB6, 0x64, 0x1D, 0x2E, 0xEB, 0x69,
    0x57, 0x86, 0xD8, 0xC9, 0x46, 0x14, 0x62, 0x39, 0xD0, 0x99,
    0xE1, 0x8E, 0x1D, 0x5A, 0x51, 0x4C, 0x73, 0x9D, 0x7C, 0xB4,
    0xA1, 0x0A, 0xD8, 0xA7, 0x88, 0x01, 0x5A, 0xC4, 0x05, 0xD7,
    0x79, 0x9D, 0xC7, 0x5E, 0x7B, 0x7D, 0x5B, 0x6C, 0xF2, 0x26,
    0x1A, 0x6A, 0x7F, 0x15, 0x07, 0x43, 0x8B, 0xF0, 0x1B, 0xEB,
    0x6C, 0xA3, 0x92, 0x6F, 0x95, 0x82,

    0x01, 0x45, 0xBA, 0x99, 0xA8, 0x47, 0xAF, 0x43, 0x79, 0x3F,
    0xDD, 0x0E, 0x87, 0x2E, 0x7C, 0xDF, 0xA1, 0x6B, 0xE3, 0x0F,
    0xDC, 0x78, 0x0F, 0x97, 0xBC, 0xCC, 0x3F, 0x07, 0x83, 0x80,
    0x20, 0x1E, 0x9C, 0x67, 0x7D, 0x60, 0x0B, 0x34, 0x37, 0x57,
    0xA3, 0xBD, 0xBF, 0x2A, 0x31, 0x63, 0xE4, 0xC2, 0xF8, 0x69,
    0xCC, 0xA7, 0x45, 0x8A, 0xA4, 0xA4, 0xEF, 0xFC, 0x31, 0x1F,
    0x5C, 0xB1, 0x51, 0x68, 0x5E, 0xB9,

    0x00, 0xD0, 0xB3, 0x97, 0x5A, 0xC4, 0xB7, 0x99, 0xF5, 0xBE,
    0xA1, 0x6D, 0x5E, 0x13, 0xE9, 0xAF, 0x97, 0x1D, 0x5E, 0x9B,
    0x98, 0x4C, 0x9F, 0x39, 0x72, 0x8B, 0x5E, 0x57, 0x39, 0x73,
    0x5A, 0x21, 0x9B, 0x97, 0xC3, 0x56, 0x43, 0x6A, 0xDC, 0x6E,
    0x95, 0xBB, 0x03, 0x52, 0xF6, 0xBE, 0x64, 0xA6, 0xC2, 0x91,
    0x2D, 0x4E, 0xF2, 0xD0, 0x43, 0x3C, 0xED, 0x2B, 0x61, 0x71,
    0x64, 0x00, 0x12, 0xD9, 0x46, 0x0F,

    0x01, 0x5C, 0x68, 0x22, 0x63, 0x83, 0x95, 0x6E, 0x3B, 0xD0,
    0x66, 0xE7, 0x97, 0xB6, 0x23, 0xC2, 0x7C, 0xE0, 0xEA, 0xC2,
    0xF5, 0x51, 0xA1, 0x0C, 0x2C, 0x72, 0x4D, 0x98, 0x52, 0x07,
    0x7B, 0x87, 0x22, 0x0B, 0x65, 0x36, 0xC5, 0xC4, 0x08, 0xA1,
    0xD2, 0xAE, 0xBB, 0x8E, 0x86, 0xD6, 0x78, 0xAE, 0x49, 0xCB,
    0x57, 0x09, 0x1F, 0x47, 0x32, 0x29, 0x65, 0x79, 0xAB, 0x44,
    0xFC, 0xD1, 0x7F, 0x0F, 0xC5, 0x6A,

    0x01, 0x14, 0x4C, 0x7D, 0x79, 0xAE, 0x69, 0x56, 0xBC, 0x8E,
    0xDB, 0x8E, 0x7C, 0x78, 0x7C, 0x45, 0x21, 0xCB, 0x08, 0x6F,
    0xA6, 0x44, 0x07, 0xF9, 0x78, 0x94, 0xE5, 0xE6, 0xB2, 0xD7,
    0x9B, 0x04, 0xD1, 0x42, 0x7E, 0x73, 0xCA, 0x4B, 0xAA, 0x24,
    0x0A, 0x34, 0x78, 0x68, 0x59, 0x81, 0x0C, 0x06, 0xB3, 0xC7,
    0x15, 0xA3, 0xA8, 0xCC, 0x31, 0x51, 0xF2, 0xBE, 0xE4, 0x17,
    0x99, 0x6D, 0x19, 0xF3, 0xDD, 0xEA,
};

enum ecdh_data { SIDE_A_KEY, SIDE_B_KEY, SHARED_SECRET };
static void *generate_test_ecdh_data(const int group_id,
                                     enum ecdh_data request_data)
{
    uint8_t        *data_set;
    int             size;
    EC_KEY         *key;
    const EC_GROUP *group;
    const BIGNUM   *k_priv = NULL;
    const BIGNUM   *k_pubx = NULL;
    const BIGNUM   *k_puby = NULL;
    EC_POINT       *k_pub  = NULL;

    switch (group_id) {
    case HIP_DH_NIST_P_256:
        data_set = TEST_ECDH_NIST_P_256;
        break;
    case HIP_DH_NIST_P_384:
        data_set = TEST_ECDH_NIST_P_384;
        break;
    case HIP_DH_NIST_P_521:
        data_set = TEST_ECDH_NIST_P_521;
        break;
    default:
        return NULL;
    }

    size = hip_get_dh_size(group_id) / 2;

    switch (request_data) {
    case SIDE_A_KEY:
        key    = hip_generate_ecdh_key(group_id);
        group  = EC_KEY_get0_group(key);
        k_priv = BN_bin2bn(data_set + size * TEST_ECDH_PRIV_A, size, NULL);
        k_pubx = BN_bin2bn(data_set + size * TEST_ECDH_PUBX_A, size, NULL);
        k_puby = BN_bin2bn(data_set + size * TEST_ECDH_PUBY_A, size, NULL);
        k_pub  = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, k_pub, k_pubx, k_puby, NULL);
        EC_KEY_set_public_key(key, k_pub);
        EC_KEY_set_private_key(key, k_priv);
        return key;
    case SIDE_B_KEY:
        key    = hip_generate_ecdh_key(group_id);
        group  = EC_KEY_get0_group(key);
        k_priv = BN_bin2bn(data_set + size * TEST_ECDH_PRIV_B, size, NULL);
        k_pubx = BN_bin2bn(data_set + size * TEST_ECDH_PUBX_B, size, NULL);
        k_puby = BN_bin2bn(data_set + size * TEST_ECDH_PUBY_B, size, NULL);
        k_pub  = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, k_pub, k_pubx, k_puby, NULL);
        EC_KEY_set_public_key(key, k_pub);
        EC_KEY_set_private_key(key, k_priv);
        return key;
    case SHARED_SECRET:
        return data_set + size * TEST_ECDH_SHARED;
    }

    return NULL;
}

START_TEST(test_create_ecdsa_key_invalid_id)
{
    HIP_DEBUG("Trying to create some invalid ECDSA keys.\n");

    fail_unless(create_ecdsa_key(-1)    == NULL, NULL);
    fail_unless(create_ecdsa_key(0)     == NULL, NULL);
    fail_unless(create_ecdsa_key(1)     == NULL, NULL);
    fail_unless(create_ecdsa_key(11111) == NULL, NULL);

    HIP_DEBUG("Successfully passed create test for invalid ECDSA keys.\n");
}
END_TEST

START_TEST(test_create_ecdsa_key)
{
    unsigned int i;
    int          nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY      *keys[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Trying to create some valid ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        fail_unless((keys[i] = create_ecdsa_key(nids[i])) != NULL, NULL);
    }

    /* Creation worked, now check keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        fail_unless(EC_KEY_check_key(keys[i]), NULL);
        EC_KEY_free(keys[i]);
    }

    HIP_DEBUG("Successfully passed create test for valid ECDSA keys.\n");
}
END_TEST

START_TEST(test_create_different_ecdsa_keys)
{
    unsigned int i;
    int          nids[2] = { NID_X9_62_prime256v1, NID_X9_62_prime256v1 };
    EC_KEY      *ec_keys[sizeof(nids) / sizeof(int)];
    EVP_PKEY    *keys[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Checking uniqueness of ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        ec_keys[i] = create_ecdsa_key(nids[i]);
        keys[i]    = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(keys[i], ec_keys[i]);
    }

    /* Keys should be statistically unique
     * todo: take more samples */
    fail_unless(EVP_PKEY_cmp(keys[0], keys[1]) == 0, NULL);

    HIP_DEBUG("Successfully passed test for uniqueness of ECDSA keys.\n");
}
END_TEST

START_TEST(test_save_invalid_ecdsa_key)
{
    EC_KEY *eckey = NULL;
    HIP_DEBUG("Trying some invalid save operations.\n");

    fail_unless(save_ecdsa_private_key("tmp_file", NULL) != 0, NULL);

    eckey = create_ecdsa_key(NID_X9_62_prime256v1);
    fail_unless(save_ecdsa_private_key(NULL, eckey) != 0, NULL);
    EC_KEY_free(eckey);

    eckey = EC_KEY_new();
    fail_unless(save_ecdsa_private_key("tmp_file", eckey) != 0, NULL);
    EC_KEY_free(eckey);

    fail_unless(save_ecdsa_private_key(NULL, NULL) != 0, NULL);

    HIP_DEBUG("Successfully passed test for invalid save operations.\n");
}
END_TEST

START_TEST(test_load_save_ecdsa_key)
{
    unsigned int i;
    int          nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EVP_PKEY    *keys[sizeof(nids) / sizeof(int)];
    EVP_PKEY    *keys_loaded[sizeof(nids) / sizeof(int)];
    EC_KEY      *eckeys[sizeof(nids) / sizeof(int)];
    EC_KEY      *eckeys_loaded[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Trying to save and load some ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        keys[i]        = EVP_PKEY_new();
        keys_loaded[i] = EVP_PKEY_new();
        eckeys[i]      = create_ecdsa_key(nids[i]);
        EVP_PKEY_assign_EC_KEY(keys[i], eckeys[i]);
    }

    /* Save and reload keys */
    save_ecdsa_private_key("tmp_key1", EVP_PKEY_get1_EC_KEY(keys[0]));
    save_ecdsa_private_key("tmp_key2", EVP_PKEY_get1_EC_KEY(keys[1]));
    save_ecdsa_private_key("tmp_key3", EVP_PKEY_get1_EC_KEY(keys[2]));
    load_ecdsa_private_key("tmp_key1", &eckeys_loaded[0]);
    load_ecdsa_private_key("tmp_key2", &eckeys_loaded[1]);
    load_ecdsa_private_key("tmp_key3", &eckeys_loaded[2]);

    /* Now compare keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        EVP_PKEY_assign_EC_KEY(keys_loaded[i], eckeys_loaded[i]);
        fail_unless(EVP_PKEY_cmp(keys[i], keys_loaded[i]) == 1, NULL);
        // Note: EC_KEYS will be freed when the parent EVP_PKEY is freed.
        EVP_PKEY_free(keys[i]);
        EVP_PKEY_free(keys_loaded[i]);
    }

    unlink("tmp_key2");
    unlink("tmp_key3");
    unlink("tmp_key2.pub");
    unlink("tmp_key3.pub");

    HIP_DEBUG("Successfully passed load/save test for ECDSA keys.\n");
}
END_TEST

START_TEST(test_load_invalid_ecdsa_key)
{
    EC_KEY *eckey = NULL;
    int     err;

    HIP_DEBUG("Trying some invalid load operations.\n");

    err = load_ecdsa_private_key("non_existing", &eckey);
    fail_unless(err != 0 && eckey == NULL, NULL);

    err = load_ecdsa_private_key(NULL, &eckey);
    fail_unless(err != 0 && eckey == NULL, NULL);

    err = load_ecdsa_private_key("/tmp/tmp_key1", NULL);
    unlink("tmp_key1");
    unlink("tmp_key1.pub");
    fail_unless(err != 0, NULL);

    err = load_ecdsa_private_key(NULL, NULL);
    fail_unless(err != 0, NULL);

    HIP_DEBUG("Successfully passed test for invalid load operations.\n");
}
END_TEST

START_TEST(test_impl_ecdsa_sign_verify)
{
    unsigned int         i;
    const unsigned char *digest    = (const unsigned char *) "ABCD1ABCD2ABCD3ABCD4ABCD5";
    unsigned char       *signature = NULL;
    int                  nids[3]   = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY              *key       = NULL;

    HIP_DEBUG("Trying to some lowlevel sign, verify operations.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        key       = create_ecdsa_key(nids[i]);
        signature = malloc(ECDSA_size(key));
        fail_unless(impl_ecdsa_sign(digest, key, signature) == 0, NULL);
        fail_unless(impl_ecdsa_verify(digest, key, signature) == 0, NULL);
        free(signature);
        EC_KEY_free(key);
    }

    HIP_DEBUG("Successfully passed test on lowlevel sign, verify operations.\n");
}
END_TEST

START_TEST(test_invalid_impl_ecdsa_sign_verify)
{
    const unsigned char *digest     = (const unsigned char *) "ABCD1ABCD2ABCD3ABCD4ABCD5";
    const unsigned char *mod_digest = (const unsigned char *) "BBCD1ABCD2ABCD3ABCD4ABCD5";
    unsigned char       *signature  = NULL;
    EC_KEY              *key        = NULL;

    HIP_DEBUG("Trying to some lowlevel sign, verify operations with invalid inputs.\n");

    key       = create_ecdsa_key(NID_secp160r1);
    signature = malloc(ECDSA_size(key));

    /* NULL inputs to sign */
    fail_unless(impl_ecdsa_sign(NULL, key, signature) != 0, NULL);
    fail_unless(impl_ecdsa_sign(digest, NULL, signature) != 0, NULL);
    fail_unless(impl_ecdsa_sign(digest, key, NULL) != 0, NULL);

    /* NULL inputs to verify */
    impl_ecdsa_sign(digest, key, signature);
    fail_unless(impl_ecdsa_verify(NULL, key, signature) != 0, NULL);
    fail_unless(impl_ecdsa_verify(digest, NULL, signature) != 0, NULL);
    fail_unless(impl_ecdsa_verify(digest, key, NULL) != 0, NULL);

    /* Modified signature, digest */
    fail_unless(impl_ecdsa_verify(mod_digest, key, signature) != 0, NULL);
    signature[0] += 1;
    fail_unless(impl_ecdsa_verify(digest, key, signature) != 0, NULL);

    free(signature);
    EC_KEY_free(key);

    HIP_DEBUG("Successfully passed test on lowlevel sign, verify operations with invalid inputs.\n");
}
END_TEST

#define TEST_ECDH_GROUP_SIZE 3
static int TEST_ECDH_GROUPS[TEST_ECDH_GROUP_SIZE] = { HIP_DH_NIST_P_256,
                                                      HIP_DH_NIST_P_384,
                                                      HIP_DH_NIST_P_521 };

START_TEST(test_generate_ecdh_key_invalid_group_id)
{
    fail_unless(hip_generate_ecdh_key(0) == NULL);
    fail_unless(hip_generate_ecdh_key(-1) == NULL);
    fail_unless(hip_generate_ecdh_key(HIP_MAX_DH_GROUP_ID) == NULL);
}
END_TEST

START_TEST(test_generate_ecdh_key_valid_group_id)
{
    EC_KEY *key;
    int     i;

    for (i = 0; i < TEST_ECDH_GROUP_SIZE; i++) {
        key = hip_generate_ecdh_key(TEST_ECDH_GROUPS[i]);
        fail_if(key == NULL || EC_KEY_check_key(key) == 0);
    }
}
END_TEST

START_TEST(test_ecdh_generate_2_keys_and_share_secret)
{
    EC_KEY *key1;
    EC_KEY *key2;
    int     out1, out2;
    int     len1, len2;
    int     i;
    int     group_id;
    int     pubkey_size;

    for (i = 0; i < TEST_ECDH_GROUP_SIZE; i++) {
        group_id    = TEST_ECDH_GROUPS[i];
        pubkey_size = hip_get_dh_size(group_id);
        fail_if(pubkey_size <= 0);

        key1 = hip_generate_ecdh_key(group_id);
        key2 = hip_generate_ecdh_key(group_id);
        fail_if(key1 == NULL || key2 == NULL);

        const EC_POINT *k1pub = EC_KEY_get0_public_key(key1);
        const EC_POINT *k2pub = EC_KEY_get0_public_key(key2);

        len1 = len2 = pubkey_size / 2;
        unsigned char share1[len1];
        unsigned char share2[len2];

        out1 = ECDH_compute_key(share1, len1, k2pub, key1, NULL);
        out2 = ECDH_compute_key(share2, len2, k1pub, key2, NULL);
        fail_if(out1 <= 0 || out2 <= 0);
        fail_if(out1 != len1 && out2 != len2);
        fail_if(memcmp(share1, share2, len1) != 0);
    }
}
END_TEST

START_TEST(test_ecdh_encode_publickey)
{
    int i, group_id, key_size;

    for (i = 0; i < TEST_ECDH_GROUP_SIZE; i++) {
        group_id = TEST_ECDH_GROUPS[i];
        key_size = hip_get_dh_size(group_id);
        uint8_t out[key_size];
        EC_KEY *key = hip_generate_ecdh_key(group_id);
        fail_if(hip_encode_ecdh_publickey(key, out, key_size) != key_size);
    }
}
END_TEST

START_TEST(test_ecdh_gen_shared_key)
{
    int i, group_id, size, res;

    for (i = 0; i < TEST_ECDH_GROUP_SIZE; i++) {
        group_id = TEST_ECDH_GROUPS[i];
        size     = hip_get_dh_size(group_id) / 2;
        uint8_t pub[size * 2];
        uint8_t out[size];
        EC_KEY *a      = generate_test_ecdh_data(group_id, SIDE_A_KEY);
        EC_KEY *b      = generate_test_ecdh_data(group_id, SIDE_B_KEY);
        void   *secret = generate_test_ecdh_data(group_id, SHARED_SECRET);
        fail_if(a == NULL || b == NULL || secret == NULL);
        fail_if(EC_KEY_check_key(a) == 0 || EC_KEY_check_key(b) == 0);

        hip_encode_ecdh_publickey(b, pub, size * 2);
        res = hip_gen_ecdh_shared_key(a, pub, pub + size, size, out, size);
        fail_if(res != size);
        fail_if(memcmp(secret, out, size) != 0);

        hip_encode_ecdh_publickey(a, pub, size * 2);
        res = hip_gen_ecdh_shared_key(b, pub, pub + size, size, out, size);
        fail_if(res != size);
        fail_if(memcmp(secret, out, size) != 0);
    }
}
END_TEST

Suite *libcore_crypto(void)
{
    Suite *s = suite_create("libcore/crypto");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_create_ecdsa_key_invalid_id);
    tcase_add_test(tc_core, test_create_ecdsa_key);
    tcase_add_test(tc_core, test_create_different_ecdsa_keys);
    tcase_add_test(tc_core, test_load_save_ecdsa_key);
    tcase_add_test(tc_core, test_save_invalid_ecdsa_key);
    tcase_add_test(tc_core, test_load_invalid_ecdsa_key);
    tcase_add_test(tc_core, test_impl_ecdsa_sign_verify);
    tcase_add_test(tc_core, test_invalid_impl_ecdsa_sign_verify);
    tcase_add_test(tc_core, test_generate_ecdh_key_invalid_group_id);
    tcase_add_test(tc_core, test_generate_ecdh_key_valid_group_id);
    tcase_add_test(tc_core, test_ecdh_generate_2_keys_and_share_secret);
    tcase_add_test(tc_core, test_ecdh_encode_publickey);
    tcase_add_test(tc_core, test_ecdh_gen_shared_key);

    suite_add_tcase(s, tc_core);

    return s;
}

#endif /* HAVE_EC_CRYPTO */
