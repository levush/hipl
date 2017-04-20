/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University.
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

#include "libcore/crypto.h"
#include "libcore/hostid.h"
#include "config.h"
#include "test_suites.h"

#ifdef HAVE_EC_CRYPTO
START_TEST(test_serialize_deserialize_keys)
{
    unsigned int            i, keyrr_len = 0;
    int                     nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY                 *key     = NULL, *key_deserialized = NULL;
    EVP_PKEY               *key_a   = NULL, *key_b = NULL;
    unsigned char          *keyrr;
    struct hip_host_id_priv hostid;

    HIP_DEBUG("Trying to serialize and deserialize some ECDSA keys.\n");

    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        key_a = EVP_PKEY_new();
        key_b = EVP_PKEY_new();
        key   = create_ecdsa_key(nids[i]);
        fail_unless((keyrr_len = ecdsa_to_key_rr(key, &keyrr)) > 0, NULL);
        memcpy(&hostid.key, keyrr, keyrr_len);
        fail_unless((key_deserialized = hip_key_rr_to_ecdsa(&hostid, 1)) != NULL, NULL);
        EVP_PKEY_assign_EC_KEY(key_a, key);
        EVP_PKEY_assign_EC_KEY(key_b, key_deserialized);
        fail_unless(EVP_PKEY_cmp(key_a, key_b) == 1, NULL);
        EVP_PKEY_free(key_a);
        EVP_PKEY_free(key_b);
    }

    HIP_DEBUG("Successfully passed test for serialization and deserialization of ECDSA keys.\n");
}
END_TEST

#endif /* HAVE_EC_CRYPTO */

START_TEST(test_serialize_deserialize_rsa_keys)
{
    unsigned int            i, keyrr_len = 0;
    int                     bits[3] = { 1024, 2048, 3072 };
    RSA                    *key     = NULL, *key_deserialized = NULL;
    EVP_PKEY               *key_a   = NULL, *key_b = NULL;
    unsigned char          *keyrr;
    struct hip_host_id_priv hostid;

    HIP_DEBUG("Trying to serialize and deserialize some RSA keys.\n");

    for (i = 0; i < sizeof(bits) / sizeof(int); i++) {
        key_a = EVP_PKEY_new();
        key_b = EVP_PKEY_new();
        key   = create_rsa_key(bits[i]);
        fail_unless((keyrr_len = rsa_to_dns_key_rr(key, &keyrr)) > 0, NULL);
        memcpy(&hostid.key, keyrr, keyrr_len);
        hostid.hi_length = htons(keyrr_len + sizeof(struct hip_host_id_key_rdata));
        fail_unless((key_deserialized = hip_key_rr_to_rsa(&hostid, 1)) != NULL, NULL);
        EVP_PKEY_assign_RSA(key_a, key);
        EVP_PKEY_assign_RSA(key_b, key_deserialized);
        fail_unless(EVP_PKEY_cmp(key_a, key_b) == 1, NULL);
        EVP_PKEY_free(key_a);
        EVP_PKEY_free(key_b);
    }

    HIP_DEBUG("Successfully passed test for serialization and deserialization of RSA keys.\n");
}
END_TEST

#ifdef HAVE_EC_CRYPTO
START_TEST(test_invalid_serialize_deserialize)
{
    EC_KEY        *key = NULL;
    unsigned char *keyrr;

    HIP_DEBUG("Trying to serialize and deserialize with invalid inputs.\n");

    /* serialize NULL key */
    fail_if(ecdsa_to_key_rr(NULL, &keyrr) > 0 || keyrr != NULL, NULL);

    /* serialize empty key */
    key = EC_KEY_new();
    fail_if(ecdsa_to_key_rr(key, &keyrr) > 0 || keyrr != NULL, NULL);
    EC_KEY_free(key);

    /* serialize valid key to invalid output */
    key = create_ecdsa_key(NID_secp160r1);
    fail_if(ecdsa_to_key_rr(key, NULL) > 0 || keyrr != NULL, NULL);
    EC_KEY_free(key);

    /* deserialize without host id */
    fail_unless(hip_key_rr_to_ecdsa(NULL, 0) == NULL, NULL);
    fail_unless(hip_key_rr_to_ecdsa(NULL, 1) == NULL, NULL);

    HIP_DEBUG("Successfully passed test for serialization and deserialization with invalid inputs.\n");
}
END_TEST

#endif /* HAVE_EC_CRYPTO */

Suite *libcore_hostid(void)
{
    Suite *s = suite_create("libcore/hostid");

    TCase *tc_core = tcase_create("Core");
    /* the default test timeout of 4 seconds is too short,
     * generating keys in scratchbox or on the N900 takes a while */
    tcase_set_timeout(tc_core, 120);

    tcase_add_test(tc_core, test_serialize_deserialize_rsa_keys);
#ifdef HAVE_EC_CRYPTO
    tcase_add_test(tc_core, test_serialize_deserialize_keys);
    tcase_add_test(tc_core, test_invalid_serialize_deserialize);
#endif /* HAVE_EC_CRYPTO */

    suite_add_tcase(s, tc_core);

    return s;
}
