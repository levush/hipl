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

#include "libcore/cert.h"
#include "libcore/crypto.h"
#include "libcore/ife.h"
#include "libcore/protodefs.h"
#include "config.h"
#include "test_suites.h"

#define TEST_CERT HIPL_SOURCEDIR "/test/libcore/test_cert.pem"
#define TEST_KEY  HIPL_SOURCEDIR "/test/libcore/test_key.pem"

START_TEST(test_cert_load_x509_certificate)
{
    X509 *cert = NULL;

    HIP_DEBUG("Test loading of X509 certificates.\n");

    fail_unless((cert = cert_load_x509_certificate(TEST_CERT,
                                                   ENCODING_FORMAT_PEM)) != NULL,
                NULL);
    X509_free(cert);
    fail_unless((cert = cert_load_x509_certificate("non_existing_cert.pem",
                                                   ENCODING_FORMAT_PEM)) == NULL,
                NULL);
    X509_free(cert);
    fail_unless((cert = cert_load_x509_certificate(NULL,
                                                   ENCODING_FORMAT_PEM)) == NULL,
                NULL);
    X509_free(cert);

    HIP_DEBUG("Successfully passed tests for loading X509 certificates.\n");
}
END_TEST

START_TEST(test_cert_DER_encoding)
{
    int            len          = 0;
    X509          *cert         = NULL;
    X509          *cert_decoded = NULL;
    unsigned char *buf          = NULL;

    HIP_DEBUG("Test DER en/decoding of X509 certificates.\n");

    fail_unless((cert = cert_load_x509_certificate(TEST_CERT,
                                                   ENCODING_FORMAT_PEM)) != NULL,
                NULL);
    fail_unless((len = cert_X509_to_DER(cert, &buf)) > 0, NULL);
    fail_unless((cert_decoded = cert_DER_to_X509(buf, len)) != NULL, NULL);
    fail_unless(X509_cmp(cert, cert_decoded) == 0, NULL);
    X509_free(cert_decoded);

    fail_unless((len = cert_X509_to_DER(NULL, &buf)) < 0, NULL);
    fail_unless((len = cert_X509_to_DER(cert, NULL)) < 0, NULL);
    fail_unless((len = cert_X509_to_DER(NULL, NULL)) < 0, NULL);

    fail_unless((cert_decoded = cert_DER_to_X509(NULL, len)) == NULL, NULL);
    fail_unless((cert_decoded = cert_DER_to_X509(buf, len - 1)) == NULL, NULL);
    fail_unless((cert_decoded = cert_DER_to_X509(buf, len + 1)) == NULL, NULL);
    fail_unless((cert_decoded = cert_DER_to_X509(buf, 0)) == NULL, NULL);

    X509_free(cert);
    X509_free(cert_decoded);
    free(buf);

    HIP_DEBUG("Successfully passed tests for DER en/decoding of X509 certificates.\n");
}

END_TEST

START_TEST(test_cert_match_public_key)
{
    int       err  = 0;
    RSA      *rsa  = NULL;
    X509     *cert = NULL;
    EVP_PKEY *pkey = NULL;

    HIP_DEBUG("Test matching of public keys.\n");

    fail_unless((err = load_rsa_private_key(TEST_KEY, &rsa)) == 0, NULL);
    fail_unless((cert = cert_load_x509_certificate(TEST_CERT,
                                                   ENCODING_FORMAT_PEM)) != NULL,
                NULL);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    fail_unless((err = cert_match_public_key(cert, pkey)) == 1, NULL);

    fail_unless((err = cert_match_public_key(NULL, pkey)) == 0, NULL);
    fail_unless((err = cert_match_public_key(cert, NULL)) == 0, NULL);
    fail_unless((err = cert_match_public_key(NULL, NULL)) == 0, NULL);

    EVP_PKEY_free(pkey);
    X509_free(cert);

    HIP_DEBUG("Successfully passed test for matching of public keys.\n");
}

END_TEST

START_TEST(test_cert_verify_chain)
{
    int             err   = 0;
    X509           *cert  = NULL;
    STACK_OF(X509) *chain = NULL;

    HIP_DEBUG("Test verification of certificate chains.\n");

    fail_unless((cert = cert_load_x509_certificate(TEST_CERT,
                                                   ENCODING_FORMAT_PEM)) != NULL,
                NULL);
    fail_unless((chain = sk_X509_new_null()) != NULL, NULL);
    sk_X509_push(chain, cert);
    fail_unless((err = cert_verify_chain(cert, NULL, chain, NULL)) == 0, NULL);

    fail_unless((err = cert_verify_chain(NULL, NULL, chain, NULL)) != 0, NULL);
    fail_unless((err = cert_verify_chain(cert, NULL, NULL, NULL)) != 0, NULL);

    X509_free(cert);
    sk_X509_free(chain);

    HIP_DEBUG("Successfully passed test for verification of certificate chains.\n");
}

END_TEST

START_TEST(test_cert_get_X509_from_msg)
{
    int                len  = 0;
    X509              *cert = NULL, *cert2 = NULL;
    struct hip_common *msg  = NULL;
    unsigned char     *buf  = NULL;

    HIP_DEBUG("Test certificate extraction functionality.\n");

    fail_unless((cert = cert_load_x509_certificate(TEST_CERT,
                                                   ENCODING_FORMAT_PEM)) != NULL,
                NULL);
    msg = hip_msg_alloc();
    hip_build_network_hdr(msg, HIP_UPDATE, 0, &in6addr_any, &in6addr_any, HIP_V1);
    fail_unless((len = cert_X509_to_DER(cert, &buf)) > 0, NULL);
    fail_unless(hip_build_param_cert(msg, 0, 1, 1, HIP_CERT_X509V3, buf, len) == 0, NULL);
    fail_unless((cert2 = cert_get_X509_from_msg(msg)) != NULL, NULL);
    fail_unless(X509_cmp(cert, cert2) == 0, NULL);

    X509_free(cert);
    X509_free(cert2);
    free(buf);
    free(msg);

    HIP_DEBUG("Successfully passed test for certificate extraction functionality.\n");
}

END_TEST


Suite *libcore_cert(void)
{
    Suite *s = suite_create("libcore/cert");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_cert_load_x509_certificate);
    tcase_add_test(tc_core, test_cert_DER_encoding);
    tcase_add_test(tc_core, test_cert_match_public_key);
    tcase_add_test(tc_core, test_cert_verify_chain);
    tcase_add_test(tc_core, test_cert_get_X509_from_msg);

    suite_add_tcase(s, tc_core);

    return s;
}
