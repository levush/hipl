/*
 * Copyright (c) 2010-2012 Aalto University and RWTH Aachen University.
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

/**
 * @file
 * @brief functionality for handling X509 certificates
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "builder.h"
#include "debug.h"
#include "ife.h"
#include "common.h"
#include "cert.h"

/**
 * This function encodes the given certificate to its DER encoding for
 * transmission over the wire. The encoded certificate is written to @p buf.
 *
 * @param cert      the certificate to encode
 * @param buf       the output is written here
 *
 * @return          the length of the encoded data
 *
 * @note: The encoded data is in binary form and may contain embedded zeroes.
 *        Functions such as strlen() will not return the correct length of the
 *        encoded structure. Therefore the length value returned by this
 *        function should always be used.
 */
int cert_X509_to_DER(X509 *const cert, unsigned char **buf)
{
    int len;

    if (!cert) {
        HIP_ERROR("Cannot encode NULL-certificate\n");
        return -1;
    }
    if (!buf) {
        HIP_ERROR("Cannot create output buffer at NULL-pointer.\n");
        return -1;
    }

    *buf = NULL;
    len  = i2d_X509(cert, buf);

    if (len < 0) {
        HIP_ERROR("Could not DER-encode the given certificate.\n");
        return -1;
    }
    return len;
}

/**
 * Function to decode a DER-encoded certificate to the internal OpenSSL X509
 * structure.
 *
 * @param buf   the buffer from which the DER-encoded certificate is read
 * @param len   the length of the DER-encoded certificate
 *              (NOTE: strlen() and similar functions fail, since DER is
 *              basically binary data that can contain 0-bytes).
 *
 * @return      the OpenSSL X509 structure corresponding the DER-encoded
 *              certificate, NULL if errors occured
 */
X509 *cert_DER_to_X509(const unsigned char *buf, const int len)
{
    if (!buf) {
        HIP_ERROR("Cannot decode from NULL-buffer\n");
        return NULL;
    }
    if (len <= 0) {
        HIP_ERROR("Cannot decode certificate of length <= 0\n");
        return NULL;
    }
    return d2i_X509(NULL, &buf, len);
}

/**
 * Load a X509 certificate from @p file. If @p file contains more
 * than one certificate, the certificate at the top of the file is
 * returned.
 *
 * @param   file  the file to load the certficate from
 * @param   fmt   the input format of the certificate
 *
 * @return  a pointer to an X.509 certificate on success, NULL on error
 */
X509 *cert_load_x509_certificate(const char *const file,
                                 enum encoding_format fmt)
{
    FILE *fp   = NULL;
    X509 *cert = NULL;

    if (!file) {
        HIP_ERROR("Cannot read certificate from NULL-filename.\n");
        return NULL;
    }

    fp = fopen(file, "rb");
    if (!fp) {
        HIP_ERROR("Could not open file for reading: %s\n", file);
        return NULL;
    }

    switch (fmt) {
    case ENCODING_FORMAT_PEM:
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        break;
    case ENCODING_FORMAT_DER:
        cert = d2i_X509_fp(fp, NULL);
        break;
    default:
        HIP_ERROR("Invalid encoding format %i \n", fmt);
    }

    if (!cert) {
        HIP_ERROR("Could not decode certificate from file.\n");
    }

    if (fclose(fp)) {
        HIP_ERROR("Error closing file: %s\n", file);
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/**
 * Search for hip_cert parameter in @p msg and try to decode the data in
 * the first certificate parameter of a X509 certificate.
 *
 * @param msg   the message to extract the certificate from
 *
 * @return      the first X509 certificate found in the message on success,
 *              NULL on error and if no certificates were found
 */
X509 *cert_get_X509_from_msg(const struct hip_common *const msg)
{
    const struct hip_cert *param_cert = NULL;

    if (!(param_cert = hip_get_param(msg, HIP_PARAM_CERT))) {
        HIP_ERROR("Message contains no certificate.\n");
        return NULL;
    }

    /* The contents of the certificate begin after the header of the
     * hip_cert parameter. */
    return cert_DER_to_X509((const unsigned char *) (param_cert + 1),
                            ntohs(param_cert->length) -
                            sizeof(struct hip_cert) +
                            sizeof(struct hip_tlv_common));
}

/**
 * Compare a given public key @p pkey with the public key
 * contained in @p cert.
 *
 * @param cert  the X509 certificate
 * @param pkey  the public key to match
 *
 * @return 1 if match, 0 otherwise
 */
int cert_match_public_key(X509 *cert, const EVP_PKEY *pkey)
{
    int       ret   = 0;
    EVP_PKEY *pkey2 = NULL;

    if (!cert || !pkey) {
        return 0;
    }

    pkey2 = X509_get_pubkey(cert);

    if (pkey2) {
        ret = (EVP_PKEY_cmp(pkey2, pkey) == 1);
        EVP_PKEY_free(pkey2);
    }

    return ret;
}

/**
 * Build and verify a certificate chain.
 *
 * @param leaf_cert             the certificate to verify
 * @param trusted_lookup_dir    certificates in this directory are used as
 *                              root certificates
 * @param trusted_chain         a certificate stack that can contain additional
 *                              trusted certificates
 * @param untrusted_chain       a chain of untrusted certificates that can be
 *                              used to build a complete certificate chain
 *
 * @return                      0 if a certificate chain could be built and
 *                              verified, a non-zero error code otherwise
 */
int cert_verify_chain(X509 *leaf_cert,
                      const char *trusted_lookup_dir,
                      STACK_OF(X509) *trusted_chain,
                      STACK_OF(X509) *untrusted_chain)
{
    int             err              = 0;
    X509_LOOKUP    *lookup           = NULL;
    X509_STORE     *verify_ctx_store = NULL;
    X509_STORE_CTX *verify_ctx       = NULL;

    if (!leaf_cert) {
        HIP_ERROR("Cannot verify NULL-certificate.\n");
        return -1;
    }

    if (!trusted_lookup_dir && !trusted_chain) {
        HIP_ERROR("Need trusted dir and trusted chain.\n");
        return -1;
    }

    /* Build the verify context */
    if (!(verify_ctx_store = X509_STORE_new())) {
        HIP_ERROR("Failed to init certificate store.\n");
        return -1;
    }
    if (!(lookup = X509_STORE_add_lookup(verify_ctx_store, X509_LOOKUP_hash_dir()))) {
        HIP_ERROR("Failed to init lookup directory.\n");
        return -1;
    }
    if (trusted_lookup_dir) {
        if (!X509_LOOKUP_add_dir(lookup, trusted_lookup_dir,
                                 X509_FILETYPE_PEM)) {
            HIP_ERROR("Failed to add directory %s to trusted lookup resources.\n",
                      trusted_lookup_dir);
            return -1;
        }
    } else {
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

    if (!(verify_ctx = X509_STORE_CTX_new())) {
        HIP_ERROR("Failed to allocate new verify context.\n");
        return -ENOMEM;
    }
    if (!X509_STORE_CTX_init(verify_ctx, verify_ctx_store, leaf_cert,
                             untrusted_chain)) {
        HIP_ERROR("Failed to setup verify context.\n");
        X509_STORE_CTX_free(verify_ctx);
        return -1;
    }
    if (trusted_chain) {
        X509_STORE_CTX_trusted_stack(verify_ctx, trusted_chain);
    }

    /* Finally do the verification and output some info on error */
    OpenSSL_add_all_algorithms();
    err = X509_verify_cert(verify_ctx);

    if (err != 1) {
        err = X509_STORE_CTX_get_error(verify_ctx);
        HIP_DEBUG("X509 verify cert error: %d \n", err);
        HIP_DEBUG("at depth: %d \n", X509_STORE_CTX_get_error_depth(verify_ctx));
        HIP_DEBUG("reason: %s\n", X509_verify_cert_error_string(err));
        HIP_DEBUG("certificate:\n");
        X509_print_fp(stderr, X509_STORE_CTX_get_current_cert(verify_ctx));
    } else {
        err = 0;
    }

    X509_STORE_free(verify_ctx_store);
    X509_STORE_CTX_free(verify_ctx);
    return err;
}
