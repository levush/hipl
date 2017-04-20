/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * certifcate functionality for the firewall
 *
 * @brief certificate functions for the firewall
 */

#define _BSD_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <openssl/x509.h>

#include "libcore/common.h"
#include "libcore/ife.h"
#include "libcore/builder.h"
#include "libcore/cert.h"
#include "libcore/debug.h"
#include "conntrack.h"
#include "hipfw_defines.h"
#include "rule_management.h"
#include "cert.h"

// runtime configuration
static int use_cert = false;

static STACK_OF(X509) *root_chain = NULL;

/**
 * Init function for certificate functionality.
 *
 * Iterate the firewall rules and look for the cert option. If found,
 * certificates are used and the root certificate is preloaded to verify
 * certificates. If no such rule is found, certificates are deactivated.
 *
 * @return 0 on success, negative if an error occurred
 */
int cert_init(void)
{
    X509         *cert = NULL;
    struct rule  *rule = NULL;
    struct dlist *list = NULL;

    if (!(list = get_rule_list(NF_IP6_FORWARD))) {
        use_cert = false;
        HIP_DEBUG("certificates deactivated\n");
        return 0;
    }

    if (!(root_chain = sk_X509_new_null())) {
        HIP_ERROR("Memory allocation failure.\n");
        return -ENOMEM;
    }

    /* Search for rules with cert option */
    while (list) {
        rule = list->data;
        if (rule->cert) {
            HIP_DEBUG("allowed cert: %s\n", rule->cert->value);
            use_cert = true;
            if (!(cert = cert_load_x509_certificate(rule->cert->value,
                                                    ENCODING_FORMAT_PEM))) {
                HIP_ERROR("Could not load certificate of community operator from file: %s \n",
                          rule->cert->value);
                return -1;
            }
            sk_X509_push(root_chain, cert);
        }
        list = list->next;
    }

    if (use_cert) {
        HIP_DEBUG("certificates activated\n");
    }

    return 0;
}

/**
 * Uninit function for certificate functionality.
 *
 * @return 0
 */
int cert_uninit(void)
{
    sk_X509_free(root_chain);
    return 0;
}

/**
 * Helper function that converts the special RSA and DSA key structures
 * to the generic EVP_PKEY structure.
 *
 * @param key   the RSA or DSA key structure
 * @param algo  either HIP_HI_RSA or HIP_HI_DSA
 *
 * @return      the EVP_PKEY structure that wraps the original key,
 *              or NULL on error
 */
static EVP_PKEY *any_key_to_evp_key(void *key, int algo)
{
    int       err = 0;
    EVP_PKEY *ret = NULL;

    if (!(ret = EVP_PKEY_new())) {
        HIP_ERROR("Could not init EVP_PKEY wrapper\n");
        return NULL;
    }

    switch (algo) {
    case HIP_HI_RSA:
        err = EVP_PKEY_assign_RSA(ret, key);
        break;
    case HIP_HI_DSA:
        err = EVP_PKEY_assign_DSA(ret, key);
        break;
    default:
        HIP_DEBUG("Unknown algorithm \n");
    }
    if (err == 0) {
        HIP_ERROR("Could not assign key to EVP_PKEY.\n");
        EVP_PKEY_free(ret);
        return NULL;
    }

    return ret;
}

/**
 * Extract the certificate from the R2 packet and match the contained public
 * key against the HI provided in the R1 and try to build and verify
 * a certificate chain.
 *
 * For an update exchange, a certificate must be contained either in the U2
 * (if the exchange was started by the Initiator) or in the U3
 * (if the exchange was started by the Responder). If a certificate cannot be
 * found in these situations an error is returned.
 *
 * @param common    the R2 or U2 packet
 * @param tuple     the connection tracking tuple
 * @param ctx       the firewall context
 * @return          0 on success, negative error code otherwise
 */
int cert_handle_certificate(const struct hip_common *const common,
                            UNUSED struct tuple *const tuple,
                            UNUSED const struct hip_fw_context *const ctx)
{
    X509     *cert = NULL;
    EVP_PKEY *pkey = NULL;

    if (use_cert) {
        /* Should there be a certificate?
         * Not if this update is not sent by the Responder. */
        if (!(tuple->direction == REPLY_DIR)) {
            return 0;
        }

        /* Extract certificate of trust point from the packet. */
        if (!(cert = cert_get_X509_from_msg(common))) {
            HIP_DEBUG("Could not find trust-point certificate in R2/U2.\n");
            return -1;
        }

        /* Match HI against public key in given certificate. */
        pkey = any_key_to_evp_key(tuple->hip_tuple->data->src_pub_key,
                                  tuple->hip_tuple->data->pub_key_type);
        if (!cert_match_public_key(cert, pkey)) {
            HIP_ERROR("HI does not match public key in given certificate.\n");
            return -1;
        }
        HIP_DEBUG("HI matches given certificate.\n");

        /* Check certificate of trust point. */
        if (cert_verify_chain(cert, NULL, root_chain, NULL)) {
            HIP_ERROR("Could not verify trust point certificate.\n");
            return -1;
        }

        HIP_DEBUG("Verified trust-point certificate.\n");
    }

    return 0;
}
