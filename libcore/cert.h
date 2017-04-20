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

#ifndef HIPL_LIBCORE_CERT_H
#define HIPL_LIBCORE_CERT_H

#include <openssl/x509.h>

#include "libcore/protodefs.h"

enum encoding_format {
    ENCODING_FORMAT_PEM,
    ENCODING_FORMAT_DER
};

int cert_X509_to_DER(X509 *const cert, unsigned char **buf);
X509 *cert_DER_to_X509(const unsigned char *const buf, const int len);

X509 *cert_load_x509_certificate(const char *const file,
                                 enum encoding_format fmt);
X509 *cert_get_X509_from_msg(const struct hip_common *const msg);

int cert_match_public_key(X509 *cert, const EVP_PKEY *pkey);
int cert_verify_chain(X509 *leaf_cert,
                      const char *trusted_lookup_dir,
                      STACK_OF(X509) *trusted_chain,
                      STACK_OF(X509) *untrusted_chain);

#endif /* HIPL_LIBCORE_CERT_H */
