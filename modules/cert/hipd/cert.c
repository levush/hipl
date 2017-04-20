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
 * @brief functions to add certificates to R2 and U2 messages
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcore/builder.h"
#include "libcore/cert.h"
#include "libcore/debug.h"
#include "libcore/ife.h"
#include "libcore/protodefs.h"
#include "libhipl/hipd.h"
#include "libhipl/pkt_handling.h"
#include "modules/midauth/hipd/midauth.h"
#include "modules/update/hipd/update.h"
#include "cert.h"

static X509 *host_cert = NULL;

/**
 *  Handler that adds the certificate to an R2 message.
 *
 *  @param msg          the message where to add the certificate
 *  @param certificate  the certificate to add to the message
 *
 *  @return             0 on success, negative on error
 */
static int hip_add_certificate(struct hip_common *msg, X509 *certificate)
{
    unsigned char *buf;
    int            len = 0;

    /* Sanity checks */
    if (!msg) {
        HIP_ERROR("Message is NULL\n");
        return -1;
    }
    if (!certificate) {
        HIP_ERROR("Certificate is NULL\n");
        return -1;
    }

    /* Encode the certificate to DER and build the certificate parameter. */
    if ((len = cert_X509_to_DER(certificate, &buf)) < 0) {
        HIP_ERROR("Encoding error\n");
        return -1;
    }
    if (hip_build_param_cert(msg, 0, 1, 1, HIP_CERT_X509V3, buf, len)) {
        HIP_ERROR("Building of certificate parameter failed.\n");
        return -1;
    }

    return 0;
}

/**
 *  Handler that adds the certificate to an R2 message.
 *
 * @param packet_type unused
 * @param ha_state    unused
 * @param ctx         the packet context
 *
 * @return 0 on success, negative on failure
 *
 * @note:  The certificate is regarded non-critical thus the function does
 *         not fail even if no certificate is available.
 */
static int hip_add_certificate_r2(UNUSED const uint8_t packet_type,
                                  UNUSED const uint32_t ha_state,
                                  struct hip_packet_context *ctx)
{
    if (hip_add_certificate(ctx->output_msg, host_cert)) {
        HIP_DEBUG("Sending R2 without certificate.\n");
    }
    return 0;
}

/**
 * Handler that adds the certificate to the second or third update message.
 * A certificate should only be included if the previous
 * update packet contained a middlebox challenge.
 *
 * @param packet_type unused
 * @param ha_state    unused
 * @param ctx         the packet context
 *
 * @return 0 on success, negative on failure
 *
 * @note:  The certificate is regarded non-critical thus the function does
 *          not fail even if no certificate is available.
 */
static int hip_add_certificate_update(UNUSED const uint8_t packet_type,
                                      UNUSED const uint32_t ha_state,
                                      struct hip_packet_context *ctx)
{
    if (!host_cert) {
        HIP_DEBUG("No certificate available.\n");
        return 0;
    }

    /* Include a certificate in the U2 or U3, if available. */
    if (hip_classify_update_type(ctx->input_msg) == FIRST_UPDATE_PACKET ||
        hip_classify_update_type(ctx->input_msg) == SECOND_UPDATE_PACKET) {
        if (hip_get_param_contents(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST)) {
            if (hip_add_certificate(ctx->output_msg, host_cert)) {
                HIP_ERROR("Failed to add certificate to update message.\n");
                return -1;
            }
        } else {
            HIP_DEBUG("No middlebox found in previous update, omitting certificate.\n");
        }
    }

    return 0;
}

/**
 * Initialize certificate functionality in the hipd.
 * Registers handlers to add the trust point certificate in R2 and U2 messages.
 *
 * @return 0 on success, negative on error
 */
int hip_cert_init(void)
{
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED,
                                     &hip_add_certificate_r2, 40500)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_UPDATE, HIP_STATE_ESTABLISHED,
                                     &hip_add_certificate_update, 20752)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }
    if (hip_register_handle_function(HIP_ALL, HIP_UPDATE, HIP_STATE_R2_SENT,
                                     &hip_add_certificate_update, 20752)) {
        HIP_ERROR("Error on registering certificate handle function.\n");
        return -1;
    }

    if (!(host_cert = cert_load_x509_certificate(HIPL_SYSCONFDIR "/host-cert.der",
                                                 ENCODING_FORMAT_DER))) {
        HIP_DEBUG("Could not load certificate.\n");
    }

    HIP_DEBUG("certificates initialized\n");

    return 0;
}
