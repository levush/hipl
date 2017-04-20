/*
 * Copyright (c) 2010, 2012 Aalto University and RWTH Aachen University.
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
 * This file provides a framework for modifying HIP packets. It includes
 * adding new parameters in the correct order and adapting the various
 * headers.
 *
 * @brief Framework for the midauth extensions
 *
 * @note: According to draft-heer-hip-middle-auth-00 we SHOULD support IP-level
 * fragmentation for IPv6 and MUST support IP-level fragmentation for IPv4.
 * Currently we do neither.
 */

#define _BSD_SOURCE

#include <openssl/rand.h>
#include <stdbool.h>
#include <string.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/solve.h"
#include "modules/midauth/hipd/midauth.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "hipfw_defines.h"
#include "rewrite.h"
#include "midauth.h"


// static configuration
static const bool ignore_missing_challenge_request  = false;
static const bool ignore_missing_challenge_response = false;
static const bool ignore_wrong_challenge_solution   = false;
static const bool ignore_malformed_update           = false;
static const bool notify_failed_challenge           = true;

static const uint8_t DEFAULT_DIFFICULTY = 1;

// runtime configuration
bool use_midauth = false;

/* Number of concurrent midauth nonces. */
#define MIDAUTH_NONCES 2
/* Nonces used for midauth challenge. */
static unsigned char nonces[MIDAUTH_NONCES][MIDAUTH_DEFAULT_NONCE_LENGTH];
/* The currently active nonce in [0, MIDAUTH_NONCES - 1]. */
static unsigned int current_nonce;
/* Time at which midauth challenge nonces have last been updated. */
static time_t last_nonce_check;
/* Interval in seconds at which the nonces are updated. */
static time_t nonce_update_interval = 1;

/* The structure of the challenge used for midauth verification. */
union midauth_challenge {
    struct challenge {
        hip_hit_t src_hit;
        hip_hit_t dst_hit;
        uint8_t   nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];
    } structured __attribute__((packed));

    unsigned char serialized[sizeof(struct challenge)];
};

/**
 * Initialize the midauth extension for the firewall.
 */
void midauth_init(void)
{
    HIP_DEBUG("== midauth enabled ==\n");
}

/**
 * Get the lifetime of a midauth challenge.
 *
 * @param difficulty The difficulty of the puzzle.
 * @return The lifetime of the challenge.
 *
 * @todo Lifetime should depend on difficulty.
 */
static inline uint8_t lifetime(UNUSED const uint8_t difficulty)
{
    return 2;
}

/**
 * Build a midauth opaque value used in the CHALLENGE_REQUEST parameter.
 *
 * Behaviour is undefined if destination buffer is not at least 20 Bytes or no
 * valid connection context is provided or the nonce index is out of the
 * [0, MIDAUTH_NONCES - 1] bounds.
 *
 * @param dest        The destination buffer (at least 20 Bytes for SH1 output).
 * @param src_hit     The source HIT.
 * @param dst_hit     The destination HIT.
 * @param nonce_index The index of the nonce to be used to build the midauth nonce.
 * @return  0 on success.
 *         -1 on error.
 */
static int build_midauth_opaque(uint8_t *dest, const hip_hit_t src_hit,
                                const hip_hit_t dst_hit, unsigned nonce_index)
{
    union midauth_challenge challenge;

    challenge.structured.src_hit = src_hit;
    challenge.structured.dst_hit = dst_hit;
    memcpy(challenge.structured.nonce, nonces[nonce_index],
           sizeof(nonces[nonce_index]));

    if (!SHA1(challenge.serialized, sizeof(challenge), dest)) {
        HIP_ERROR("Failed to generate CHALLENGE_REQUEST nonce\n");
        return -1;
    }

    return 0;
}

/**
 * Update the two nonces used for midauth authentication.
 *
 * @return  0 on success.
 *         -1 on error.
 */
int hipfw_midauth_update_nonces(void)
{
    const time_t now = time(NULL);

    if (now < last_nonce_check) {
        HIP_ERROR("Clock skew detected; timestamp reset.\n");
        last_nonce_check = now;
        return -1;
    }

    if (now - last_nonce_check < nonce_update_interval) {
        return 0;
    }

    last_nonce_check = now;
    current_nonce    = (current_nonce + 1) % MIDAUTH_NONCES;
    if (!RAND_bytes(nonces[current_nonce], MIDAUTH_DEFAULT_NONCE_LENGTH)) {
        HIP_ERROR("Failed to generate CHALLENGE_REQUEST nonce\n");
        return -1;
    }

    return 0;
}

/**
 * Add a CHALLENGE_REQUEST parameter to a HIP packet passing through the
 * firewall.
 *
 * @param ctx The packet context.
 * @param common The packet itself.
 * @return 1 on success, 0 otherwise
 */
int hipfw_midauth_add_challenge(struct hip_fw_context *const ctx,
                                struct hip_common *const common)
{
    struct hip_challenge_request request;
    static const size_t          min_length = sizeof(request) -
                                              sizeof(request.tlv) -
                                              sizeof(request.opaque);
    if (use_midauth) {
        HIP_ASSERT(common);
        HIP_ASSERT(ctx);
        HIP_ASSERT(ctx->packet_type == HIP_PACKET);

        /* note: the length cannot be calculated with calc_param_len() */
        hip_set_param_contents_len(&request.tlv,
                                   min_length + MIDAUTH_DEFAULT_NONCE_LENGTH);
        hip_set_param_type(&request.tlv, HIP_PARAM_CHALLENGE_REQUEST);

        request.K        = DEFAULT_DIFFICULTY;
        request.lifetime = lifetime(DEFAULT_DIFFICULTY);

        if (build_midauth_opaque(request.opaque, common->hit_sender,
                                 common->hit_receiver, current_nonce) == -1) {
            HIP_ERROR("Failed to generate CHALLENGE_REQUEST nonce\n");
            return ignore_missing_challenge_request;
        }

        // IP (and UDP, if needed) frames will be updated upon send
        // Implicitly calls hip_fw_context_enable_write() if needed
        if (!hipfw_splice_param(ctx, &request.tlv)) {
            HIP_ERROR("Failed to splice CHALLENGE_REQUEST into existing packet\n");

            // fatality depends on current settings
            return ignore_missing_challenge_request;
        }
    }

    return 1;
}

/**
 * Getter for the length of the opaque field in a CHALLENGE_REPSONSE parameter.
 *
 * @param response The CHALLENGE_REPSONSE parameter.
 * @return The length of the opaque value.
 */
static uint8_t hip_challenge_response_opaque_len(const struct hip_challenge_response *response)
{
    HIP_ASSERT(response);
    static const size_t min_len = sizeof(*response) -
                                  sizeof(response->tlv) -
                                  sizeof(response->opaque);

    return hip_get_param_contents_len(&response->tlv) - min_len;
}

enum verification_result {
    ERROR,
    RESPONSE_CORRECT,
    RESPONSE_INCORRECT,
    RESPONSE_NO_MATCH
};

/**
 * Helper function for verifying a CHALLENGE_RESPONSE parameter.
 *
 * @param ctx The packet context.
 * @param response The CHALLENGE_RESPONSE parameter.
 * @param common The packet itself.
 * @return ERROR on validation error,
 *         RESPONSE_CORRECT if validation was successful,
 *         RESPONSE_INCORRECT if nonces match but solution is incorrect, and
 *         RESPONSE_NO_MATCH if no matching nonces are stored.
 */
static enum verification_result verify_response(const struct hip_fw_context *const ctx,
                                                const struct hip_challenge_response *const response,
                                                const struct hip_common *const common)
{
    HIP_ASSERT(ctx);
    HIP_ASSERT(response);
    HIP_ASSERT(common);

    //
    // TODO: - check lifetime
    //       - compare with connection state entry (K, nonce)
    //       - use HITs from packet or from ctx?
    //

    const uint8_t len   = hip_challenge_response_opaque_len(response);
    bool          match = false;

    if (len != MIDAUTH_DEFAULT_NONCE_LENGTH) {
        HIP_ERROR("Invalid nonce length: %d.\n", len);
        return ERROR;
    }

    for (unsigned i = 0; i < MIDAUTH_NONCES; i++) {
        uint8_t  nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];
        unsigned nonce_index = (current_nonce + i) % MIDAUTH_NONCES;

        if (build_midauth_opaque(nonce, common->hit_receiver,
                                 common->hit_sender, nonce_index) == -1) {
            return ERROR;
        } else if (!memcmp(response->opaque, nonce, MIDAUTH_DEFAULT_NONCE_LENGTH)) {
            match = true;
            break;
        }
    }

    if (!match) {
        return RESPONSE_NO_MATCH;
    }

    if (response->K < DEFAULT_DIFFICULTY) {
        return RESPONSE_INCORRECT;
    }

    const struct hip_common *const hip = ctx->transport_hdr.hip;

    if (response->K > 0) {
        struct puzzle_hash_input tmp_puzzle;

        if (hip_midauth_puzzle_seed(response->opaque, len, tmp_puzzle.puzzle)) {
            HIP_ERROR("failed to derive midauth puzzle\n");
            return ERROR;
        }
        tmp_puzzle.initiator_hit = hip->hit_sender;
        tmp_puzzle.responder_hit = hip->hit_receiver;
        memcpy(tmp_puzzle.solution, response->J, PUZZLE_LENGTH);

        if (hip_verify_puzzle_solution(&tmp_puzzle, response->K)) {
            return RESPONSE_INCORRECT;
        }
    }

    return RESPONSE_CORRECT;
}

/**
 * Verify a puzzle solution in the CHALLENGE_RESPONSE parameter.
 *
 * @param ctx The packet context.
 * @param common The packet itself.
 * @return 1 on success, 0 otherwise
 */
int hipfw_midauth_verify_challenge(const struct hip_fw_context *const ctx,
                                   const struct hip_common *const common)
{
    const struct hip_challenge_response *response;

    HIP_ASSERT(ctx);
    HIP_ASSERT(common);

    if (use_midauth) {
        HIP_ASSERT(ctx->packet_type == HIP_PACKET);

        response = hip_get_param(ctx->transport_hdr.hip,
                                 HIP_PARAM_CHALLENGE_RESPONSE);
        if (!response) {
            HIP_ERROR("Challenge response expected but not found\n");
            return ignore_missing_challenge_response ? 1 : 0;
        }

        do {
            switch (verify_response(ctx, response, common)) {
            case RESPONSE_CORRECT:
                HIP_DEBUG("Correct CHALLENGE_RESPONSE found\n");
                return 1;
            case RESPONSE_INCORRECT:
                HIP_ERROR("Incorrect CHALLENGE_RESPONSE found\n");
                if (notify_failed_challenge) {
                    // TODO: notify peer (ICMP, HIP notify)
                    HIP_DEBUG("STUB: notify\n");
                }

                if (!ignore_wrong_challenge_solution) {
                    return 0;
                }
                break;
            case RESPONSE_NO_MATCH:
                break;
            default:
                HIP_ERROR("Unable to compute challenge verification.\n");
                break;
            }

            response = (const struct hip_challenge_response *)
                       hip_get_next_param(ctx->transport_hdr.hip, &response->tlv);
        } while (response &&
                 hip_get_param_type(response) == HIP_PARAM_CHALLENGE_RESPONSE);

        return ignore_missing_challenge_response ? 1 : 0;
    }

    return 1;
}
