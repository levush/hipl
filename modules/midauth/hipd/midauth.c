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
 * This file contains the implementation for the middlebox authentication
 * extension.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "libcore/builder.h"
#include "libcore/common.h"
#include "libcore/ife.h"
#include "libcore/modularization.h"
#include "libcore/protodefs.h"
#include "libcore/solve.h"
#include "libcore/state.h"
#include "libhipl/hidb.h"
#include "libhipl/pkt_handling.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "modules/update/hipd/update.h"
#include "midauth.h"


/**
 * Handle the CHALLENGE_REQUEST parameter.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *            the packet handling (received message, source and destination
 *            address, the ports and the corresponding entry from the host
 *            association database).
 *
 * @return zero if the challenge was processed correctly or no challenge
 * parameter was attached to the packet, negative value otherwise.
 */
static int handle_challenge_request_param(UNUSED const uint8_t packet_type,
                                          UNUSED const enum hip_state ha_state,
                                          struct hip_packet_context *ctx)
{
    const struct hip_challenge_request *request = NULL;

    request = hip_get_param(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST);

    // each on-path middlebox may add a challenge on its own
    while (request &&
           hip_get_param_type(request) == HIP_PARAM_CHALLENGE_REQUEST) {
        struct puzzle_hash_input tmp_puzzle;
        const unsigned int       len = hip_challenge_request_opaque_len(request);

        if (hip_midauth_puzzle_seed(request->opaque, len, tmp_puzzle.puzzle)) {
            HIP_ERROR("failed to derive midauth puzzle\n");
            return -1;
        }

        tmp_puzzle.initiator_hit = ctx->input_msg->hit_receiver;
        tmp_puzzle.responder_hit = ctx->input_msg->hit_sender;

        if (hip_solve_puzzle(&tmp_puzzle, request->K)) {
            HIP_ERROR("Solving of middlebox challenge failed\n");
            return -EINVAL;
        }

        if (hip_build_param_challenge_response(ctx->output_msg,
                                               request,
                                               tmp_puzzle.solution) < 0) {
            HIP_ERROR("Error while creating CHALLENGE_RESPONSE parameter\n");
            return -1;
        }

        // process next challenge parameter, if available
        request = (const struct hip_challenge_request *)
                  hip_get_next_param(ctx->input_msg, &request->tlv);
    }

    return 0;
}

/**
 * Add a HOST_ID parameter corresponding to the local HIT of the association to
 * an UPDATE packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *            the packet handling (received message, source and destination
 *            address, the ports and the corresponding entry from the host
 *            association database).
 *
 * @return zero on success, negative value otherwise
 */
static int add_host_id_param_update(UNUSED const uint8_t packet_type,
                                    UNUSED const enum hip_state ha_state,
                                    struct hip_packet_context *ctx)
{
    const struct hip_challenge_request *const challenge_request =
        hip_get_param(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST);

    // add HOST_ID to packets containing a CHALLENGE_RESPONSE
    if (challenge_request) {
        const struct local_host_id *const host_id_entry =
            hip_get_hostid_entry_by_lhi_and_algo(&ctx->input_msg->hit_receiver,
                                                 HIP_ANY_ALGO,
                                                 -1);
        if (!host_id_entry) {
            HIP_ERROR("Unknown HIT\n");
            return -1;
        }

        if (hip_build_param_host_id(ctx->output_msg, &host_id_entry->host_id)) {
            HIP_ERROR("Building of host id failed\n");
            return -1;
        }
    }

    return 0;
}

/**
 * Initialization function for the midauth module.
 *
 * @return zero on success, negative value otherwise
 */
int hip_midauth_init(void)
{
    if (lmod_register_parameter_type(HIP_PARAM_CHALLENGE_REQUEST,
                                     "HIP_PARAM_CHALLENGE_REQUEST")) {
        HIP_ERROR("failed to register parameter type\n");
        return -1;
    }

    if (lmod_register_parameter_type(HIP_PARAM_CHALLENGE_RESPONSE,
                                     "HIP_PARAM_CHALLENGE_RESPONSE")) {
        HIP_ERROR("failed to register parameter type\n");
        return -1;
    }

    const enum hip_state challenge_request_R1_states[] = { HIP_STATE_I1_SENT,
                                                           HIP_STATE_I2_SENT,
                                                           HIP_STATE_CLOSING,
                                                           HIP_STATE_CLOSED };
    for (unsigned i = 0; i < ARRAY_SIZE(challenge_request_R1_states); i++) {
        if (hip_register_handle_function(HIP_ALL, HIP_R1,
                                         challenge_request_R1_states[i],
                                         &handle_challenge_request_param,
                                         32500)) {
            HIP_ERROR("Error on registering MIDAUTH handle function.\n");
            return -1;
        }
    }

    //
    // we hook on every occasion that causes an R2 to get sent.
    // R2 packet is first allocated at 40000, so we use a higher
    // base priority here.
    //
    const enum hip_state challenge_request_I2_states[] = { HIP_STATE_UNASSOCIATED,
                                                           HIP_STATE_I1_SENT,
                                                           HIP_STATE_I2_SENT,
                                                           HIP_STATE_R2_SENT,
                                                           HIP_STATE_ESTABLISHED,
                                                           HIP_STATE_CLOSING,
                                                           HIP_STATE_CLOSED,
                                                           HIP_STATE_NONE };
    for (unsigned i = 0; i < ARRAY_SIZE(challenge_request_I2_states); i++) {
        if (hip_register_handle_function(HIP_ALL, HIP_I2,
                                         challenge_request_I2_states[i],
                                         &handle_challenge_request_param,
                                         40322)) {
            HIP_ERROR("Error on registering MIDAUTH handle function.\n");
            return -1;
        }
    }

    //
    // Priority computed the same as above, but UPDATE response is sent at
    // priority 30000 already (checking is 20000) and we must add our
    // CHALLENGE_REQUEST verification in between, hence a lower base priority.
    //
    const enum hip_state challenge_request_UPDATE_states[] = { HIP_STATE_R2_SENT,
                                                               HIP_STATE_ESTABLISHED };
    for (unsigned i = 0; i < ARRAY_SIZE(challenge_request_UPDATE_states); i++) {
        if (hip_register_handle_function(HIP_ALL, HIP_UPDATE,
                                         challenge_request_UPDATE_states[i],
                                         &handle_challenge_request_param,
                                         20322)) {
            HIP_ERROR("Error on registering MIDAUTH handle function.\n");
            return -1;
        }

        if (hip_register_handle_function(HIP_ALL, HIP_UPDATE,
                                         challenge_request_UPDATE_states[i],
                                         &add_host_id_param_update,
                                         20750)) {
            HIP_ERROR("Error on registering MIDAUTH handle function.\n");
            return -1;
        }
    }

    return 0;
}
