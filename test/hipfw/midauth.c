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

#define _BSD_SOURCE

#include "config.h"
#include "hipfw/hipfw.c"
#include "hipfw/hipfw_defines.h"
#include "hipfw/midauth.h"
#include "hipfw/midauth.c"
#include "modules/midauth/lib/midauth_builder.h"
#include "test_suites.h"
#include "test/mocks.h"

#ifdef HAVE_TCASE_ADD_EXIT_TEST
START_TEST(test_hipfw_midauth_add_challenge_NULL_common)
{
    struct hip_fw_context ctx;

    HIP_DEBUG("Testing NULL common \n");
    use_midauth = true;
    hipfw_midauth_add_challenge(&ctx, NULL);
}
END_TEST

START_TEST(test_hipfw_midauth_add_challenge_NULL_ctx)
{
    struct hip_common common;

    HIP_DEBUG("Testing NULL ctx \n");
    use_midauth = true;
    hipfw_midauth_add_challenge(NULL, &common);
}
END_TEST

START_TEST(test_hip_challenge_response_opaque_len_NULL)
{
    HIP_DEBUG("Testing hip_challenge_response_opaque_len on NULL input\n");
    hip_challenge_response_opaque_len(NULL);
}
END_TEST

START_TEST(test_verify_response_NULL_ctx)
{
    struct hip_challenge_response response;
    struct hip_common             common;

    verify_response(NULL, &response, &common);
}
END_TEST

START_TEST(test_verify_response_NULL_response)
{
    struct hip_fw_context ctx;
    struct hip_common     common;

    verify_response(&ctx, NULL, &common);
}
END_TEST

START_TEST(test_verify_response_NULL_common)
{
    struct hip_fw_context         ctx;
    struct hip_challenge_response response;

    verify_response(&ctx, &response, NULL);
}
END_TEST

START_TEST(test_hipfw_midauth_verify_challenge_NULL_ctx)
{
    struct hip_common common;

    hipfw_midauth_verify_challenge(NULL, &common);
}
END_TEST

START_TEST(test_hipfw_midauth_verify_challenge_NULL_common)
{
    struct hip_fw_context ctx;

    hipfw_midauth_verify_challenge(&ctx, NULL);
}
END_TEST

#endif /* HAVE_TCASE_ADD_EXIT_TEST */

START_TEST(test_hip_challenge_response_opaque_len)
{
    struct hip_challenge_response response;

    HIP_DEBUG("Testing hip_challenge_response_opaque_len \n");

    hip_set_param_contents_len(&response.tlv, 30);
    fail_unless(hip_challenge_response_opaque_len(&response) == 20, NULL);

    hip_set_param_contents_len(&response.tlv, 11);
    fail_unless(hip_challenge_response_opaque_len(&response) == 1, NULL);
}
END_TEST

START_TEST(test_verify_response_no_match)
{
    struct hip_fw_context         ctx;
    struct hip_challenge_response response;
    struct hip_common             common;
    uint8_t                       midauth_nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];

    HIP_DEBUG("Testing verify_response on non-matching inputs\n");

    common.hit_sender   = in6addr_any;
    common.hit_receiver = in6addr_any;

    hipfw_midauth_update_nonces();

    build_midauth_opaque(midauth_nonce, common.hit_sender,
                         common.hit_receiver, 1);

    hip_set_param_contents_len(&response.tlv, 30);
    memcpy(response.opaque, midauth_nonce, MIDAUTH_DEFAULT_NONCE_LENGTH);
    response.opaque[0]++;
    fail_unless(verify_response(&ctx, &response, &common) == 3, NULL);
    response.opaque[0]--;

    response.opaque[MIDAUTH_DEFAULT_NONCE_LENGTH - 1]++;
    fail_unless(verify_response(&ctx, &response, &common) == 3, NULL);
}
END_TEST

START_TEST(test_verify_response)
{
    int                           i;
    struct hip_common             hip;
    struct hip_fw_context         ctx;
    struct hip_challenge_response response;
    struct puzzle_hash_input      tmp_puzzle;
    uint8_t                       midauth_nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];

    HIP_DEBUG("Testing verify_response on valid inputs\n");

    // build context
    ctx.transport_hdr.hip = &hip;
    hip.hit_sender        = in6addr_any;
    hip.hit_receiver      = in6addr_any;

    hipfw_midauth_update_nonces();

    build_midauth_opaque(midauth_nonce, hip.hit_receiver, hip.hit_sender, 1);

    // build response
    fail_unless(hip_midauth_puzzle_seed(midauth_nonce, MIDAUTH_DEFAULT_NONCE_LENGTH, tmp_puzzle.puzzle) == 0, NULL);
    tmp_puzzle.initiator_hit = in6addr_any;
    tmp_puzzle.responder_hit = in6addr_any;
    hip_set_param_contents_len(&response.tlv, 30);
    memcpy(response.opaque, midauth_nonce, MIDAUTH_DEFAULT_NONCE_LENGTH);
    for (i = 1; i <= 20; i++) {
        HIP_DEBUG("Difficulty: %i \n", i);
        response.K = i;
        fail_unless(hip_solve_puzzle(&tmp_puzzle, response.K) == 0, NULL);
        memcpy(response.J, tmp_puzzle.solution, 8);
        fail_unless(verify_response(&ctx, &response, &hip) == 1, NULL);
    }
}
END_TEST

START_TEST(test_hipfw_midauth_verify_challenge)
{
    struct hip_common           *hip;
    struct hip_fw_context        ctx;
    struct hip_challenge_request request;
    struct puzzle_hash_input     tmp_puzzle;
    uint8_t                      midauth_nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];

    HIP_DEBUG("Testing verify_response on valid inputs\n");

    // build context
    hip                   = hip_msg_alloc();
    hip->hit_sender       = in6addr_any;
    hip->hit_receiver     = in6addr_any;
    ctx.transport_hdr.hip = hip;

    hipfw_midauth_update_nonces();

    build_midauth_opaque(midauth_nonce, hip->hit_sender, hip->hit_receiver, 1);

    // build request
    request.K        = 1;
    request.tlv.type = HIP_PARAM_CHALLENGE_REQUEST;
    hip_set_param_contents_len(&request.tlv, 22);
    memcpy(request.opaque, midauth_nonce, 20);

    // build solution
    fail_unless(hip_midauth_puzzle_seed(midauth_nonce, MIDAUTH_DEFAULT_NONCE_LENGTH, tmp_puzzle.puzzle) == 0, NULL);
    tmp_puzzle.initiator_hit = in6addr_any;
    tmp_puzzle.responder_hit = in6addr_any;
    fail_unless(hip_solve_puzzle(&tmp_puzzle, request.K) == 0, NULL);

    // build parameter
    hip_build_param_challenge_response(hip, &request, tmp_puzzle.solution);

    fail_unless(hipfw_midauth_verify_challenge(&ctx, hip) == 1, NULL);
}
END_TEST

Suite *firewall_midauth(void)
{
    Suite *s          = suite_create("hipfw/midauth");
    TCase *tc_midauth = tcase_create("Midauth");

#ifdef HAVE_TCASE_ADD_EXIT_TEST
    tcase_add_exit_test(tc_midauth, test_hipfw_midauth_add_challenge_NULL_common, 1);
    tcase_add_exit_test(tc_midauth, test_hipfw_midauth_add_challenge_NULL_ctx, 1);
    tcase_add_exit_test(tc_midauth, test_hip_challenge_response_opaque_len_NULL, 1);
    tcase_add_exit_test(tc_midauth, test_verify_response_NULL_ctx, 1);
    tcase_add_exit_test(tc_midauth, test_verify_response_NULL_response, 1);
    tcase_add_exit_test(tc_midauth, test_verify_response_NULL_common, 1);
    tcase_add_exit_test(tc_midauth, test_hipfw_midauth_verify_challenge_NULL_ctx, 1);
    tcase_add_exit_test(tc_midauth, test_hipfw_midauth_verify_challenge_NULL_common, 1);
#endif

    tcase_add_test(tc_midauth, test_hip_challenge_response_opaque_len);
    tcase_add_test(tc_midauth, test_verify_response_no_match);
    tcase_add_test(tc_midauth, test_verify_response);
    tcase_add_test(tc_midauth, test_hipfw_midauth_verify_challenge);

    suite_add_tcase(s, tc_midauth);

    return s;
}
