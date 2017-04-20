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
 * HIP cookie handling
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libcore/builder.h"
#include "libcore/common.h"
#include "libcore/debug.h"
#include "libcore/icomm.h"
#include "libcore/ife.h"
#include "libcore/protodefs.h"
#include "libcore/solve.h"
#include "libcore/gpl/pk.h"
#include "config.h"
#include "hidb.h"
#include "output.h"
#include "cookie.h"


static uint8_t hip_cookie_difficulty = 0; /* a difficulty of i leads to approx. 2^(i-1) hash computations during BEX */

/**
 * query for current puzzle difficulty
 *
 * @return the puzzle difficulty
 */
static int get_cookie_difficulty(void)
{
    /* Note: we could return a higher value if we detect DoS */
    return hip_cookie_difficulty;
}

/**
 * set puzzle difficulty
 *
 * @param k the new puzzle difficulty
 * @return the k value on success or negative on error
 */
static int set_cookie_difficulty(const uint8_t k)
{
    if (k > MAX_PUZZLE_DIFFICULTY) {
        HIP_ERROR("Bad cookie value (%d), min=%d, max=%d\n",
                  k, 1, MAX_PUZZLE_DIFFICULTY);
        return -1;
    }
    hip_cookie_difficulty = k;
    HIP_DEBUG("HIP cookie value set to %d\n", k);
    return k;
}

/**
 * get the puzzle difficulty and return result (for hipconf)
 *
 * @param msg A message containing a HIT for which to query for
 *            the difficulty. The difficulty will be written
 *            into the message as a HIP_PARAM_INT parameter.
 * @return zero on success and negative on error
 */
int hip_get_puzzle_difficulty_msg(struct hip_common *msg)
{
    int err = 0, diff = 0;

    diff = get_cookie_difficulty();

    hip_build_param_contents(msg, &diff, HIP_PARAM_INT, sizeof(diff));

    return err;
}

/**
 * set the puzzle difficulty according to the msg sent by hipconf
 *
 * @param msg An input/output message. Should contain the target
 *            HIT and the required puzzle difficulty.
 * @return zero on success and negative on error
 */
int hip_set_puzzle_difficulty_msg(struct hip_common *msg)
{
    const int       *new_val = NULL;
    const hip_hit_t *dst_hit = NULL;

    if (!(dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT))) {
        HIP_ERROR("No HIT set\n");
        return -1;
    }
    if (!(new_val = hip_get_param_contents(msg, HIP_PARAM_INT))) {
        HIP_ERROR("No difficulty set\n");
        return -1;
    }
    if (set_cookie_difficulty(*new_val), -1) {
        HIP_ERROR("Setting difficulty failed\n");
        return -1;
    }

    return 0;
}

/**
 * increase cookie difficulty by one
 *
 * @return the new cookie difficulty
 */
int hip_inc_cookie_difficulty(void)
{
    int k = get_cookie_difficulty() + 1;
    return set_cookie_difficulty(k);
}

/**
 * decrease cookie difficulty by one
 *
 * @return the new cookie difficulty
 */
int hip_dec_cookie_difficulty()
{
    int k = get_cookie_difficulty() - 1;
    return set_cookie_difficulty(k);
}

/**
 * calculate the index of a cookie
 *
 * @param ip_i Initiator's IPv6 address
 * @param ip_r Responder's IPv6 address
 *
 * @return 0 <= x < HIP_R1TABLESIZE
 */
static int calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r)
{
    register uint32_t base = 0;
    int               i;

    for (i = 0; i < 4; i++) {
        base ^= ip_i->s6_addr32[i];
        base ^= ip_r->s6_addr32[i];
    }

    for (i = 0; i < 3; i++) {
        base ^= (base >> (24 - i * 8)) & 0xFF;
    }

    /* base ready */

    return (base) % HIP_R1TABLESIZE;
}

/**
 * Get a copy of R1entry structure.
 *
 * @param ip_i        Initiator's IPv6
 * @param ip_r        Responder's IPv6
 * @param our_hit     Our HIT
 * @param dh_group_id Diffie Hellman group ID. -1 for HIPv1, otherwise return
                      R1 for HIPv2
 * @return            A R1 packet copy on success, NULL on error
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r,
                              struct in6_addr *our_hit, const int dh_group_id)
{
    struct hip_common    *r1         = NULL;
    struct hip_common    *r1_matched = NULL;
    struct local_host_id *hid        = NULL;
    int                   idx, len;

    /* Find the proper R1 table and copy the R1 message from the table */
    hid = hip_get_hostid_entry_by_lhi_and_algo(our_hit, HIP_ANY_ALGO, -1);
    if (hid == NULL) {
        HIP_ERROR("Unknown HIT\n");
        return NULL;
    }

    idx = calc_cookie_idx(ip_i, ip_r);
    HIP_DEBUG("Calculated index: %d\n", idx);

    if (dh_group_id == -1) {
        r1_matched = &hid->r1[idx].buf.msg;
    } else {
        r1_matched = &hid->r1_v2[dh_group_id][idx].buf.msg;
    }
    /* Create a copy of the found entry */
    len = hip_get_msg_total_len(r1_matched);
    if (len <= 0) {
        HIP_ERROR("Invalid r1 entry\n");
        return NULL;
    }

    if ((r1 = hip_msg_alloc()) == NULL) {
        return NULL;
    }

    memcpy(r1, r1_matched, len);

    return r1;
}

/**
 * HIPv1 & HIPv2: precreate R1 entries
 *
 * @param id_entry    a pointer to host ID entry
 * @param hit         the local HIT
 * @param sign        a signing callback function
 * @param privkey     the private key to use for signing
 * @param pubkey      the host id (public key)
 * @return            zero on success and non-zero on error
 */
int hip_precreate_r1(struct local_host_id *id_entry,
                     const hip_hit_t *const hit,
                     int (*sign)(void *const key, struct hip_common *const m),
                     void *const privkey,
                     const struct hip_host_id *const pubkey)
{
    const uint8_t cookie_k = get_cookie_difficulty();
    int           i, j, group_id;

    for (i = 0; i < HIP_R1TABLESIZE; i++) {
        hip_msg_init(&id_entry->r1[i].buf.msg);

        if (hip_create_r1(&id_entry->r1[i].buf.msg, hit, sign, privkey,
                          pubkey, cookie_k)) {
            HIP_ERROR("Unable to precreate R1s\n");
            return -1;
        }
        HIP_DEBUG("R1 Packet %d created\n", i);
    }

    for (j = 0; j < HIP_DH_GROUP_LIST_SIZE; j++) {
        group_id = HIP_DH_GROUP_LIST[j];
        for (i = 0; i < HIP_R1TABLESIZE; i++) {
            hip_msg_init(&id_entry->r1_v2[group_id][i].buf.msg);

            if (hip_create_r1_v2(&id_entry->r1_v2[group_id][i].buf.msg, hit, sign,
                                 privkey, pubkey, cookie_k, group_id)) {
                HIP_ERROR("Unable to precreate R1_v2\n");
                return -1;
            }
            HIP_DEBUG("R1_v2 Packets %d created for group: %d\n", i, group_id);
        }
    }

    return 0;
}

/**
 * Verifies the solution of a puzzle. First we check that K and I are the same
 * as in the puzzle we sent. If not, then we check the previous ones (since the
 * puzzle might just have been expired).
 *
 * @param ip_i        a pointer to Initiator's IP address.
 * @param ip_r        a pointer to Responder's IP address.
 * @param hdr         a pointer to HIP packet common header
 * @param solution    a pointer to a solution structure
 * @param hip_version HIP message version
 * @param dh_group_id the Diffie-Hellman group ID of the R1 entry. This
 *                    parameter is required for a HIPv2 cookie verification.
 *                    For v1, this parameter will be ignored.
 * @return            Zero if the cookie was verified successfully, negative
 *                    otherwise.
 */
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r,
                      struct hip_common *hdr,
                      const struct hip_solution *solution,
                      const uint8_t hip_version,
                      const int dh_group_id)
{
    /* In a effort to conform the HIPL coding convention, the return value
     * of this function was inverted. I.e. This function now returns
     * negative for error conditions, zero otherwise. It used to be the
     * other way around. -Lauri 23.07.2008. */
    const struct hip_puzzle *puzzle = NULL;
    struct hip_r1entry      *result = NULL;
    struct local_host_id    *hid    = NULL;
    struct puzzle_hash_input puzzle_input;
    int                      err = 0;

    /* Find the proper R1 table */
    HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(&hdr->hit_receiver,
                                                          HIP_ANY_ALGO,
                                                          -1)),
             -1, "Requested source HIT not (any more) available.\n");

    if (hip_version == HIP_V1) {
        result = &hid->r1[calc_cookie_idx(ip_i, ip_r)];
    } else {
        result = &hid->r1_v2[dh_group_id][calc_cookie_idx(ip_i, ip_r)];
    }

    puzzle = hip_get_param(&result->buf.msg, HIP_PARAM_PUZZLE);
    HIP_IFEL(!puzzle, -1, "Internal error: could not find the cookie\n");
    HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
                    HIP_PUZZLE_OPAQUE_LEN), -1,
             "Received cookie opaque does not match the sent opaque\n");

    HIP_DEBUG("Solution's I (0x%llx), sent I (0x%llx)\n",
              solution->I, puzzle->I);

    if (solution->K != puzzle->K) {
        HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
                 solution->K, puzzle->K);

        HIP_IFEL(solution->K != result->Ck, -1,
                 "Solution's K did not match any sent Ks.\n");
        HIP_IFEL(memcmp(solution->I, result->Ci, PUZZLE_LENGTH), -1,
                 "Solution's I did not match the sent I\n");
        HIP_IFEL(memcmp(solution->opaque, result->Copaque,
                        HIP_PUZZLE_OPAQUE_LEN), -1,
                 "Solution's opaque data does not match sent opaque data.\n");
        HIP_DEBUG("Received solution to an old puzzle\n");
    } else {
        HIP_HEXDUMP("solution", solution, sizeof(*solution));
        HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
        HIP_IFEL(memcmp(solution->I, puzzle->I, PUZZLE_LENGTH), -1,
                 "Solution's I did not match the sent I\n");
        HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
                        HIP_PUZZLE_OPAQUE_LEN), -1,
                 "Solution's opaque data does not match the opaque data sent\n");
    }

    memcpy(puzzle_input.puzzle, solution->I, PUZZLE_LENGTH);
    puzzle_input.initiator_hit = hdr->hit_sender;
    puzzle_input.responder_hit = hdr->hit_receiver;
    memcpy(puzzle_input.solution, solution->J, PUZZLE_LENGTH);

    HIP_IFEL(hip_verify_puzzle_solution(&puzzle_input, solution->K),
             -1, "Puzzle incorrectly solved.\n");

out_err:
    return err;
}

/**
 * recreate R1 packets corresponding to one HI
 *
 * @param entry the host id entry
 * @param opaque unused, required for compatibility with hip_for_each_hi()
 * @return zero on success or negative on error
 */
static int recreate_r1s_for_entry_move(struct local_host_id *entry,
                                       UNUSED void *opaque)
{
    int (*signature_func)(void *const key, struct hip_common *const m);

    switch (hip_get_host_id_algo(&entry->host_id)) {
    case HIP_HI_RSA:
        signature_func = hip_rsa_sign;
        break;
    case HIP_HI_DSA:
        signature_func = hip_dsa_sign;
        break;
#ifdef HAVE_EC_CRYPTO
    case HIP_HI_ECDSA:
        signature_func = hip_ecdsa_sign;
        break;
#endif /* HAVE_EC_CRYPTO */
    default:
        HIP_ERROR("Unknown algorithm");
        return -1;
    }

    if (hip_precreate_r1(entry, &entry->hit, signature_func,
                         entry->private_key, &entry->host_id) < 0) {
        HIP_ERROR("Precreate r1 failed\n");
        return -1;
    }

    return 0;
}

/**
 * precreate all R1 packets
 *
 * @return zero on success or negative on error
 */
int hip_recreate_all_precreated_r1_packets(void)
{
    return hip_for_each_hi(recreate_r1s_for_entry_move, NULL);
}
