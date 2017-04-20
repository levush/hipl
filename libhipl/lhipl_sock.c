/*
 * Copyright (c) 2012 Aalto University and RWTH Aachen University.
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
 * Provides functions for maintaining libhipl sockets.
 */

#define _BSD_SOURCE

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "libcore/debug.h"
#include "libcore/hashtable.h"
#include "lhipl_sock.h"


/* A hashtable to record all opening libhipl sockets */
static HIP_HASHTABLE *hsocks = NULL;

static unsigned long hipl_sk_hash(const struct hipl_sock *hsock)
{
    return hsock->sid;
}

STATIC_IMPLEMENT_LHASH_HASH_FN(hipl_sk, struct hipl_sock)

static int hipl_sk_cmp(const struct hipl_sock *hsock1,
                       const struct hipl_sock *hsock2)
{
    return memcmp(&hsock1->sid, &hsock2->sid, sizeof(hsock1->sid));
}

STATIC_IMPLEMENT_LHASH_COMP_FN(hipl_sk, struct hipl_sock)

static uint32_t hsock_generate_id(void)
{
    static uint32_t id_generator = HIPL_LIB_HSOCK_ID_MIN;

    if (id_generator == HIPL_LIB_HSOCK_ID_MAX) {
        id_generator = HIPL_LIB_HSOCK_ID_MIN;
    } else {
        id_generator += 1;
    }

    return id_generator;
}

/**
 * Initialize the libhipl socket hashtable.
 */
void hipl_hsock_init(void)
{
    hsocks = hip_ht_init(LHASH_HASH_FN(hipl_sk), LHASH_COMP_FN(hipl_sk));
}

/**
 * Create a new libhipl socket and save it to the libhipl socket hashtable.
 *
 * @param family      the address family of the libhipl socket (INET or INET6).
 * @param type        the type of the protocol.
 * @param protocol    the protocol of the libhipl socket (TCP or UDP).
 * @return            pointer to the created libhipl socket on success, NULL on
 *                    error.
 */
struct hipl_sock *hipl_hsock_new(const int family, const int type,
                                 const int protocol)
{
    struct hipl_sock *hsock = NULL;

    hsock = calloc(sizeof(struct hipl_sock), sizeof(uint8_t));
    if (hsock == NULL) {
        HIP_ERROR("calloc() failed.\n");
        return NULL;
    }

    hsock->sid         = hsock_generate_id();
    hsock->sock_family = family;
    hsock->sock_type   = type;
    hsock->sock_proto  = protocol;
    hip_ht_add(hsocks, hsock);
    return hsock;
}

/**
 * Get a libhipl socket by its ID.
 *
 * @param hsock_id the ID of the libhipl socket.
 * @return         pointer to the libhipl socket on success, or NULL if the
 *                 given ID doesn't match any record.
 */
struct hipl_sock *hipl_hsock_find(const uint16_t hsock_id)
{
    struct hipl_sock hsock;

    hsock.sid = hsock_id;
    return hip_ht_find(hsocks, &hsock);
}

/**
 * Delete a libhipl socket and free the memory it occupies.
 *
 * @param hsock pointer to the libhipl socket to be deleted.
 */
void hipl_hsock_delete_and_free(struct hipl_sock *const hsock)
{
    struct hipl_sock *deleted_item;

    deleted_item = hip_ht_delete(hsocks, hsock);
    free(deleted_item);
}

/**
 * Get the HIP association state of a given libhipl socket.
 *
 * @param hsock the libhipl socket.
 * @return      the HIP association state of the libhipl socket.
 */
enum hip_state hipl_hsock_ha_state(const struct hipl_sock *const hsock)
{
    if (!hsock->ha) {
        return HIP_STATE_UNASSOCIATED;
    } else {
        return hsock->ha->state;
    }
}
