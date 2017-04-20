/*
 * Copyright (c) 2010,2012 Aalto University and RWTH Aachen University.
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

#ifndef HIPL_LIBHIPL_HIDB_H
#define HIPL_LIBHIPL_HIDB_H

/**
 * @file
 * Public interface for the HIDB, the database of local host identities (LHIs),
 * i.e., all the HIP identities known for the local host.
 */

#include <stdbool.h>
#include <netinet/in.h>

#include "libcore/crypto.h"
#include "libcore/protodefs.h"


#define HIP_R1TABLESIZE 3 /* precreate only this many R1s */

struct hip_r1entry {
    union hip_msg_bfr buf;
    uint32_t          generation;
    uint8_t           Ci[PUZZLE_LENGTH];
    uint8_t           Ck;
    uint8_t           Copaque[HIP_PUZZLE_OPAQUE_LEN];
};

struct local_host_id {
    hip_hit_t          hit;
    bool               anonymous;         /**< Is this an anonymous HI */
    hip_lsi_t          lsi;
    struct hip_host_id host_id;
    void              *private_key;       /* RSA or DSA */

    /* precreated R1 entries.
     * Due to the introduction of DH_GROUP_LIST in HIPv2,  R1's DIFFIE_HELLMAN
     * parameter must match one of the group ID of initiator's I1. Therefore we
     * precreate R1 for all DH groups we support. */
    struct hip_r1entry r1[HIP_R1TABLESIZE];
    struct hip_r1entry r1_v2[HIP_MAX_DH_GROUP_ID][HIP_R1TABLESIZE];
};

struct local_host_id *hip_get_hostid_entry_by_lhi_and_algo(const struct in6_addr *const hit,
                                                           const int algo, const int anon);
int hip_get_host_id_and_priv_key(struct in6_addr *hit,
                                 int algo,
                                 struct hip_host_id **host_id,
                                 void **key);

void hip_uninit_host_id_dbs(void);

int hip_handle_add_local_hi(const struct hip_common *input);

int hip_handle_del_local_hi(const struct hip_common *input);
int hip_for_each_hi(int (*func)(struct local_host_id *entry, void *opaq), void *opaque);

/*lsi support*/
int hip_hidb_exists_lsi(hip_lsi_t *lsi);
int hip_hidb_associate_default_hit_lsi(hip_hit_t *default_hit, hip_lsi_t *default_lsi);
int hip_hidb_get_lsi_by_hit(const hip_hit_t *our, hip_lsi_t *our_lsi);

/* existence */
int hip_hidb_hit_is_our(const hip_hit_t *src);

void hip_init_hostid_db(void);
int hip_get_default_hit(struct in6_addr *hit);
int hip_get_default_hit_msg(struct hip_common *msg);
int hip_get_default_lsi(struct in_addr *lsi);

#endif /* HIPL_LIBHIPL_HIDB_H */
