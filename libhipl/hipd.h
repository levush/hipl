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

#ifndef HIPL_LIBHIPL_HIPD_H
#define HIPL_LIBHIPL_HIPD_H

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "libcore/hashtable.h"
#include "libcore/protodefs.h"
#include "libcore/gpl/nlink.h"


#define HIP_HIT_DEV "dummy0"

#define HIP_SELECT_TIMEOUT 1
/* The select timeout in microseconds. */
#define HIP_SELECT_TIMEOUT_USEC (HIP_SELECT_TIMEOUT * 1000000)
#define HIP_RETRANSMIT_MAX        10
#define HIP_RETRANSMIT_BACKOFF_MIN (100 * 1000) /* microseconds */
#define HIP_RETRANSMIT_BACKOFF_MAX (15 * 1000000) /* microseconds */

#define HIP_R1_PRECREATE_INTERVAL 60 * 60 /* seconds */
#define HIP_R1_PRECREATE_INIT (HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)

#define QUEUE_CHECK_INTERVAL 15 /* seconds */
#define QUEUE_CHECK_INIT (QUEUE_CHECK_INTERVAL / HIP_SELECT_TIMEOUT)

#define CERTIFICATE_PUBLISH_INTERVAL 120 /* seconds */
#define HIP_HA_PURGE_TIMEOUT 5

#define HIP_ADDRESS_CHANGE_WAIT_INTERVAL 3 /* seconds */

extern struct rtnl_handle hip_nl_generic;

extern int hit_db_lock;

extern int hip_broadcast_status;
extern int lsi_status;

extern int  esp_prot_active;
extern int  esp_prot_num_transforms;
extern long esp_prot_num_parallel_hchains;

/* For switch userspace / kernel IPsec */
extern int hip_use_userspace_ipsec;

/* Functions for handling incoming packets. */
int hip_sock_recv_firewall(void);

/* Functions for handling outgoing packets. */
int hip_sendto_firewall(const struct hip_common *msg);

int hip_update_select_timeout(void);
int hipd_parse_cmdline_opts(int argc, char *argv[], uint64_t * flags);
int hipd_main(uint64_t flags);

/* libhip_mode accessor */
bool hipl_is_libhip_mode(void);
void hipl_set_libhip_mode(void);

#endif /* HIPL_LIBHIPL_HIPD_H */
