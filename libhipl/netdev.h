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
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */

#ifndef HIPL_LIBHIPL_NETDEV_H
#define HIPL_LIBHIPL_NETDEV_H

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "libcore/hashtable.h"
#include "libcore/protodefs.h"
#include "libcore/gpl/nlink.h"

extern struct rtnl_handle  hip_nl_route;
extern struct rtnl_handle  hip_nl_ipsec;
extern int                 hip_use_userspace_data_packet_mode;
extern int                 suppress_af_family;
extern int                 address_count;
extern HIP_HASHTABLE      *addresses;
extern hip_transform_suite hip_nat_status;
extern int                 address_change_time_counter;
extern int                 hip_wait_addr_changes_to_stabilize;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(void);
void hip_delete_all_addresses(void);
int hip_netdev_event(struct nlmsghdr *msg, int len, void *arg);
int hip_add_iface_local_hit(const hip_hit_t *const local_hit);
int hip_remove_iface_all_local_hits(void);
int hip_add_iface_local_route(const hip_hit_t *local_hit);
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst);
int netdev_trigger_bex(const hip_hit_t *src_hit_in,
                       const hip_hit_t *dst_hit_in,
                       const hip_lsi_t *src_lsi_in,
                       const hip_lsi_t *dst_lsi_in,
                       const struct in6_addr *src_addr_in,
                       const struct in6_addr *dst_addr_in);
int hip_netdev_trigger_bex_msg(const struct hip_common *msg);
void hip_add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

int hip_netdev_white_list_add(const char *const device_name);
int hip_exists_address_in_list(struct sockaddr *addr, int ifindex);

int hip_map_id_to_addr(const hip_hit_t *hit, const hip_lsi_t *lsi,
                       struct in6_addr *addr);

#endif /* HIPL_LIBHIPL_NETDEV_H */
