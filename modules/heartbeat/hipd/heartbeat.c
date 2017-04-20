/*
 * Copyright (c) 2010, 2012-2013 Aalto University and RWTH Aachen University.
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
 *
 * The heartbeat code detects problems with the ESP tunnel. It is based on
 * sending ICMPv6 requests inside the tunnel. Each received ICMPv6
 * message indicates that the tunnel is in good "health". Correspondingly,
 * when there are no ICMPv6 messages received it may be a good time
 * to trigger an UPDATE packet to recover from the disconnectivity.
 *
 * The heartbeat code also keeps track of the timestamps for the
 * ICMPv6 messages. It could be used to implement handovers to switch
 * to faster paths or even as an utility for load balancing. At the
 * moment, the heartbeat algorithm is rather simple and used just for
 * fault tolerance.  It should also be noticed that the heartbeat code
 * is required only at one side of the communication as long as the
 * other party supports replying to ICMPv6 echo requests.
 *
 * @see Varjonen et al, Secure and Efficient IPv4/IPv6 Handovers Using
 * Host-Based Identifier-Locator Split, Journal of Communications
 * Software and Systems, 2010.
 *
 * @note Implementation of the heartbeat concept:
 *   - Send periodic ICMP messages to all associated peers (HEARTBEATs).
 *   - Increment the heartbeat counter in the hadb.
 *   - When a HEARTBEAT response is received, calculate roundtrip time and
 *     maintain statistics. Reset heartbeat counter to 0.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "android/android.h"
#include "libcore/common.h"
#include "libcore/debug.h"
#include "libcore/icomm.h"
#include "libcore/ife.h"
#include "libcore/prefix.h"
#include "libcore/protodefs.h"
#include "libcore/statistics.h"
#include "libcore/straddr.h"
#include "libcore/modularization.h"
#include "libcore/gpl/nlink.h"
#include "libhipl/close.h"
#include "libhipl/hadb.h"
#include "libhipl/hip_socket.h"
#include "libhipl/init.h"
#include "libhipl/maintenance.h"
#include "libhipl/nat.h"
#include "libhipl/output.h"
#include "libhipl/pkt_handling.h"
#include "libhipl/user.h"
#include "heartbeat.h"

#define HIP_MAX_ICMP_PACKET 512

static int hip_icmp_sock;

/** interval between ICMP heartbeats in multiples of the maintenance interval */
#define HIP_HEARTBEAT_INTERVAL 5
static int heartbeat_interval = HIP_HEARTBEAT_INTERVAL;

/** Remove state for stale connections after this many heartbeat failures. */
static const int heartbeat_state_remove_threshold = 12;

/**
 * This function sends ICMPv6 echo with timestamp
 *
 * @param sockfd to send with
 * @param entry the HA entry
 *
 * @return 0 on success negative on error
 */
static int icmp_send(int sockfd, struct hip_hadb_state *entry)
{
    struct icmp6_hdr     *icmph = NULL;
    struct sockaddr_in6   dst6  = { 0 };
    struct msghdr         mhdr  = { 0 };
    struct iovec          iov[1];
    struct cmsghdr       *chdr = NULL;
    struct inet6_pktinfo *pkti = NULL;
    struct timeval        tval;
    unsigned char         cmsgbuf[CMSG_SPACE(sizeof(struct inet6_pktinfo))] = { 0 };
    unsigned char        *icmp_pkt                                          = NULL;
    int                   identifier                                        = 0;

    if (!entry) {
        HIP_ERROR("No entry\n");
        return 0;
    }

    icmp_pkt = calloc(1, HIP_MAX_ICMP_PACKET);
    if (!icmp_pkt) {
        HIP_ERROR("calloc() for icmp_pkt failed.\n");
        return -ENOMEM;
    }

    chdr = (struct cmsghdr *) cmsgbuf;
    pkti = (struct inet6_pktinfo *) CMSG_DATA(chdr);

    identifier = getpid() & 0xFFFF;

    /* Build ancillary data */
    chdr->cmsg_len   = CMSG_LEN(sizeof(struct inet6_pktinfo));
    chdr->cmsg_level = IPPROTO_IPV6;
    chdr->cmsg_type  = IPV6_PKTINFO;
    memcpy(&pkti->ipi6_addr, &entry->hit_our, sizeof(struct in6_addr));

    /* get the destination */
    memcpy(&dst6.sin6_addr, &entry->hit_peer, sizeof(struct in6_addr));
    dst6.sin6_family   = AF_INET6;
    dst6.sin6_flowinfo = 0;

    /* build icmp header */
    icmph             = (struct icmp6_hdr *) icmp_pkt;
    icmph->icmp6_type = ICMP6_ECHO_REQUEST;
    icmph->icmp6_code = 0;
    entry->heartbeats_sent++;

    icmph->icmp6_seq = htons(entry->heartbeats_sent);
    icmph->icmp6_id  = identifier;

    gettimeofday(&tval, NULL);

    memset(&icmp_pkt[8], 0xa5, HIP_MAX_ICMP_PACKET - 8);
    /* put timeval into the packet */
    memcpy(&icmp_pkt[8], &tval, sizeof(struct timeval));

    /* put the icmp packet to the io vector struct for the msghdr */
    iov[0].iov_base = icmp_pkt;
    iov[0].iov_len  = sizeof(struct icmp6_hdr) + sizeof(struct timeval);

    /* build the msghdr for the sendmsg, put ancillary data also*/
    mhdr.msg_name       = &dst6;
    mhdr.msg_namelen    = sizeof(struct sockaddr_in6);
    mhdr.msg_iov        = iov;
    mhdr.msg_iovlen     = 1;
    mhdr.msg_control    = &cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    if (sendmsg(sockfd, &mhdr, MSG_DONTWAIT) <= 0) {
        HIP_ERROR("Failed to send ICMP into ESP tunnel\n");
    } else {
        HIP_DEBUG_HIT("Sent heartbeat to", &entry->hit_peer);
    }

    free(icmp_pkt);
    return 0;
}

/**
 * This function calculates RTT and then stores them to correct entry
 *
 * @param src HIT
 * @param dst HIT
 * @param stval time when sent
 * @param rtval time when received
 *
 * @return zero on success or negative on failure
 */
static int icmp_statistics(struct in6_addr *src, struct in6_addr *dst,
                           struct timeval *stval, struct timeval *rtval)
{
    uint32_t               rcvd_heartbeats = 0;
    uint64_t               rtt             = 0;
    double                 avg             = 0.0, std_dev = 0.0;
    char                   hit[INET6_ADDRSTRLEN];
    struct hip_hadb_state *entry              = NULL;
    uint8_t               *heartbeat_failures = NULL;

    hip_in6_ntop(src, hit);

    /* Find the correct entry */
    entry = hip_hadb_find_byhits(src, dst);
    if (!entry) {
        HIP_ERROR("Entry not found.\n");
        return -1;
    }

    /* Calculate the RTT from given timevals */
    rtt = calc_timeval_diff(stval, rtval);

    /* add the heartbeat item to the statistics */
    add_statistics_item(&entry->heartbeats_statistics, rtt);

    /* calculate the statistics for immediate output */
    calc_statistics(&entry->heartbeats_statistics, &rcvd_heartbeats, NULL,
                    NULL, &avg, &std_dev, STATS_IN_MSECS);

    heartbeat_failures = lmod_get_state_item(entry->hip_modular_state,
                                             "heartbeat_update");

    *heartbeat_failures = 0;
    HIP_DEBUG("heartbeat_failures: %d\n", *heartbeat_failures);

    HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
              "%.6f ms std dev, packets sent %d recv %d lost %d\n",
              hit, (float) rtt / STATS_IN_MSECS, avg, std_dev,
              entry->heartbeats_sent, rcvd_heartbeats,
              entry->heartbeats_sent - rcvd_heartbeats);

    return 0;
}

/**
 * This function receives ICMPv6 msgs (heartbeats)
 *
 * @param sockfd to recv from
 *
 * @return 0 on success otherwise negative
 *
 * @note see RFC2292
 */
static int icmp_recvmsg(int sockfd)
{
    int                   err  = 0, ret = 0, identifier = 0;
    struct msghdr         mhdr = { 0 };
    struct cmsghdr       *chdr;
    struct iovec          iov[1];
    unsigned char         iovbuf[HIP_MAX_ICMP_PACKET] = { 0 };
    unsigned char         cmsgbuf[CMSG_SPACE(sizeof(struct inet6_pktinfo))];
    struct sockaddr_in6   src_sin6 = { 0 };
    struct icmp6_hdr     *icmph    = NULL;
    struct inet6_pktinfo *pktinfo;
    struct in6_addr      *src   = NULL, *dst = NULL;
    struct timeval       *stval = NULL, *rtval = NULL, *ptr = NULL;

    /* malloc what you need */
    stval = calloc(1, sizeof(struct timeval));
    if (!stval) {
        HIP_ERROR("calloc for stval failed\n");
        return -ENOMEM;
    }
    rtval = calloc(1, sizeof(struct timeval));
    HIP_IFEL(!rtval, -ENOMEM, "calloc for rtval failed\n");
    src = calloc(1, sizeof(struct in6_addr));
    HIP_IFEL(!src, -ENOMEM, "calloc for dst6 failed\n");
    dst = calloc(1, sizeof(struct in6_addr));
    HIP_IFEL(!dst, -ENOMEM, "calloc for dst failed\n");

    /* cast */
    chdr    = (struct cmsghdr *) cmsgbuf;
    pktinfo = (struct inet6_pktinfo *) CMSG_DATA(chdr);

    /* receive control msg */
    chdr->cmsg_level = IPPROTO_IPV6;
    chdr->cmsg_type  = IPV6_2292PKTINFO;
    chdr->cmsg_len   = CMSG_LEN(sizeof(struct inet6_pktinfo));

    /* Input output buffer */
    iov[0].iov_base = &iovbuf;
    iov[0].iov_len  = sizeof(iovbuf);

    /* receive msg hdr */
    mhdr.msg_iov        = &(iov[0]);
    mhdr.msg_iovlen     = 1;
    mhdr.msg_name       = (caddr_t) &src_sin6;
    mhdr.msg_namelen    = sizeof(struct sockaddr_in6);
    mhdr.msg_control    = (caddr_t) cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    ret = recvmsg(sockfd, &mhdr, MSG_DONTWAIT);
    if (errno == EAGAIN) {
        err = 0;
        goto out_err;
    }
    if (ret < 0) {
        HIP_DEBUG("Recvmsg on ICMPv6 failed\n");
        err = -1;
        goto out_err;
    }

    /* Get the current time as the return time */
    gettimeofday(rtval, NULL);

    /* Check if the process identifier is ours and that this really is echo response */
    icmph = (struct icmp6_hdr *) iovbuf;
    if (icmph->icmp6_type != ICMP6_ECHO_REPLY) {
        err = 0;
        goto out_err;
    }
    identifier = getpid() & 0xFFFF;
    if (identifier != icmph->icmp6_id) {
        err = 0;
        goto out_err;
    }

    /* Get the timestamp as the sent time*/
    ptr = (struct timeval *) (icmph + 1);
    memcpy(stval, ptr, sizeof(struct timeval));

    /* gather addresses */
    memcpy(src, &src_sin6.sin6_addr, sizeof(struct in6_addr));
    memcpy(dst, &pktinfo->ipi6_addr, sizeof(struct in6_addr));

    if (!ipv6_addr_is_hit(src) && !ipv6_addr_is_hit(dst)) {
        HIP_DEBUG("Addresses are NOT HITs, this msg is not for us\n");
    }

    /* Calculate and store everything into the correct entry */
    if (icmp_statistics(src, dst, stval, rtval)) {
        HIP_ERROR("Failed to calculate the statistics and store the values\n");
        err = -1;
    }

out_err:
    free(stval);
    free(rtval);
    free(src);
    free(dst);

    return err;
}

static int heartbeat_handle_icmp_sock(UNUSED struct hip_packet_context *ctx)
{
    if (icmp_recvmsg(hip_icmp_sock)) {
        HIP_ERROR("Failed to recvmsg from ICMPv6.\n");
        return -1;
    }
    return 0;
}

/**
 * This function goes through the HA database and sends an icmp echo to all of them
 *
 * @param hadb_entry
 * @param opaq
 *
 * @return 0 on success negative on error
 */
static int heartbeat_send(struct hip_hadb_state *hadb_entry, void *opaq)
{
    int     *sockfd             = (int *) opaq;
    uint8_t *heartbeat_failures = NULL;

    if (hadb_entry->state == HIP_STATE_ESTABLISHED) {
        if (!(heartbeat_failures = lmod_get_state_item(hadb_entry->hip_modular_state,
                                                       "heartbeat_update"))) {
            HIP_ERROR("Missing 'heartbeat_update' state item.\n");
            return -1;
        }

        /* check if we should remove the broken connection */
        if (*heartbeat_failures >= heartbeat_state_remove_threshold) {
            char *opaque         = NULL;
            int   delete_ha_info = 1;

            if (!(opaque = calloc(1, sizeof(hip_hit_t) + sizeof(int)))) {
                HIP_ERROR("failed to allocate memory\n");
                return -ENOMEM;
            }

            memcpy(opaque, &hadb_entry->hit_peer, sizeof(hip_hit_t));
            memcpy(opaque + sizeof(hip_hit_t), &delete_ha_info, sizeof(int));

            xmit_close(hadb_entry, opaque);

            free(opaque);
            return 0;
        }

        if (icmp_send(*sockfd, hadb_entry)) {
            HIP_ERROR("Error sending heartbeat.\n");
        }

        *heartbeat_failures += 1;
        HIP_DEBUG("heartbeat_failures: %d\n", *heartbeat_failures);
    }

    return 0;
}

static int heartbeat_maintenance(void)
{
    /* Check if the heartbeats should be sent */
    if (heartbeat_interval < 1) {
        hip_for_each_ha(heartbeat_send, &hip_icmp_sock);
        heartbeat_interval = HIP_HEARTBEAT_INTERVAL;
    } else {
        heartbeat_interval--;
    }

    return 0;
}

static int heartbeat_handle_user_msg(UNUSED struct hip_common *msg,
                                     UNUSED struct sockaddr_in6 *src)
{
    return 0;
}

static int heartbeat_init_state(struct modular_state *state)
{
    uint8_t *heartbeat_failures = NULL;

    if (!(heartbeat_failures = calloc(1, sizeof(uint8_t)))) {
        HIP_ERROR("Error on allocating memory for heartbeat_failures.\n");
        return -ENOMEM;
    }

    return lmod_add_state_item(state, heartbeat_failures, "heartbeat_update");
}

/**
 * Initialize icmpv6 socket.
 */
int hip_heartbeat_init(void)
{
    int                 err = 0, on = 1;
    struct icmp6_filter filter;

    HIP_INFO("Initializing heartbeat extension\n");

    hip_icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    set_cloexec_flag(hip_icmp_sock, 1);
    if (hip_icmp_sock <= 0) {
        HIP_ERROR("ICMPv6 socket creation failed\n");
        return 1;
    }

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    err = setsockopt(hip_icmp_sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                     sizeof(filter));
    if (err) {
        HIP_ERROR("setsockopt icmp ICMP6_FILTER failed\n");
        return -1;
    }

    err = setsockopt(hip_icmp_sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    if (err) {
        HIP_ERROR("setsockopt icmp IPV6_RECVPKTINFO failed\n");
        return -1;
    }
    if (hip_register_socket(hip_icmp_sock, &heartbeat_handle_icmp_sock,
                            30000)) {
        HIP_ERROR("Error on registration of hip_icmp_sock for HEARTBEAT module.\n");
        return -1;
    }

    if (hip_unregister_maint_function(&hip_nat_refresh_port)) {
        HIP_DEBUG("Unregister 'hip_nat_refresh_port()' failed.\n");
    }

    if (hip_register_maint_function(&heartbeat_maintenance, 10000)) {
        HIP_ERROR("Error on registration of heartbeat_maintenance().\n");
        return -1;
    }

    if (lmod_register_state_init_function(&heartbeat_init_state)) {
        HIP_ERROR("Error on registration of heartbeat_init_state().\n");
        return -1;
    }

    if (hip_user_register_handle(HIP_MSG_HEARTBEAT, &heartbeat_handle_user_msg,
                                 20000)) {
        HIP_ERROR("Error on registering HEARTBEAT user message handle function.\n");
        return -1;
    }

    return err;
}
