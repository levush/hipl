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
 * Provides the internal implementation of the libhipl socket related
 * operations.
 */

#define _BSD_SOURCE

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "libcore/builder.h"
#include "libcore/hip_udp.h"
#include "libcore/ife.h"
#include "libcore/prefix.h"
#include "lhipl.h"
#include "lhipl_sock.h"
#include "hadb.h"
#include "hidb.h"
#include "input.h"
#include "netdev.h"
#include "output.h"
#include "lhipl_operations.h"


/**
 * Automatically bind to a port for a libhipl socket.
 *
 * @param hsock the libhipl socket for port binding.
 * @return      0 on success, -1 on error.
 */
static int auto_bind(struct hipl_sock *const hsock)
{
    struct sockaddr_storage ss = { 0 };
    struct sockaddr_in     *addr4;
    struct sockaddr_in6    *addr6;

    if (hsock->src_port != 0) {
        HIP_DEBUG("A bound port exists, auto_bind stops\n");
        return 0;
    }

    if (hsock->sock_family == AF_INET) {
        ss.ss_family    = AF_INET;
        addr4           = (struct sockaddr_in *) &ss;
        addr4->sin_port = 0;
        return hipl_bind_internal(hsock, (struct sockaddr *) addr4,
                                  sizeof(ss));
    } else {
        ss.ss_family     = AF_INET6;
        addr6            = (struct sockaddr_in6 *) &ss;
        addr6->sin6_port = 0;
        return hipl_bind_internal(hsock, (struct sockaddr *) addr6,
                                  sizeof(ss));
    }
}

static uint16_t get_port_from_saddr(const struct sockaddr *const addr)
{
    const struct sockaddr_in  *addr4 = (const struct sockaddr_in *) addr;
    const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;

    if (addr->sa_family == AF_INET) {
        return addr4->sin_port;
    } else {
        return addr6->sin6_port;
    }
}

/**
 * Set global variables in order to inter-operate with libhipdeamon.
 *
 * @param sock_fd     the socket file descriptor for sending message.
 * @param local_port  the local port for sending message.
 * @param remote_port the remote port for receiving message.
 */
static void set_hip_connection_parameters(const int sock_fd,
                                          const int local_port,
                                          const int remote_port)
{
    HIP_DEBUG("Set connection params: fd = %d, lport = %d, rport= %d\n",
              sock_fd, local_port, remote_port);
    hip_nat_sock_output_udp = sock_fd;
    hip_raw_sock_output_v4  = sock_fd;
    hip_raw_sock_output_v6  = sock_fd;
    hip_set_local_nat_udp_port(local_port);
    hip_set_peer_nat_udp_port(remote_port);
}

/**
 * Check whether a received packet is a HIP control packet.
 *
 * @param buf   buffer containing the received packet.
 * @param len   size of the @c buf.
 * @param hsock the libhipl socket receiving the packet.
 * @return      1 on a control message, 0 on a user message,
 *              negative number on error.
 */
static int hipl_is_control_msg(char *const buf, unsigned int len,
                               struct hipl_sock *const hsock)
{
    char                    udp_pad[HIP_UDP_ZERO_BYTES_LEN] = { 0 };
    struct hip_common      *msg;
    struct sockaddr_storage src    = { 0 };
    socklen_t               srclen = sizeof(src);

    if (len < sizeof(struct hip_common)) {
        return 0;
    }

    if (!memcmp(udp_pad, buf, HIP_UDP_ZERO_BYTES_LEN)) {
        HIP_DEBUG("Message is padded\n");
        msg  = (struct hip_common *) (buf + HIP_UDP_ZERO_BYTES_LEN);
        len -= HIP_UDP_ZERO_BYTES_LEN;
    } else {
        msg = (struct hip_common *) buf;
    }

    if (getsockname(hsock->sock_fd, (struct sockaddr *) &src, &srclen) < 0) {
        HIP_PERROR("getsockname()");
        return true;
    }

    return !hip_verify_network_header(msg, (struct sockaddr *) &src,
                                      (struct sockaddr *) &hsock->peer_locator,
                                      len);
}

static void build_packet_context(struct hip_packet_context *const ctx,
                                 struct sockaddr *ctx_dst, struct sockaddr *ctx_src)
{
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;

    if (ctx_dst->sa_family == AF_INET) {
        s4 = (struct sockaddr_in *) ctx_dst;
        IPV4_TO_IPV6_MAP(&s4->sin_addr, &ctx->dst_addr);
        ctx->msg_ports.dst_port = ntohs(s4->sin_port);
    } else if (ctx_dst->sa_family == AF_INET6) {
        s6                      = (struct sockaddr_in6 *) ctx_dst;
        ctx->dst_addr           = s6->sin6_addr;
        ctx->msg_ports.dst_port = ntohs(s6->sin6_port);
    }

    if (ctx_src->sa_family == AF_INET) {
        s4 = (struct sockaddr_in *) ctx_src;
        IPV4_TO_IPV6_MAP(&s4->sin_addr, &ctx->src_addr);
        ctx->msg_ports.src_port = ntohs(s4->sin_port);
    } else if (ctx_src->sa_family == AF_INET6) {
        s6                      = (struct sockaddr_in6 *) ctx_src;
        ctx->src_addr           = s6->sin6_addr;
        ctx->msg_ports.src_port = ntohs(s6->sin6_port);
    }
}

/**
 * Receive and pre-process an incoming message.
 *
 * This function discards UDP packet from an unknown peer, identifies
 * user/control packet, eliminates zero padding in control packets and
 * builds the packet context for handling control packets.
 *
 * @param hsock       the libhipl socket for receiving message.
 * @param msg         buffer to hold the incoming message.
 * @param flags       the flags of socket @c recvmsg().
 * @param ctx         the HIP packet context to be built.
 * @param is_user_msg true if the message is a user message, false otherwise.
 * @return            negative number on errors, 0 on end-of-file, number of
 *                    bytes received otherwise.
 */
static int recv_msg_wrapper(struct hipl_sock *const hsock,
                            struct msghdr *const msg, const int flags,
                            struct hip_packet_context *const ctx,
                            bool *is_user_msg)
{
    int                     ret;
    struct sockaddr_storage our_locator = { 0 };
    socklen_t               sslen       = sizeof(our_locator);

    *is_user_msg = true;

    // The recvmsg function of socket library in meamo 5 platform somehow
    // doesn't work properly. It never returns the peer's address, which
    // causes libhipl failure.
    // Because of this, we use recvfrom instead for UDP. Since we don't support
    // gather read (multiple buffer) yet, there is only one buffer in the
    // msghdr and changing from recvmsg to recvfrom is ok. But this problem
    // need to be considered when we implement gather read.
    if (hsock->sock_proto == IPPROTO_UDP) {
        struct iovec *iov = msg->msg_iov;
        ret = recvfrom(hsock->sock_fd, iov->iov_base, iov->iov_len, flags,
                       msg->msg_name, &msg->msg_namelen);
    } else {
        ret = recvmsg(hsock->sock_fd, msg, flags);
    }
    if (ret < 0) {
        HIP_PERROR("recv message failed");
        return -1;
    }

    //in UDP mode, we don't know the peer locator until we receive the
    //first message from the peer. Once we get the peer locator, save it
    //to 'hsock'. We should also fill the packet context for UDP.
    if (hsock->sock_proto == IPPROTO_UDP) {
        if (msg->msg_name != NULL && hsock->peer_locator.ss_family == 0) {
            memcpy(&hsock->peer_locator, msg->msg_name,
                   sizeof(hsock->peer_locator));
        }
        if (ctx != NULL) {
            if (getsockname(hsock->sock_fd, (struct sockaddr *) &our_locator,
                            &sslen) < 0) {
                HIP_PERROR("getsockname()");
                return -1;
            }
            build_packet_context(ctx, (struct sockaddr *) &our_locator,
                                 (struct sockaddr *) &hsock->peer_locator);
        }
    }

    char *buf = msg->msg_iov->iov_base;
    if (hipl_is_control_msg(buf, ret, hsock)) {
        memmove(buf, buf + HIP_UDP_ZERO_BYTES_LEN,
                HIP_MAX_PACKET - HIP_UDP_ZERO_BYTES_LEN);
        ret         -= HIP_UDP_ZERO_BYTES_LEN;
        *is_user_msg = false;
    }

    return ret;
}

static int nonblock_result_check(const int ret, const int err)
{
    if (ret < 0 && err != EWOULDBLOCK && err != EAGAIN) {
        HIP_ERROR("BEX failed, errno = %d, errstr = %s\n", err,
                  strerror(err));
        return -1;
    }
    if (ret < 0 && (err == EWOULDBLOCK || err == EAGAIN)) {
        HIP_DEBUG("BEX returns EWOULDBLOCK or EAGAIN\n");
        return -EWAITBEX;
    }

    return 0;
}

/**
 * Wait for a HIP I1 packet and continue performing base exchange.
 *
 * @param hsock     the libhipl socket waiting for the I1 packet.
 * @param ctx       the HIP packet context for HIP packet processing.
 * @return          0 on success, -1 on error, -EWAITBEX when BEX is pending
 */
static int nonblock_await_bex(struct hipl_sock *const hsock,
                              struct hip_packet_context *const ctx)
{
    struct msghdr           params = { 0 };
    struct iovec            iov;
    struct sockaddr_storage ss;
    bool                    is_user_msg;
    int                     ret = 0;
    int                     flag;

    params.msg_name    = &ss;
    params.msg_namelen = sizeof(ss);
    params.msg_iovlen  = 1;
    iov.iov_base       = ctx->input_msg;
    iov.iov_len        = HIP_MAX_PACKET;
    params.msg_iov     = &iov;

    flag = fcntl(hsock->sock_fd, F_GETFL, 0);
    fcntl(hsock->sock_fd, F_SETFL, flag | O_NONBLOCK);

    set_hip_connection_parameters(hsock->sock_fd, hsock->src_port, 0);
    ret = recv_msg_wrapper(hsock, &params, 0, ctx, &is_user_msg);
    if ((ret = nonblock_result_check(ret, errno)) != 0) {
        HIP_DEBUG("returns %d\n", ret);
        goto out;
    }

    if (is_user_msg || hip_receive_control_packet(ctx) < 0) {
        HIP_ERROR("hip_receive_control_packet() failed\n");
        ret = -1;
    }

out:
    fcntl(hsock->sock_fd, F_SETFL, flag);
    return ret;
}

/**
 * Trigger BEX in a non-blocking way.
 *
 * @param hsock    the libhipl socket to trigger BEX.
 * @param src_hit  the source HIT for base exchange.
 * @param dst_hit  the destination HIT for base exchange.
 * @param dst_port the destination port.
 * @return         -1 on error, -EWAITBEX when the BEX is pending, 0 if sending
 *                 BEX trigger message successfully.
 */
static int nonblock_trigger_bex(struct hipl_sock *hsock,
                                const hip_hit_t *src_hit,
                                const hip_hit_t *dst_hit,
                                const int dst_port)
{
    struct in6_addr dst_addr;
    int             err = 0, flag;

    flag = fcntl(hsock->sock_fd, F_GETFL, 0);
    fcntl(hsock->sock_fd, F_SETFL, flag | O_NONBLOCK);

    err = hip_map_id_to_addr(dst_hit, NULL, &dst_addr);
    HIP_IFEL(err < 0, -1, "failed to match hit to IP\n");
    HIP_IFEL(ipv6_addr_any(&dst_addr), -1, "Couldn't map HIT to IP\n");

    set_hip_connection_parameters(hsock->sock_fd, hsock->src_port, dst_port);
    err = netdev_trigger_bex(src_hit, dst_hit, NULL, NULL, NULL, &dst_addr);
    HIP_DEBUG("netdev_trigger_bex returns %d, errno = %d\n", err, errno);
    err = nonblock_result_check(err, errno);
    if (err == 0) {
        hsock->ha = hip_hadb_find_byhits(src_hit, dst_hit);
    }

out_err:
    fcntl(hsock->sock_fd, F_SETFL, flag);
    return err;
}

/**
 * Handle BEX for a libhipl socket.
 *
 * If param @c peer_hit is given, current libhipl socket will be the initiator
 * and trigger the BEX. otherwise, it acts as a responder and waits for an I1
 * message.
 *
 * @param hsock    the libhipl socket to handle BEX.
 * @param peer_hit the peer's hit and port.
 * @return         -1 on error, -EWAITBEX when the BEX is pending, and
 *                 -EBEXESTABLISHED when BEX finishes.
 */
static int handle_bex(struct hipl_sock *hsock, struct sockaddr_in6 *peer_hit)
{
    int                       err = 0;
    struct hip_packet_context ctx = { 0 };

    // We are the initiator, send I1
    if (hipl_hsock_ha_state(hsock) == HIP_STATE_UNASSOCIATED && peer_hit) {
        hsock->peer_hit = peer_hit->sin6_addr;

        err = nonblock_trigger_bex(hsock, &hsock->src_hit,
                                   &peer_hit->sin6_addr,
                                   ntohs(peer_hit->sin6_port));
        // send I1 successfully, return -EWAITBEX.
        if (err == 0) {
            err = -EWAITBEX;
        }
        return err;
    }

    // waiting for and handle control messages
    hsock->ha = hip_hadb_find_byhits(&hsock->src_hit, &hsock->peer_hit);
    if (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED) {
        ctx.input_msg  = hip_msg_alloc();
        ctx.output_msg = hip_msg_alloc();
        HIP_IFEL(!ctx.input_msg || !ctx.output_msg, -ENOMEM,
                 "hip_msg_alloc() failed\n");

        err = nonblock_await_bex(hsock, &ctx);
        HIP_DEBUG("nonb_await_bex returns %d\n", err);
        if (err < 0) { /* -1 or -EWAITBEX */
            goto out_err;
        }
        hsock->peer_hit = ctx.input_msg->hit_sender;
        hsock->ha       = hip_hadb_find_byhits(&hsock->src_hit, &hsock->peer_hit);
    }

    if (hipl_hsock_ha_state(hsock) == HIP_STATE_ESTABLISHED) {
        err = -EBEXESTABLISHED;
    } else {
        err = -EWAITBEX;
    }

out_err:
    free(ctx.input_msg);
    free(ctx.output_msg);
    return err;
}

static int validate_udp_peer_addr(const struct hipl_sock *const hsock,
                                  const struct sockaddr_storage *const saddr)
{
    const struct in6_addr *paddr;
    struct in6_addr        peer_addr;

    if (hsock->sock_proto != IPPROTO_UDP) {
        return 0;
    }

    switch (saddr->ss_family) {
    case AF_INET:
        IPV4_TO_IPV6_MAP(&((const struct sockaddr_in *) saddr)->sin_addr,
                         &peer_addr);
        paddr = &peer_addr;
        break;

    case AF_INET6:
        paddr = &((const struct sockaddr_in6 *) saddr)->sin6_addr;
        break;

    default:
        HIP_DEBUG("Unsupported family: %d\n", saddr->ss_family);
        return -1;
    }

    if (ipv6_addr_cmp(&hsock->ha->peer_addr, paddr)) {
        HIP_DEBUG("Packet not from associated address. Dropping.\n");
        HIP_DEBUG_IN6ADDR("expected", &hsock->ha->peer_addr);
        HIP_DEBUG_IN6ADDR("got", paddr);
        return -1;
    }

    return 0;
}

/**
 * Build a @c sockaddr_storage from a given IPv6 address and a port number.
 *
 * If the address is V4MAPPED, the storage family will be @c AF_INET,
 * otherwise the storage family will be @c AF_INET6.
 *
 * @param addr    a V6 address or a V4MAPPED address.
 * @param port    the port number.
 * @param ss      the @c sockaddr_storage to be filled.
 */
void hipl_build_addrstorage(const struct in6_addr *const addr,
                            const uint16_t port,
                            struct sockaddr_storage *const ss)
{
    HIP_ASSERT(addr && ss);
    memset(ss, 0, sizeof(*ss));

    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct sockaddr_in *const in = (struct sockaddr_in *) ss;
        in->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(addr, &in->sin_addr);
        in->sin_port = htons(port);
    } else {
        struct sockaddr_in6 *const in6 = (struct sockaddr_in6 *) ss;
        in6->sin6_family = AF_INET6;
        ipv6_addr_copy(&in6->sin6_addr, addr);
        in6->sin6_port = htons(port);
    }
}

/**
 * Create a libhipl socket.
 *
 * @param family    the communications domain of the libhipl socket
 * @param type      the socket type of the libhipl socket
 * @param protocol  the protocol of the libhipl socket
 * @return          the ID of the new libhipl socket on success, negative
 *                  number otherwise
 */
int hipl_socket_internal(const int family, const int type, const int protocol)
{
    int               sock;
    int               on    = 1, off = 0;
    struct hipl_sock *hsock = NULL;

    //TODO support IPV6
    if (family == AF_INET6) {
        HIP_ERROR("No IPv6 support yet.\n");
        return -ENOTSUP;
    }

    sock = socket(family, type, protocol);
    if (family == AF_INET) {
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
        setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
        setsockopt(sock, IPPROTO_IP, IP_RECVERR, &off, sizeof(off));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    } else {
        setsockopt(sock, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(off));
        setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
    if ((hsock = hipl_hsock_new(family, type, protocol)) == NULL) {
        HIP_ERROR("Failed to create libhipl socket.\n");
        close(sock);
        return -1;
    }
    hsock->sock_fd = sock;
    hip_get_default_hit(&hsock->src_hit);

    return hsock->sid;
}

/**
 * Bind a libhipl socket to a local address.
 *
 * @param hsock         the libhipl socket for address binding.
 * @param address       the IP address to be bound.
 * @param address_len   the length of the @c address.
 * @return              0 on success, -1 on error.
 */
int hipl_bind_internal(struct hipl_sock *const hsock,
                       const struct sockaddr *const address,
                       const socklen_t address_len)
{
    struct     sockaddr_storage laddr     = { 0 };
    socklen_t                   laddr_len = sizeof(laddr);
    uint16_t                    request_port;

    request_port = get_port_from_saddr(address);
    if (bind(hsock->sock_fd, address, address_len) < 0) {
        HIP_PERROR("bind error:");
        return -1;
    }

    /* Ask OS for the assigned port number */
    if (request_port == 0) {
        if (0 > getsockname(hsock->sock_fd, (struct sockaddr *) &laddr,
                            &laddr_len)) {
            HIP_PERROR("getsockname() error: ");
            return -1;
        }
        request_port = get_port_from_saddr((struct sockaddr *) &laddr);
    }

    hsock->src_port = ntohs(request_port);
    HIP_DEBUG("bind to port %d\n", hsock->src_port);

    return 0;
}

/**
 * Initiate a connection to a peer.
 *
 * @param hsock    the libhipl socket to initiate the connection.
 * @param peer     the peer's HIT and port number.
 * @return         0 on success, -1 on error.
 */
int hipl_connect_internal(struct hipl_sock *const hsock,
                          const struct sockaddr_in6 *const peer)
{
    struct in6_addr         dst_addr = { { { 0 } } };
    struct sockaddr_storage ss;

    if (ipv6_addr_any(&peer->sin6_addr)) {
        HIP_ERROR("Invalid argument: dst_hit.\n");
        return -1;
    }

    if (hip_map_id_to_addr(&peer->sin6_addr, NULL, &dst_addr) < 0) {
        return -1;
    }
    if (ipv6_addr_any(&dst_addr)) {
        HIP_ERROR("Couldn't map HIT to IP\n");
        return -1;
    }

    HIP_DEBUG_IN6ADDR("Dest locator is: ", &dst_addr);
    HIP_DEBUG("Dest locator is V4MAPPED: %d\n", IN6_IS_ADDR_V4MAPPED(&dst_addr));
    hipl_build_addrstorage(&dst_addr, ntohs(peer->sin6_port), &ss);

    if (connect(hsock->sock_fd, (struct sockaddr *) &ss, sizeof(ss)) < 0) {
        HIP_ERROR("connect(): %s\n", strerror(errno));
        return -1;
    }

    /* Save related information into hsock */
    hsock->peer_hit     = peer->sin6_addr;
    hsock->peer_locator = ss;
    if (hsock->src_port == 0) {
        socklen_t taddr_len = sizeof(ss);

        if (getsockname(hsock->sock_fd, (struct sockaddr *) &ss,
                        &taddr_len) < 0) {
            HIP_PERROR("getsockname() error: ");
            return -1;
        }
        hsock->src_port = ntohs(get_port_from_saddr((struct sockaddr *) &ss));
    }

    return 0;
}

/**
 * Wait for an incoming connection on a libhipl socket.
 *
 * @param hsock the libhipl socket waiting for the connection.
 * @return      the ID of the accepted libhipl socket on success, -1 on error.
 */
int hipl_accept_internal(struct hipl_sock *const hsock)
{
    int                     new_fd;
    struct hipl_sock       *hsock_new = NULL;
    struct sockaddr_storage ss        = { 0 };
    socklen_t               ss_len    = sizeof(ss);

    new_fd = accept(hsock->sock_fd, (struct sockaddr *) &ss, &ss_len);
    if (new_fd < 0) {
        HIP_PERROR("accept(): ");
        return -1;
    }

    hsock_new = hipl_hsock_new(hsock->sock_family, hsock->sock_type,
                               hsock->sock_proto);
    hsock_new->src_port     = hsock->src_port;
    hsock_new->src_hit      = hsock->src_hit;
    hsock_new->sock_fd      = new_fd;
    hsock_new->peer_locator = ss;

    return hsock_new->sid;
}

/**
 * Receive data from a remote peer.
 *
 * Wait for base exchange if no host association exists.
 * @note Data is currently sent unencrypted.
 * @note Scatter read is not supported yet.
 *
 * @param hsock     the libhipl socket for receiving data.
 * @param msg       the buffer to hold data and peer information.
 * @param flags     the flags of the socket function @c recvmsg().
 * @return          number of bytes received on success,
 *                  0 on end-of-file,
 *                  -EWAITBEX when the BEX is pending,
 *                  -EBEXESTABLISHED when BEX finishes,
 *                  other negative numbers on error.
 */
ssize_t hipl_recvmsg_internal(struct hipl_sock *const hsock,
                              struct msghdr *const msg,
                              const int flags)
{
    struct hip_packet_context ctx    = { 0 };
    struct msghdr             params = { 0 };
    struct iovec              iov;
    struct sockaddr_storage   recv_remote_addr;
    int                       err = 0;
    bool                      is_user_msg;

    if (msg->msg_iovlen != 1) {
        HIP_ERROR("Invalid iovlen: %d, scatter read is not supported yet\n",
                  msg->msg_iovlen);
        return -ENOTSUP;
    }

    /* Bind to an ephemeral port if the src port hasn't been bound yet */
    if (auto_bind(hsock)) {
        HIP_ERROR("Fail to bind the hip socket.\n");
        return -1;
    }

    /* Handle BEX if HA hasn't established */
    if (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED
        && hipl_hsock_ha_state(hsock) != HIP_STATE_CLOSING) {
        return handle_bex(hsock, NULL);
    }

    ctx.input_msg  = hip_msg_alloc();
    ctx.output_msg = hip_msg_alloc();
    HIP_IFEL(!ctx.input_msg || !ctx.output_msg, -ENOMEM,
             "hip_msg_alloc() failed\n");
    params.msg_name    = &recv_remote_addr;
    params.msg_namelen = sizeof(recv_remote_addr);
    params.msg_iovlen  = 1;
    iov.iov_base       = ctx.input_msg;
    iov.iov_len        = HIP_MAX_PACKET;
    params.msg_iov     = &iov;

    err = recv_msg_wrapper(hsock, &params, flags, &ctx, &is_user_msg);
    HIP_IFEL(err < 0, -1, "recv_msg_wrapper() failed\n");

    if (validate_udp_peer_addr(hsock, &recv_remote_addr) < 0) {
        HIP_IFEL(true, -EAGAIN,
                 "Received a packet with invalid peer address, dropping.\n");
    }
    if (!is_user_msg) {
        HIP_DEBUG("receive a hip control message.\n");
        hip_receive_control_packet(&ctx);
        if (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED) {
            HIP_DEBUG("HA state change to %d, return 0.\n", hsock->ha->state);
            return 0;
        }
    } else {
        HIP_DEBUG("receive a user message.\n");
        // TODO, if buffer size is too small, we should save it to a internal buffer
        // and only return content with length specified by user's buffer (TCP).
        // return error for UDP in this case.
        struct iovec        *iovp;
        struct sockaddr_in6 *hitp;
        hitp = msg->msg_name;
        iovp = msg->msg_iov;
        HIP_IFEL(iovp->iov_len < (unsigned int) err, -1,
                 "buffer size too small\n");
        HIP_DEBUG_HIT("ha->hit_peer:", &hsock->ha->hit_peer);
        hitp->sin6_family = AF_INET6;
        hitp->sin6_port   = get_port_from_saddr((const struct sockaddr *) &hsock->peer_locator);
        HIP_DEBUG("hitp port: %d\n", ntohs(hitp->sin6_port));
        hitp->sin6_addr = hsock->ha->hit_peer;
        memcpy(iovp->iov_base, ctx.input_msg, err);
    }

out_err:
    free(ctx.input_msg);
    free(ctx.output_msg);
    return err;
}

/**
 * Send data to a peer.
 *
 * Trigger base exchange if no host association exists.
 * @note Data is currently sent unencrypted.
 * @note Gather write is not supported yet.
 *
 * @param hsock     the libhipl socket for sending data.
 * @param msg       containing data, and peer information.
 * @param flags     the flags of the socket function @c sendmsg().
 * @return          number of bytes sent on success,
 *                  -EWAITBEX if the BEX is pending,
 *                  -EBEXESTABLISHED if the BEX finishes,
 *                  other negative number on error.
 */
ssize_t hipl_sendmsg_internal(struct hipl_sock *const hsock,
                              struct msghdr *const msg,
                              const int flags)
{
    int fd = hsock->sock_fd;

    /* Gather write is not supported yet */
    if (msg->msg_iovlen > 1) {
        HIP_ERROR("Invalid iovlen: %d, gather write is not supported\n",
                  msg->msg_iovlen);
        return -ENOTSUP;
    }

    /* Bind to an ephemeral port if the src port hasn't been bound yet */
    if (auto_bind(hsock)) {
        HIP_ERROR("Fail to bind the hip socket.\n");
        return -1;
    }

    /* Start BEX if HA hasn't established */
    if (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED) {
        return handle_bex(hsock, msg->msg_name);
    }

    /* Determine peer's locator and send out the message */
    HIP_DEBUG("BEX ok, start to send user data\n");
    if (hsock->peer_locator.ss_family == 0) {
        hipl_build_addrstorage(&hsock->ha->peer_addr,
                               hsock->ha->peer_udp_port,
                               &hsock->peer_locator);
    }
    msg->msg_namelen = sizeof(hsock->peer_locator);
    memcpy(msg->msg_name, &hsock->peer_locator, msg->msg_namelen);
    return sendmsg(fd, msg, flags);
}
