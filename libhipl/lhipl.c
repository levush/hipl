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
 * Provides the implementation of the libhipl public APIs.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "libcore/builder.h"
#include "libcore/ife.h"
#include "libcore/prefix.h"
#include "close.h"
#include "hadb.h"
#include "init.h"
#include "lhipl_sock.h"
#include "lhipl_operations.h"
#include "netdev.h"
#include "output.h"
#include "lhipl.h"


/* A switch to turn BEX feedback off/on.
 *
 * If it is on, when the BEX process is conducted during "recvmsg" and "sendmsg",
 * the intermediate result is returned to the caller.
 * If it is off, "recvmsg" and "sendmsg" will only return after the message gets
 * sent or received.
 */
static bool libhipl_bex_feedback;

/**
 * build a @c sockaddr_in6 address to store a peer's HIT and port number from a
 * string-based peer name and a port number.
 *
 * @param peername the string representation of a peer, only support HIT string
 *                 currently.
 * @param port     the port of the peer.
 * @param peer     the @c sockaddr_in6 to hold the peer's HIT and port number.
 * @return         0 on success, -1 on error.
 */
static int build_peer_hit(const char *peername, const uint16_t port,
                          struct sockaddr_in6 *peer)
{
    if (!peername || !peer) {
        HIP_ERROR("Invalid input\n");
        return -1;
    }

    if (inet_pton(AF_INET6, peername, &peer->sin6_addr) != 1) {
        HIP_ERROR("Failed to translate %s into HIT\n", peername);
    }
    peer->sin6_port   = htons(port);
    peer->sin6_family = AF_INET6;
    return 0;
}

/**
 * Initialize libhipl library.
 *
 * This function should be called before using libhipl.
 *
 * @param debug_level the debug level of the libhipl library.
 * @return            0 on success, negative number on error.
 */
int hipl_lib_init_all(enum hipl_lib_loglv debug_level)
{
    hipl_hsock_init();
    switch (debug_level) {
    case HIPL_LIB_LOG_DEBUG:
        return hipl_lib_init(LOGDEBUG_ALL);
    case HIPL_LIB_LOG_INFO:
        return hipl_lib_init(LOGDEBUG_MEDIUM);
    case HIPL_LIB_LOG_ERROR:
        return hipl_lib_init(LOGDEBUG_LOW);
    case HIPL_LIB_LOG_NONE:
        return hipl_lib_init(LOGDEBUG_NONE);
    }

    return -1;
}

/**
 * Check the current state of the BEX feedback switch.
 *
 * @return true if the switch is on, false if it is off.
 */
bool hipl_lib_bex_feedback(void)
{
    return libhipl_bex_feedback;
}

/**
 * Turn the BEX feedback switch off/on.
 *
 * @param val true to turn the switch on, false to turn it off.
 */
void hipl_lib_set_bex_feedback(bool val)
{
    libhipl_bex_feedback = val;
}

/**
 * Turn the non-blocking feature on/off for a libhipl socket.
 *
 * @param hsock_id ID of the libhipl socket.
 * @param on       true to turn non-blocking on, false otherwise.
 * @return         0 on success, negative number on error.
 */
int hipl_lib_set_nonblock(const hipl_sock_id hsock_id, bool on)
{
    int               flags;
    struct hipl_sock *hsock = NULL;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket\n", hsock_id);
        return -EBADF;
    }

    flags = fcntl(hsock->sock_fd, F_GETFL, 0);
    if (on && !(flags & O_NONBLOCK)) {
        fcntl(hsock->sock_fd, F_SETFL, flags | O_NONBLOCK);
    } else if (!on && (flags & O_NONBLOCK)) {
        fcntl(hsock->sock_fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    return 0;
}

/**
 * Return the corresponding socket file descriptor of a libhipl socket.
 *
 * @param hsock_id the ID of the libhipl socket
 * @return         socket file descriptor on success, -1 on error.
 */
int hipl_lib_get_sockfd(const hipl_sock_id hsock_id)
{
    struct hipl_sock *hsock = NULL;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket\n", hsock_id);
        return -1;
    }

    return hsock->sock_fd;
}

/**
 * Save peer's HIT-to-IP mapping.
 *
 * @param hit  peer's hit.
 * @param addr peer's IP address.
 * @return     0 on success, -1 otherwise.
 */
int hipl_add_peer_info(const char *const hit, const char *const addr)
{
    struct in6_addr peer_hit, peer_addr6;
    struct in_addr  peer_addr4;

    if (!hit || !addr) {
        HIP_ERROR("Invalid argument\n");
        return -1;
    }
    if (inet_pton(AF_INET6, hit, &peer_hit) != 1) {
        HIP_ERROR("Invalid hit: %s\n", hit);
        return -1;
    }
    if (!ipv6_addr_is_hit(&peer_hit)) {
        HIP_ERROR("Invalid hit: %s\n", hit);
        return -1;
    }
    if (inet_pton(AF_INET6, addr, &peer_addr6) != 1) {
        if (inet_pton(AF_INET, addr, &peer_addr4) != 1) {
            HIP_ERROR("Invalid address: %s\n", addr);
            return -1;
        }
        IPV4_TO_IPV6_MAP(&peer_addr4, &peer_addr6);
    }

    return hip_hadb_add_peer_info(&peer_hit, &peer_addr6, NULL, NULL);
}

/**
 * Create a libhipl socket.
 *
 * @param domain    the domain of the libhipl socket (AF_INET / AF_INET6).
 * @param type      the type of the libhipl socket (SOCK_DGRAM / SOCK_STREAM).
 * @param protocol  the protocol (IPPROTO_UDP / IPPROTO_TCP).
 * @return          the ID of the new libhipl socket on success, negative
 *                  number on error.
 */
int hipl_socket(const int domain, const int type, const int protocol)
{
    if (domain != AF_INET && domain != AF_INET6) {
        HIP_ERROR("Invalid domain: %d\n", domain);
        return -EINVAL;
    }
    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        HIP_ERROR("Invalid type: %d\n", type);
        return -EINVAL;
    }
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
        HIP_ERROR("Invalid protocol: %d\n", protocol);
        return -EINVAL;
    }

    return hipl_socket_internal(domain, type, protocol);
}

/**
 * Close a socket.
 *
 * Send HIP CLOSE message to the associated peer and delete the libhipl
 * socket information.
 *
 * @param hsock_id the ID of the libhipl socket to be closed.
 * @return         0 on success, negative number on error.
 */
int hipl_close(const hipl_sock_id hsock_id)
{
    int                ret   = 0;
    struct hip_common *msg   = NULL;
    struct hipl_sock  *hsock = NULL;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket\n", hsock_id);
        return -1;
    }
    if (!hsock->ha || hsock->ha->state == HIP_STATE_CLOSED) {
        HIP_DEBUG("Not sending CLOSE.\n");
        goto skip_close_msg;
    }

    /* Build HIP_CLOSE message and send it to the peer */
    if ((msg = hip_msg_alloc()) == NULL) {
        HIP_ERROR("hip_msg_alloc() failed");
        ret = -ENOMEM;
        goto skip_close_msg;
    }
    if ((ret = hip_build_param_contents(msg, &hsock->peer_hit,
                                        HIP_PARAM_HIT,
                                        sizeof(hsock->peer_hit))) < 0) {
        HIP_ERROR("hip_build_param_contents() failed\n");
        goto skip_close_msg;
    }
    if ((ret = hip_send_close(msg, 1)) < 0) {
        HIP_ERROR("hip_send_close() failed\n");
    }

skip_close_msg:
    if (hsock) {
        close(hsock->sock_fd);
        hipl_hsock_delete_and_free(hsock);
    }
    free(msg);
    return ret;
}

/**
 * Bind a libhipl socket to a local IP address.
 *
 * @param hsock_id      the ID of the libhipl socket.
 * @param address       the IP address to be bound.
 * @param address_len   the length of the @c address.
 * @return              0 on success, negative number on error.
 */
int hipl_bind(const hipl_sock_id hsock_id, const struct sockaddr *const address,
              const socklen_t address_len)
{
    struct hipl_sock *hsock;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket\n", hsock_id);
        return -1;
    }

    return hipl_bind_internal(hsock, address, address_len);
}

/**
 * Switch a libhipl socket to listening mode.
 *
 * @param hsock_id the ID of the libhipl socket.
 * @param backlog  the max length of the queue for pending connections.
 * @return         zero on success, negative number on error.
 */
int hipl_listen(const hipl_sock_id hsock_id, const int backlog)
{
    struct hipl_sock *hsock;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket.\n", hsock_id);
        return -1;
    }

    return listen(hsock->sock_fd, backlog);
}

/**
 * Send data to a peer.
 *
 * Triggers base exchange if no HIP association exists.
 * @note Data is currently sent unencrypted.
 *
 * @param hsock_id  the ID of the libhipl socket for sending data.
 * @param msg       data to send.
 * @param len       size of the data.
 * @param flags     the flags of the socket function @c sendto().
 * @param peername  the string representation of the peer.
 * @param port      peer's port number.
 * @return          number of bytes sent on success, negative number on error.
 */
int hipl_sendto(const hipl_sock_id hsock_id, const void *const msg,
                const size_t len, const int flags,
                const char *const peername, uint16_t port)
{
    struct hipl_sock   *hsock;
    struct sockaddr_in6 peer;
    struct msghdr       params = { 0 };
    struct iovec        iov;
    char               *buf = NULL;
    int                 err = 0;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket.\n", hsock_id);
        return -1;
    }
    if (hsock->sock_proto == IPPROTO_UDP
        && (peername == NULL || build_peer_hit(peername, port, &peer) < 0)) {
        HIP_ERROR("Invalid argument: peername\n");
        return -EINVAL;
    }
    if (hsock->sock_proto == IPPROTO_TCP
        && hsock->peer_locator.ss_family == 0) {
        HIP_ERROR("Not connected!\n");
        return -ENOTCONN;
    }
    if (msg == NULL) {
        HIP_ERROR("Invalid argument: msg\n");
        return -EINVAL;
    }

    struct sockaddr_storage dst;
    struct sockaddr_in6    *p6;
    if (hsock->sock_proto == IPPROTO_UDP) {
        hipl_build_addrstorage(&peer.sin6_addr, ntohs(peer.sin6_port), &dst);
    } else {
        dst             = hsock->peer_locator;
        p6              = (struct sockaddr_in6 *) &dst;
        p6->sin6_addr   = hsock->peer_hit;
        p6->sin6_family = AF_INET6;
    }
    if ((buf = malloc(len)) == NULL) {
        return -ENOMEM;
    }
    memcpy(buf, msg, len);
    iov.iov_base       = buf;
    iov.iov_len        = len;
    params.msg_name    = &dst;
    params.msg_namelen = sizeof(dst);
    params.msg_iovlen  = 1;
    params.msg_iov     = &iov;

    if (hipl_lib_bex_feedback()) {
        err = hipl_sendmsg_internal(hsock, &params, flags);
    } else {
        fd_set fdset;
        if (hipl_hsock_ha_state(hsock) == HIP_STATE_UNASSOCIATED) {
            HIP_DEBUG("Sending via hsock %d, Triggering BEX.\n", hsock->sid);
            err = hipl_sendmsg_internal(hsock, &params, flags);
            HIP_IFEL(err != -EWAITBEX, -1, "hipl_sendmsg_internal() failed\n");
        }
        if (hipl_hsock_ha_state(hsock) == HIP_STATE_ESTABLISHED) {
            HIP_DEBUG("Sending via hsock %d, HA established.\n", hsock->sid);
            err = hipl_sendmsg_internal(hsock, &params, flags);
        } else {
            while (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED) {
                FD_ZERO(&fdset);
                FD_SET(hsock->sock_fd, &fdset);
                HIP_DEBUG("Sending via hsock %d, Waiting BEX.\n", hsock->sid);
                err = select(hsock->sock_fd + 1, &fdset, NULL, NULL, NULL);
                HIP_IFEL(err < 0, -1, "select(): %s\n", strerror(errno));
                err = hipl_sendmsg_internal(hsock, &params, flags);
                HIP_IFEL(err < 0 && err != -EWAITBEX && err != -EBEXESTABLISHED,
                         -1, "hipl_sendmsg_internal() failed\n");
            }
            err = hipl_sendmsg_internal(hsock, &params, flags);
        }
    }

out_err:
    free(buf);
    return err;
}

/**
 * Receive data from a peer.
 *
 * Wait for base exchange if no host association exists.
 * @note Data is currently sent unencrypted.
 *
 * @param hsock_id  the ID of the libhipl socket for receiving data.
 * @param buf       buffer for received data.
 * @param len       the size of the @c buf.
 * @param flags     the flags of the socket function @c recvfrom().
 * @param peername  buffer for the HIT of the associated peer, the size of
 *                  this buffer should be at least @c HIPL_MAX_PEERNAME.
 * @param port      buffer for the port of the associated peer.
 * @return          number of bytes received on success,
 *                  negative number on error,
 *                  0 on end-of-file.
 */
int hipl_recvfrom(const hipl_sock_id hsock_id, void *const buf,
                  const size_t len, const int flags,
                  char *const peername, uint16_t *const port)
{
    struct hipl_sock   *hsock  = NULL;
    struct msghdr       params = { 0 };
    struct iovec        iov;
    struct sockaddr_in6 hit;
    int                 ret;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket.\n", hsock_id);
        return -1;
    }
    if (hsock->sock_proto == IPPROTO_TCP
        && hsock->peer_locator.ss_family == 0) {
        HIP_ERROR("Not connected!\n");
        return -ENOTCONN;
    }

    iov.iov_base       = buf;
    iov.iov_len        = len;
    params.msg_name    = &hit;
    params.msg_namelen = sizeof(hit);
    params.msg_iovlen  = 1;
    params.msg_iov     = &iov;

    if (!hipl_lib_bex_feedback()) {
        fd_set fdset;
        while (hipl_hsock_ha_state(hsock) != HIP_STATE_ESTABLISHED) {
            FD_ZERO(&fdset);
            FD_SET(hsock->sock_fd, &fdset);
            if (select(hsock->sock_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
                HIP_PERROR("select()");
            }
            ret = hipl_recvmsg_internal(hsock, &params, flags);
            if (ret < 0 && ret != -EWAITBEX && ret != -EBEXESTABLISHED) {
                HIP_ERROR("hipl_recvmsg_internal() failed()\n");
                return ret;
            }
        }
    }
    ret = hipl_recvmsg_internal(hsock, &params, flags);

    if (peername) {
        inet_ntop(AF_INET6, &hit.sin6_addr, peername, HIPL_MAX_PEERNAME);
    }
    if (port) {
        *port = ntohs(hit.sin6_port);
    }
    return ret;
}

/**
 * Initiate a connection to a peer.
 *
 * @param hsock_id   the ID of the libhipl socket to initiate a connection.
 * @param peername   the string representation of the peer.
 * @param port       the port number of the peer.
 * @return           0 on success, negative number on error.
 */
int hipl_connect(const hipl_sock_id hsock_id, const char *peername,
                 const uint16_t port)
{
    struct hipl_sock   *hsock = NULL;
    struct sockaddr_in6 peer;

    if (peername == NULL || build_peer_hit(peername, port, &peer) < 0) {
        HIP_ERROR("Invalid argument: peername\n");
        return -EINVAL;
    }
    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket.\n", hsock_id);
        return -1;
    }

    return hipl_connect_internal(hsock, &peer);
}

/**
 * Wait for an incoming connection.
 *
 * @param hsock_id the ID of the libhipl socket for waiting connections.
 * @return         the ID of the accepted libhipl socket, negative number
 *                 on error.
 */
int hipl_accept(const hipl_sock_id hsock_id)
{
    struct hipl_sock *hsock = NULL;

    if ((hsock = hipl_hsock_find(hsock_id)) == NULL) {
        HIP_ERROR("ID %d is not a libhipl socket.\n", hsock_id);
        return -1;
    }

    return hipl_accept_internal(hsock);
}
