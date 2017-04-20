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

#ifndef HIPL_LIB_HIPL_LHIPL_OPERATIONS_H
#define HIPL_LIB_HIPL_LHIPL_OPERATIONS_H

#include "lhipl_sock.h"


int hipl_socket_internal(const int family, const int type, const int protocol);

int hipl_bind_internal(struct hipl_sock *const hsock,
                       const struct sockaddr *const address,
                       const socklen_t address_len);

int hipl_connect_internal(struct hipl_sock *const hsock,
                          const struct sockaddr_in6 *const addr);

int hipl_accept_internal(struct hipl_sock *const hsock);

ssize_t hipl_recvmsg_internal(struct hipl_sock *const hsock,
                              struct msghdr *const msg,
                              const int flags);

ssize_t hipl_sendmsg_internal(struct hipl_sock *const hsock,
                              struct msghdr *const msg,
                              const int flags);

void hipl_build_addrstorage(const struct in6_addr *const addr,
                            const uint16_t port,
                            struct sockaddr_storage *const ss);

#endif /* HIPL_LIB_HIPL_LHIPL_OPERATIONS_H */
