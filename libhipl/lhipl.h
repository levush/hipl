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

#ifndef HIPL_LIB_HIPL_LHIPL_H
#define HIPL_LIB_HIPL_LHIPL_H

#include <sys/socket.h>
#include <stdbool.h>
#include <stdint.h>


#define EWAITBEX        139000
#define EBEXESTABLISHED 139001

#define HIPL_MAX_PEERNAME 128

enum hipl_lib_loglv { HIPL_LIB_LOG_DEBUG, HIPL_LIB_LOG_INFO,
                      HIPL_LIB_LOG_ERROR, HIPL_LIB_LOG_NONE };

typedef uint16_t hipl_sock_id;

int hipl_lib_init_all(enum hipl_lib_loglv);

void hipl_lib_set_bex_feedback(bool val);
bool hipl_lib_bex_feedback(void);

int hipl_lib_set_nonblock(const hipl_sock_id hsock_id, bool on);
int hipl_lib_get_sockfd(const hipl_sock_id hsock_id);

int hipl_add_peer_info(const char *const hit, const char *const addr);

int hipl_socket(const int domain, const int type, const int protocol);

int hipl_close(const hipl_sock_id hsock_id);

int hipl_listen(const hipl_sock_id hsock_id, const int backlog);

int hipl_bind(const hipl_sock_id hsock_id, const struct sockaddr *const address,
              const socklen_t address_len);

int hipl_sendto(const hipl_sock_id hsock_id, const void *const msg,
                const size_t len, const int flags,
                const char *const peername, const uint16_t port);

int hipl_recvfrom(const hipl_sock_id hsock_id, void *const buf,
                  const size_t len, const int flags,
                  char *const peername, uint16_t *const port);

int hipl_connect(const hipl_sock_id hsock_id, const char *const peername,
                 const uint16_t port);

int hipl_accept(const hipl_sock_id hsock_id);

#endif /* HIPL_LIB_HIPL_LHIPL_H */
