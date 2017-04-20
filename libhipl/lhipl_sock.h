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

#ifndef HIPL_LIB_HIPL_LHIPL_SOCK_H
#define HIPL_LIB_HIPL_LHIPL_SOCK_H

#include <limits.h>

#include "libcore/protodefs.h"
#include "libcore/state.h"


#define HIPL_LIB_HSOCK_ID_MIN  1
#define HIPL_LIB_HSOCK_ID_MAX  USHRT_MAX
#define HIPL_LIB_HSOCK_MAX     1024

/* The internal information about each libhipl socket.
 *
 * It is generated when a new libhipl socket is created.
 */
struct hipl_sock {
    uint16_t                sid;           /* libhipl socket ID */
    struct hip_hadb_state  *ha;
    hip_hit_t               peer_hit;
    struct sockaddr_storage peer_locator;
    hip_hit_t               src_hit;       /* our HIT */
    int                     src_port;      /* our port number */
    int                     sock_fd;       /* underlying socket */
    int                     sock_family;
    int                     sock_type;
    int                     sock_proto;
};

void hipl_hsock_init(void);

enum hip_state hipl_hsock_ha_state(const struct hipl_sock *const hsock);

struct hipl_sock *hipl_hsock_new(const int family, const int type,
                                 const int protocol);

struct hipl_sock *hipl_hsock_find(const uint16_t hsock_id);

void hipl_hsock_delete_and_free(struct hipl_sock *const hsock);

#endif /* HIPL_LIB_HIPL_LHIPL_SOCK_H */
