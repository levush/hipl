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

#ifndef HIPL_LIBHIPL_HIP_SOCKET_H
#define HIPL_LIBHIPL_HIP_SOCKET_H

#include <stdint.h>
#include <sys/select.h>
#include "libcore/protodefs.h"

extern int hip_raw_sock_input_v6;
extern int hip_raw_sock_input_v4;
extern int hip_nat_sock_input_udp;
extern int hip_nat_sock_input_udp_v6;
extern int hip_user_sock;

void hip_register_sockets(void);

void hip_unregister_sockets(void);

int hip_register_socket(int socketfd,
                        int (*func_ptr)(struct hip_packet_context *ctx),
                        const uint16_t priority);

int hip_get_highest_descriptor(void);

void hip_prepare_fd_set(fd_set *read_fdset);

void hip_run_socket_handles(fd_set *read_fdset, struct hip_packet_context *ctx);

#endif /* HIPL_LIBHIPL_HIP_SOCKET_H */
