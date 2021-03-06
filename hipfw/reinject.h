/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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

#ifndef HIPL_HIPFW_REINJECT_H
#define HIPL_HIPFW_REINJECT_H

#include <stdint.h>
#include <netinet/in.h>

void hipfw_init_raw_sockets(void);
int hipfw_send_outgoing_pkt(const struct in6_addr *src_hit,
                            const struct in6_addr *dst_hit,
                            uint8_t *msg, uint16_t len, int proto);
int hipfw_send_incoming_pkt(const struct in6_addr *src_hit,
                            const struct in6_addr *dst_hit,
                            uint8_t *msg, uint16_t len,
                            int proto, int ttl);

#endif /* HIPL_HIPFW_REINJECT_H*/
