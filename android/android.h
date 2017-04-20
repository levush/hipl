/*
 * Copyright (c) 2013 Aalto University and RWTH Aachen University.
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

#include "config.h"

#ifdef CONFIG_HIP_ANDROID
#ifndef HIPL_ANDROID_ANDROID_H
#define HIPL_ANDROID_ANDROID_H

#include <stdint.h>

/* Logging */
#define ALOGE printf

/* System properties */
#define PROPERTY_KEY_MAX 32

/* Networking */
#define HOST_NAME_MAX 64
typedef uint16_t in_port_t;

/* Filters for ICMP6
 * The definitions in Android NDK are wrong. Using them causes
 * the Heartbeat extension to miss all ICMP6_ECHO_REPLY messages.
 * Missing the messages makes Heartbeat think that the connection
 * is stale. It will first try to fix it with UPDATE and as it still
 * can't see replies, after a couple of tries it will remove the SA
 * for the "unrecovered" stale connection.
 */
#undef ICMP6_FILTER
#undef ICMP6_FILTER_SETBLOCK
#undef ICMP6_FILTER_SETBLOCKALL
#undef ICMP6_FILTER_SETPASS
#undef ICMP6_FILTER_SETPASSALL
#undef ICMP6_FILTER_WILLBLOCK
#undef ICMP6_FILTER_WILLPASS

#define ICMP6_FILTER 1
#define ICMP6_FILTER_SETBLOCK(type, filterp)  \
        ((((filterp)->icmp6_filt[(type) >> 5]) |=  (1 << ((type) & 31))))
#define ICMP6_FILTER_SETBLOCKALL(filterp)     \
        memset (filterp, 0xFF, sizeof(struct icmp6_filter));
#define ICMP6_FILTER_SETPASS(type, filterp)   \
        ((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31))))
#define ICMP6_FILTER_SETPASSALL(filterp)      \
        memset (filterp, 0x00, sizeof(struct icmp6_filter));
#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
        ((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) != 0)
#define ICMP6_FILTER_WILLPASS(type, filterp)  \
        ((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) == 0)

#endif /* HIPL_ANDROID_ANDROID_H */
#endif /* CONFIG_HIP_ANDROID */
