/*
 * Copyright (c) 2014 Aalto University and RWTH Aachen University.
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

#define _BSD_SOURCE

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "libcore/checksum.h"
#include "test/libcore/test_suites.h"
#include "libcore/protodefs.h"
#include "libcore/builder.h"
#include "libcore/straddr.h"
#include "libcore/crypto.h"

const char *src_hit_test_str_v1 = "2001:10::1",
           *dst_hit_test_str_v1 = "2001:10::2";

const char *src_ipv4_test_str = "192.168.0.1",
           *dst_ipv4_test_str = "192.168.0.2";
const char *src_ipv6_test_str = "::192.168.0.1",
           *dst_ipv6_test_str = "::192.168.0.2";

const char *src_hit_test_str_v2 = "2001:20::1",
           *dst_hit_test_str_v2 = "2001:20::2";

const char *src_ipv4_test_bis_str = "192.0.2.1",
           *dst_ipv4_test_bis_str = "192.0.2.2";
const char *src_ipv6_test_bis_str = "2001:db8::1",
           *dst_ipv6_test_bis_str = "2001:db8::2";

inline static void *ipv4_payload(struct ip *const ipv4)
{
    return ((uint8_t *) ipv4) + 4 * ipv4->ip_hl;
}

const uint8_t HIP_DH_GROUP_LIST_TEST[HIP_DH_GROUP_LIST_SIZE] = {
    HIP_DH_OAKLEY_5,
    HIP_DH_OAKLEY_15,
    HIP_DH_NIST_P_384
};

static uint16_t calculate_checksum(uint8_t proto_version,
                                   const char *src_hit_str,
                                   const char *dst_hit_str,
                                   const char *src_addr_str,
                                   const char *dst_addr_str)
{
    struct hip_common *i1 = NULL;
    hip_hit_t src_hit, dst_hit;
    struct sockaddr_in6 src_addr, dst_addr;
    uint16_t checksum = 0;

    fail_unless(((i1 = hip_msg_alloc()) != NULL), "msg alloc");

    fail_unless(inet_pton(AF_INET6, src_hit_str, &src_hit), "inet_pton");
    fail_unless(inet_pton(AF_INET6, dst_hit_str, &dst_hit), "inet_pton");

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));
    src_addr.sin6_family = AF_INET6;
    dst_addr.sin6_family = AF_INET6;

    fail_unless((hip_convert_string_to_address(src_addr_str,
                                               &src_addr.sin6_addr) == 0),
                "str conv");
    fail_unless((hip_convert_string_to_address(dst_addr_str,
                                               &dst_addr.sin6_addr) == 0),
                "str conv");

    HIP_DEBUG_IN6ADDR("src ip", &src_addr.sin6_addr);
    HIP_DEBUG_IN6ADDR("dst ip", &dst_addr.sin6_addr);

    hip_build_network_hdr(i1, HIP_I1, 0, &src_hit, &dst_hit, proto_version);
    hip_zero_msg_checksum(i1);
    hip_calc_hdr_len(i1);

    if (proto_version == HIP_V2) { /* Build DH_GROUP_LIST for HIPv2 */
        uint8_t dh_group[3];

        memcpy(dh_group, HIP_DH_GROUP_LIST_TEST, sizeof(dh_group));

        fail_unless((hip_build_param_list(i1, HIP_PARAM_DH_GROUP_LIST, dh_group,
                                          sizeof(dh_group), sizeof(uint8_t)) == 0),
                    "dh group list");
    }

    i1->checksum = hip_checksum_packet((char *) i1,
                                       (struct sockaddr *) &src_addr,
                                       (struct sockaddr *) &dst_addr);
    checksum = i1->checksum;

    HIP_DUMP_MSG(i1);

    fail_unless((hip_verify_network_header(i1,
                                           (struct sockaddr *) &src_addr,
                                           (struct sockaddr *) &dst_addr,
                                           hip_get_msg_total_len(i1) == 0)),
                "verify network header");

    return checksum;
}

START_TEST(test_ipv4_checksum_udp_hip_encap)
{
    // IP + UDP + HIP frame {{{
    char pcap[] = "\x45\x00\x02\xa8\x00\x00\x40\x00\x3f\x11\xb4\xf2\xc0\xa8\x02\x01"
                  "\xc0\xa8\x01\x01\x29\x04\x29\x04\x02\x94\x1b\x0e\x00\x00\x00\x00"
                  "\x3b\x50\x02\x11\x00\x00\x00\x00\x20\x01\x00\x10\xf0\x39\x6b\xc5"
                  "\xca\xb3\x07\x27\x7f\xbc\x9d\xcb\x20\x01\x00\x12\xbd\x2d\xd2\x3e"
                  "\x4a\x09\xb2\xab\x64\x14\xe1\x10\x01\x01\x00\x0c\x01\x2a\x48\x49"
                  "\x6a\xfc\xdb\xf7\x8d\x5b\xa0\x77\x02\x01\x00\xf6\x03\x00\xc0\x5e"
                  "\x55\x3a\x6c\x5c\xef\x01\x9c\x40\xd3\x14\x93\xdf\x50\x53\x4b\xa6"
                  "\x00\xe1\x81\x4d\xb5\x7d\xd2\x28\x84\x88\x0f\xc0\x5f\x03\xee\xb3"
                  "\x7d\x55\x7f\x61\xbe\xce\x4e\xec\xd3\xab\x75\x14\x1a\x8b\x34\x5b"
                  "\xb1\x98\x53\xe1\xff\x46\x9b\x2f\x86\xe3\x7b\xd2\x13\x21\xdf\xed"
                  "\x21\x2c\xbd\xd9\x5c\x38\xfe\x7a\x9f\x49\x3c\x64\x4d\x76\x50\x74"
                  "\x54\xa3\x15\xa4\x28\x31\x41\xfa\xde\x2e\x5f\xb2\xdc\xef\xf6\x10"
                  "\x66\xe0\xad\x56\xf3\x05\xd0\x97\x32\x91\xbf\x6c\xa2\xef\xef\xc8"
                  "\x9b\x6e\x5d\x86\x70\xa6\x27\xf7\x5b\x49\xc7\x55\x11\x53\x2f\xb1"
                  "\x47\xb1\x23\xe9\x07\xea\x8f\x4a\x2e\xc4\x4e\x0d\x33\x32\x94\xb7"
                  "\x23\xb6\xb0\xf5\x58\x92\xe5\xed\x24\xa6\xdc\x3b\x10\xa6\x70\xaf"
                  "\x22\xfa\x11\xe1\x1e\xa1\x51\x5b\xed\x84\xfd\xea\x71\x59\xc0\x86"
                  "\x72\x55\x3e\x25\x19\x7a\x96\x9e\xce\x8f\x01\x90\x6d\x1b\x73\x01"
                  "\x00\x30\x39\x95\x76\xb5\x07\x95\x69\x98\x01\x82\x95\x92\x41\x87"
                  "\x2d\x69\x2d\x09\x00\xce\x72\x79\xe4\x2e\x0d\xce\x5c\xb2\x5c\x96"
                  "\x3a\x72\x1e\x95\x35\x85\x47\xde\x77\xdf\xcd\xc8\xbe\x1a\xed\x07"
                  "\x86\x21\x00\x00\x00\x00\x00\x00\x02\x41\x00\x06\x00\x01\x00\x02"
                  "\x00\x05\x00\x00\x00\x00\x00\x00\x02\xc1\x00\x92\x00\x88\x10\x06"
                  "\x02\x02\xff\x05\x03\x01\x00\x01\xdc\x7d\x6b\x0a\x3c\x92\xff\x34"
                  "\x7b\xae\x6a\x6d\xd0\x0a\xa0\xf5\x60\x23\xa9\x69\xbf\xaf\xfb\xc1"
                  "\xa9\xa0\xd4\xfc\x96\xc7\x4b\x5e\xc0\x8b\x2d\x3d\x27\x83\x8a\x75"
                  "\x03\xa9\x99\xf2\x69\x5d\x84\x2f\xe9\xda\xc1\x48\x85\xd0\xa2\x09"
                  "\x0d\x35\x79\xc1\x29\x39\x57\x14\x9c\xf8\x57\x9a\x8f\x8c\xe4\xf1"
                  "\xfe\xef\x6b\x5c\x3f\x21\x40\xcf\x37\xcf\xba\x91\x58\x09\xc3\x7e"
                  "\xb3\xcc\xfd\xee\x1a\xde\x5b\xa4\xe4\xa4\xc8\x08\x29\xe5\x9c\x44"
                  "\x82\x41\xd5\x74\xe8\xd8\x47\x1d\x00\x14\x83\x38\x10\xb8\xa6\xfa"
                  "\x34\x9d\xcb\x62\x0c\xdb\x26\x33\x70\x69\x73\x61\x32\x00\x00\x00"
                  "\x0f\xff\x00\x08\x00\x00\x00\x01\x00\x02\x00\x05\x00\x00\x00\x00"
                  "\xf0\xc1\x00\x81\x05\xdc\x2c\x37\xed\x80\xea\x04\xee\xe9\x3a\x5d"
                  "\x36\x83\x53\x6f\x2e\xaf\x8d\x06\x94\x5d\xf1\x93\xfc\xa4\xd7\xbe"
                  "\xc4\xed\x8f\x8f\x5c\xc4\xa1\x66\x78\x70\x82\xae\xad\x12\xcd\x7f"
                  "\x9a\x7c\xda\xed\xb9\x08\x4e\x62\xfc\xea\xed\x3b\x53\x3d\x3f\x97"
                  "\x7d\xeb\x7b\x05\xf9\xc5\x38\x36\x3f\x4c\x9e\xb1\x0b\x96\xe6\x93"
                  "\x65\x38\x5a\x7c\x97\x03\x4d\xea\x7a\xe4\x1d\xa5\xf2\x4f\x01\x2c"
                  "\x86\x70\x6b\xc8\xee\x4f\x64\xa9\xf2\xf9\x66\x66\x36\x7c\xbe\xb5"
                  "\xf5\x3e\xd8\x58\x97\xfc\xb3\x75\x3b\xd2\x1d\xdc\x75\xcc\xc8\x41"
                  "\x52\x49\x25\x1b\x9b\x00\x00\x00\xff\x36\x00\x06\x01\x02\xaa\xbb"
                  "\xcc\xdd\x00\x00\x00\x00\x00\x00";
    // }}}

    struct ip     *const ipv4 = (struct ip *) pcap;
    struct udphdr *const udp  = ipv4_payload(ipv4);

    ipv4->ip_sum = 0;
    ipv4->ip_sum = checksum_ip(ipv4, ipv4->ip_hl);
    udp->check   = 0;
    udp->check   = ipv4_checksum(IPPROTO_UDP, &ipv4->ip_src, &ipv4->ip_dst,
                                 udp, ntohs(udp->len));

    fail_unless(ipv4->ip_sum == htons(0xb4f2),
                "Incorrect IPv4 header checksum calculated");
    fail_unless(udp->check == htons(0x7e05),
                "Incorrect udp checksum calculated");
}
END_TEST

START_TEST(test_ipv4_checksum_hipv1)
{
    fail_unless(calculate_checksum(HIP_V1,
                                   src_hit_test_str_v1,
                                   dst_hit_test_str_v1,
                                   src_ipv6_test_str,
                                   dst_ipv6_test_str) == ntohs(446));
}
END_TEST

START_TEST(test_ipv6_checksum_hipv1)
{
    fail_unless(calculate_checksum(HIP_V1,
                                   src_hit_test_str_v1,
                                   dst_hit_test_str_v1,
                                   src_ipv6_test_str,
                                   dst_ipv6_test_str) == ntohs(446));
}
END_TEST

START_TEST(test_ipv4_checksum_hipv2)
{
    fail_unless(calculate_checksum(HIP_V2,
                                   src_hit_test_str_v2,
                                   dst_hit_test_str_v2,
                                   src_ipv4_test_bis_str,
                                   dst_ipv4_test_bis_str) == ntohs(61902));
}
END_TEST

START_TEST(test_ipv6_checksum_hipv2)
{
    fail_unless(calculate_checksum(HIP_V2,
                                   src_hit_test_str_v2,
                                   dst_hit_test_str_v2,
                                   src_ipv6_test_bis_str,
                                   dst_ipv6_test_bis_str) == ntohs(6750));
}
END_TEST

Suite *libcore_gpl_checksum(void)
{
    Suite *s = suite_create("libcore/checksum");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_ipv4_checksum_udp_hip_encap);
    tcase_add_test(tc_core, test_ipv4_checksum_hipv1);
    tcase_add_test(tc_core, test_ipv6_checksum_hipv1);
    tcase_add_test(tc_core, test_ipv4_checksum_hipv2);
    tcase_add_test(tc_core, test_ipv6_checksum_hipv2);
    suite_add_tcase(s, tc_core);

    return s;
}
