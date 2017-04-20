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
 * @brief Tests of libhipl on localhost (see doc/HACKING on unit tests).
 */

#include <arpa/inet.h>
#include <check.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "libhipl/hidb.h"
#include "libhipl/lhipl.h"

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define LO_IP    "127.0.0.1"
#define TEST_MSG "Hello Sailor!"
#define SEND_PORT 22345
#define RECV_PORT 22300

static struct in6_addr    lo_hit;
static char               peername[HIPL_MAX_PEERNAME];
static struct sockaddr_in send_addr;
static struct sockaddr_in recv_addr;

static int sender;
static int receiver;

static void test_libhipl_lo_init(int proto)
{
    if (hipl_lib_init_all(HIPL_LIB_LOG_NONE) < 0) {
        fail("hipl_lib_init_all");
    }

    fail_if(hip_get_default_hit(&lo_hit) < 0, "Failed to load local hit");
    inet_ntop(AF_INET6, &lo_hit, peername, HIPL_MAX_PEERNAME);
    fail_if(hipl_add_peer_info(peername, LO_IP) < 0,
            "Failed to insert peer info");

    send_addr.sin_family = AF_INET;
    inet_pton(AF_INET, LO_IP, &send_addr.sin_addr);
    send_addr.sin_port   = htons(SEND_PORT);
    recv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, LO_IP, &recv_addr.sin_addr);
    recv_addr.sin_port = htons(RECV_PORT);

    if (proto == IPPROTO_TCP) {
        sender   = hipl_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        receiver = hipl_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    } else if (proto == IPPROTO_UDP) {
        sender   = hipl_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        receiver = hipl_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    fail_if(sender <= 0 || receiver <= 0);

    if (hipl_bind(sender, (struct sockaddr *) &send_addr,
                  sizeof(send_addr)) < 0) {
        fail("hipl_bind() for sender");
    }
    if (hipl_bind(receiver, (struct sockaddr *) &recv_addr,
                  sizeof(recv_addr)) < 0) {
        fail("hipl_bind() for receiver");
    }

    hipl_lib_set_bex_feedback(true);
}

static void test_libhipl_lo_main_loop(int send_hid, int recv_hid)
{
    char     peer[HIPL_MAX_PEERNAME];
    uint16_t peer_port;
    char     buf[1024];
    fd_set   rset;
    int      ret   = 0;
    int      maxfd = max(hipl_lib_get_sockfd(send_hid),
                         hipl_lib_get_sockfd(recv_hid));

    //trigger BEX
    ret = hipl_sendto(send_hid, TEST_MSG, strlen(TEST_MSG), 0,
                      peername, RECV_PORT);
    fail_if(ret != -EWAITBEX);

    while (1) {
        FD_ZERO(&rset);
        FD_SET(hipl_lib_get_sockfd(send_hid), &rset);
        FD_SET(hipl_lib_get_sockfd(recv_hid), &rset);
        fail_if(select(maxfd + 1, &rset, NULL, NULL, NULL) < 0);

        if (FD_ISSET(hipl_lib_get_sockfd(recv_hid), &rset)) {
            ret = hipl_recvfrom(recv_hid, buf, 1024, 0, peer, &peer_port);
            fail_if(ret < 0 && ret != -EWAITBEX && ret != -EBEXESTABLISHED);
            fail_if(ret > 0 && ret != strlen(TEST_MSG));

            if (ret == strlen(TEST_MSG)) {
                buf[ret] = '\0';
                fail_if(strcmp(buf, TEST_MSG) != 0);
                fail_if(strcmp(peername, peer) != 0);
                fail_if(peer_port != SEND_PORT);
                // Finish test
                break;
            }
        }
        if (FD_ISSET(hipl_lib_get_sockfd(send_hid), &rset)) {
            ret = hipl_sendto(send_hid, TEST_MSG, strlen(TEST_MSG), 0,
                              peername, RECV_PORT);
            fail_if(ret < 0 && ret != -EWAITBEX && ret != -EBEXESTABLISHED);
            fail_if(ret > 0 && ret != strlen(TEST_MSG));
        }
    }

    hipl_close(send_hid);
    hipl_close(recv_hid);
}

START_TEST(test_libhipl_lo_tcp)
{
    fd_set wset, rset;
    int    maxfd, recv_slave = 0;

    test_libhipl_lo_init(IPPROTO_TCP);

    // Setup TCP connection
    maxfd = max(hipl_lib_get_sockfd(sender), hipl_lib_get_sockfd(receiver));
    if (hipl_listen(receiver, 5) < 0) {
        fail("hipl_listen()");
    }
    fail_if(hipl_lib_set_nonblock(sender, true) < 0);
    fail_if(hipl_lib_set_nonblock(receiver, true) < 0);
    hipl_accept(receiver);
    hipl_connect(sender, peername, RECV_PORT);
    while (recv_slave <= 0) {
        FD_ZERO(&wset);
        FD_ZERO(&rset);
        FD_SET(hipl_lib_get_sockfd(sender), &wset);
        FD_SET(hipl_lib_get_sockfd(receiver), &rset);
        fail_if(select(maxfd + 1, &rset, &wset, NULL, NULL) < 0);
        if (FD_ISSET(hipl_lib_get_sockfd(receiver), &rset)) {
            if ((recv_slave = hipl_accept(receiver)) < 0) {
                fail("hipl_accept(), %s", strerror(errno));
            }
        }
        if (FD_ISSET(hipl_lib_get_sockfd(sender), &wset)) {
            if (hipl_connect(sender, peername, RECV_PORT) < 0
                && errno != EINPROGRESS && errno != EISCONN) {
                fail("hipl_connect() %s", strerror(errno));
            }
        }
    }
    fail_if(hipl_connect(sender, peername, RECV_PORT) < 0 && errno != EISCONN);
    fail_if(hipl_lib_set_nonblock(sender, false) < 0);

    // Process base exchange and user data
    test_libhipl_lo_main_loop(sender, recv_slave);
    hipl_close(receiver);
}
END_TEST

START_TEST(test_libhipl_lo_udp)
{
    test_libhipl_lo_init(IPPROTO_UDP);
    test_libhipl_lo_main_loop(sender, receiver);
}
END_TEST

static Suite *hipnc_suite(void)
{
    Suite *s = suite_create("libhipl");

    TCase *tc_libhipl_lo = tcase_create("libhipl_lo");
    tcase_add_test(tc_libhipl_lo, test_libhipl_lo_udp);
    tcase_add_test(tc_libhipl_lo, test_libhipl_lo_tcp);
    suite_add_tcase(s, tc_libhipl_lo);

    return s;
}

int main(void)
{
    int      number_failed;
    Suite   *s  = hipnc_suite();
    SRunner *sr = srunner_create(NULL);

    srunner_add_suite(sr, s);
    srunner_run_all(sr, CK_NORMAL);

    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
