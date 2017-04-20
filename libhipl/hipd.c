/*
 * Copyright (c) 2010-2013 Aalto University and RWTH Aachen University.
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
 * The HIPL main file containing the daemon main loop.
 *
 * @note HIPU: libm.a is not availble on OS X. The functions are present in libSystem.dyld, though
 * @note HIPU: lcap is used by HIPD. It needs to be changed to generic posix functions.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "android/android.h"
#include "libcore/builder.h"
#include "libcore/common.h"
#include "libcore/conf.h"
#include "libcore/debug.h"
#include "libcore/filemanip.h"
#include "libcore/hashtable.h"
#include "libcore/icomm.h"
#include "libcore/ife.h"
#include "libcore/performance.h"
#include "libcore/protodefs.h"
#include "libcore/straddr.h"
#include "libcore/util.h"
#include "config.h"
#include "accessor.h"
#include "hadb.h"
#include "hip_socket.h"
#include "init.h"
#include "maintenance.h"
#include "netdev.h"
#include "hipd.h"

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec;

/** For getting/setting routes and adding HITs (it was not possible to use
 *  nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route;

int lsi_status = HIP_MSG_LSI_OFF;

/* The timeout for the select call in the main loop. */
static struct timeval select_timeout;
/* Shortest backoff (in microseconds) of all retransmissions of all HAs.
 * Used to determine the required select timeout. */
static uint64_t shortest_backoff;

/**
 * print hipd usage instructions on stderr
 */
static void usage(void)
{
    fprintf(stderr, "Usage: hipd [options]\n\n");
    fprintf(stderr, "  -V print version information and exit\n");
    fprintf(stderr, "  -b run in background\n");
    fprintf(stderr, "  -i <device name> add interface to the white list. "
                    "Use additional -i for additional devices.\n");
    fprintf(stderr, "  -k kill existing hipd\n");
    fprintf(stderr, "  -N do not flush all IPsec databases during start\n");
    fprintf(stderr, "  -a fix alignment issues automatically(ARM)\n");
    fprintf(stderr, "  -f set debug type format to short\n");
    fprintf(stderr, "  -d set the initial (pre-config) debug level to ALL (default is LOW)\n");
    fprintf(stderr, "  -D <module name> disable this module. "
                    "Use additional -D for additional modules.\n");
    fprintf(stderr, "  -p disable privilege separation\n");
    fprintf(stderr, "  -m disable the loading/unloading of kernel modules\n");
    fprintf(stderr, "\n");
}

/**
 * Parse the command line options
 * @param argc  number of command line parameters
 * @param argv  command line parameters
 * @param flags pointer to the startup flags container
 * @return      nonzero if the caller should exit, 0 otherwise
 */
int hipd_parse_cmdline_opts(int argc, char *argv[], uint64_t *flags)
{
    int c;

    while ((c = getopt(argc, argv, ":bi:kNchafVdD:pm")) != -1) {
        switch (c) {
        case 'b':
            /* run in the "background" */
            *flags &= ~HIPD_START_FOREGROUND;
            break;
        case 'i':
            if (hip_netdev_white_list_add(optarg)) {
                HIP_INFO("Successfully added device <%s> to white list.\n", optarg);
            } else {
                HIP_DIE("Error adding device <%s> to white list. Dying...\n", optarg);
            }
            break;
        case 'k':
            *flags |= HIPD_START_KILL_OLD;
            break;
        case 'N':
            /* do NOT flush IPsec DBs */
            *flags &= ~HIPD_START_FLUSH_IPSEC;
            break;
        case 'c':
            *flags |= HIPD_START_CREATE_CONFIG_AND_EXIT;
            break;
        case 'a':
            *flags |= HIPD_START_FIX_ALIGNMENT;
            break;
        case 'f':
            HIP_INFO("Setting output format to short\n");
            hip_set_logfmt(LOGFMT_SHORT);
            break;
        case 'd':
            hip_set_logdebug(LOGDEBUG_ALL);
            break;
        case 'D':
            if (!lmod_disable_module(optarg)) {
                HIP_DEBUG("Module '%s' disabled.\n", optarg);
            } else {
                HIP_ERROR("Error while disabling module '%s'.\n", optarg);
            }
            break;
        case 'p':
            /* do _not_ use low capabilies ("privilege separation") */
            *flags &= ~HIPD_START_LOWCAP;
            break;
        case 'm':
            /* do _not_ load/unload kernel modules/drivers */
            *flags &= ~HIPD_START_LOAD_KMOD;
            break;
        case 'V':
            hip_print_version("hipd");
            return -1;
        case '?':
        case 'h':
        default:
            usage();
            return -1;
        }
    }

    return 0;
}

/**
 * Determine the lowest retransmission backoff of all retransmissions in the
 * given host association.
 *
 * Note: The lowest retransmission backoff will be written to the static
 *       variable shortest_backoff. The caller is responsible for initializing
 *       this variable as the actual retransmission backoffs are compared
 *       against it.
 *
 * @param hadb The hadb state from which the lowest retransmission backoff will
 *             be determined.
 * @param opaq UNUSED.
 *
 * @return Always 0. Not void because hip_for_each_ha() requires a return value.
 */
static int get_shortest_retrans_backoff(struct hip_hadb_state *hadb, UNUSED void *opaq)
{
    for (unsigned int i = 0; i < HIP_RETRANSMIT_QUEUE_SIZE; i++) {
        struct hip_msg_retrans *retrans = &hadb->hip_msg_retrans[i];

        if (shortest_backoff == HIP_RETRANSMIT_BACKOFF_MIN) {
            break;
        } else if (retrans->count > 0 && retrans->current_backoff < shortest_backoff) {
            shortest_backoff = retrans->current_backoff;
        }
    }

    return 0;
}

/**
 * Update the select timeout with respect to the currently outstanding
 * retransmissions. If there are no retransmissions the timeout will be
 * set to the HIP_SELECT_TIMEOUT default value. Else it will be set to the
 * minimum backoff of all retransmissions.
 *
 * @return  0 on success
 *         -1 on error
 */
int hip_update_select_timeout(void)
{
    uint64_t last_backoff = shortest_backoff;

    shortest_backoff = HIP_SELECT_TIMEOUT_USEC;
    if (hip_for_each_ha(get_shortest_retrans_backoff, NULL) < 0) {
        HIP_ERROR("Failed to determine shortest retransmission backoff.\n");
        return -1;
    }

    if (shortest_backoff != last_backoff) {
        select_timeout.tv_sec  = shortest_backoff / 1000000;
        select_timeout.tv_usec = shortest_backoff % 1000000;
        HIP_DEBUG("select() timeout set to %" PRIu64 "ms.\n",
                  shortest_backoff / 1000);
    }

    return 0;
}

/**
 * Daemon "main" function.
 * @param flags startup flags
 * @return      0 on success, negative error code otherwise
 */
int hipd_main(uint64_t flags)
{
    int                       highest_descriptor = 0, err = 0;
    fd_set                    read_fdset;
    struct hip_packet_context ctx = { 0 };

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Creating perf set\n");
    perf_set = hip_perf_create(PERF_MAX);

    check_and_create_dir("results", HIP_DIR_MODE);

    hip_perf_set_name(perf_set, PERF_STARTUP, "results/PERF_STARTUP.csv");
    hip_perf_set_name(perf_set, PERF_I1_SEND, "results/PERF_I1_SEND.csv");
    hip_perf_set_name(perf_set, PERF_I1, "results/PERF_I1.csv");
    hip_perf_set_name(perf_set, PERF_R1, "results/PERF_R1.csv");
    hip_perf_set_name(perf_set, PERF_I2, "results/PERF_I2.csv");
    hip_perf_set_name(perf_set, PERF_R2, "results/PERF_R2.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE, "results/PERF_UPDATE.csv");
    hip_perf_set_name(perf_set, PERF_DH_CREATE, "results/PERF_DH_CREATE.csv");
    hip_perf_set_name(perf_set, PERF_SIGN, "results/PERF_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_DSA_SIGN_IMPL, "results/PERF_DSA_SIGN_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY, "results/PERF_VERIFY.csv");
    hip_perf_set_name(perf_set, PERF_BASE, "results/PERF_BASE.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_SEND, "results/PERF_CLOSE_SEND.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE, "results/PERF_HANDLE_CLOSE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE_ACK, "results/PERF_HANDLE_CLOSE_ACK.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_COMPLETE, "results/PERF_CLOSE_COMPLETE.csv");
    hip_perf_set_name(perf_set, PERF_DSA_VERIFY_IMPL, "results/PERF_DSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_RSA_VERIFY_IMPL, "results/PERF_RSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_RSA_SIGN_IMPL, "results/PERF_RSA_SIGN_IMPL.csv");
    hip_perf_open(perf_set);

    HIP_DEBUG("Start PERF_STARTUP\n");
    hip_perf_start_benchmark(perf_set, PERF_STARTUP);
#endif

    /* default is long format */
    hip_set_logfmt(LOGFMT_LONG);

    if (flags & HIPD_START_FIX_ALIGNMENT) {
        HIP_DEBUG("Setting alignment traps to 3(fix+ warn)\n");
        if (system("echo 3 > /proc/cpu/alignment")) {
            HIP_ERROR("Setting alignment traps failed.");
        }
    }

    /* Configuration is valid! Fork a daemon, if so configured */
    if (flags & HIPD_START_FOREGROUND) {
        hip_set_logtype(LOGTYPE_STDERR);
        HIP_DEBUG("foreground\n");
    } else {
        hip_set_logtype(LOGTYPE_SYSLOG);
        if (fork() > 0) {
            return 0;
        }
    }

    HIP_INFO("hipd pid=%d starting\n", getpid());

    /* prepare the one and only hip_packet_context instance */
    HIP_IFEL(!(ctx.input_msg  = hip_msg_alloc()), ENOMEM, "Insufficient memory");
    HIP_IFEL(!(ctx.output_msg = hip_msg_alloc()), ENOMEM, "Insufficient memory");

    /* Default initialization function. */
    HIP_IFEL(hipd_init(flags), 1, "hipd_init() failed!\n");

    if (flags & HIPD_START_CREATE_CONFIG_AND_EXIT) {
        HIP_ERROR("Config files created, exiting...\n");
        return 0;
    }

    highest_descriptor = hip_get_highest_descriptor();

    /* Enter to the select-loop */
    HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT,
                 HIP_DEBUG_LEVEL_INFORMATIVE,
                 "Hipd daemon running. Starting select loop.\n");
    hipd_set_state(HIPD_STATE_EXEC);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_STARTUP\n");
    hip_perf_stop_benchmark(perf_set, PERF_STARTUP);
    hip_perf_write_benchmark(perf_set, PERF_STARTUP);
#endif

    select_timeout.tv_sec  = HIP_SELECT_TIMEOUT;
    select_timeout.tv_usec = 0;

    while (hipd_get_state() != HIPD_STATE_CLOSED) {
        /* The select() call modifies the provided timeout struct timeval.
         * This variable indirection makes sure that the correct timeout value
         * is used in every loop iteration. */
        struct timeval timeout = select_timeout;

        hip_prepare_fd_set(&read_fdset);

        err = select(highest_descriptor + 1, &read_fdset, NULL, NULL, &timeout);

        /* Only run socket handles, if at least one file descriptor is ready.
         * Output error, in case of a select error.*/
        if (err > 0) {
            hip_run_socket_handles(&read_fdset, &ctx);
        } else if (err < 0) {
            HIP_ERROR("select() error: %s.\n", strerror(errno));
        }

        /* always check if we got packets to be retransmitted */
        if (hip_scan_retransmissions()) {
            HIP_ERROR("Retransmission scan failed.\n");
        }

        /* This call takes care on its own that is does not execute
         * maintenance tasks below a defined time interval threshold. */
        if (hip_periodic_maintenance()) {
            HIP_ERROR("Periodic maintenance task failed\n");
        }
    }

out_err:
    /* free allocated resources */
    hip_exit();

    free(ctx.input_msg);
    free(ctx.output_msg);

    HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

    return err;
}
