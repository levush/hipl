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
 * Periodically handled "maintenance" actions are processed here by
 * default roughly once in a second. These actions include
 * retransmissions of lost HIP control packets, keepalives for NATs,
 * heartbeats to detect connectivity problems, purging of opportunistic
 * mode state, delaying of UPDATE triggering until addresses have stabilized.
 *
 * @brief Hipd maintenance loop
 *
 * @note When adding new functionality, make sure that the socket
 *       calls do not block because hipd is single threaded.
 */

#define _BSD_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/hip_udp.h"
#include "libcore/ife.h"
#include "libcore/linkedlist.h"
#include "libcore/protodefs.h"
#include "libcore/modularization.h"
#include "config.h"
#include "accessor.h"
#include "close.h"
#include "cookie.h"
#include "hadb.h"
#include "hidb.h"
#include "hipd.h"
#include "hip_socket.h"
#include "init.h"
#include "input.h"
#include "output.h"
#include "maintenance.h"

#define FORCE_EXIT_COUNTER_START                5

struct maint_function {
    uint16_t priority;
    int      (*func_ptr)(void);
};

static float precreate_counter  = HIP_R1_PRECREATE_INIT;
static int   force_exit_counter = FORCE_EXIT_COUNTER_START;

/**
 * Interval between sweeps in hip_periodic_maintenance().
 */
static const time_t maintenance_interval = 1; // in seconds

/**
 * List containing all maintenance functions.
 */
static struct hip_ll *maintenance_functions;

/**
 * Update the retransmission backoff of the given retransmission.
 * The backoff will simply be doubled and in case the maximum is exceeded
 * retransmissions are disabled.
 *
 * @param retrans The retransmission to be updated.
 */
static void update_retrans_backoff(struct hip_msg_retrans *const retrans)
{
    if (!retrans) {
        return;
    }

    retrans->current_backoff = retrans->current_backoff << 1;
    if (retrans->current_backoff > HIP_RETRANSMIT_BACKOFF_MAX) {
        HIP_DEBUG("Maximum retransmission backoff reached. Stopping"
                  " retransmission.\n");
        hip_clear_retransmission(retrans);
        return;
    }

    HIP_DEBUG("Retransmission timeout set to %" PRIu64 "ms.\n",
              retrans->current_backoff / 1000);
}

/**
 * an iterator to handle packet retransmission for a given host association
 *
 * @param entry the host association which to handle
 * @param current_time current time
 * @return zero on success or negative on failure
 */
static int handle_retransmissions(struct hip_hadb_state *entry,
                                  void *current_time)
{
    int                     err = 0, i = 0;
    struct hip_msg_retrans *retrans;
    struct timeval         *now = current_time;

    for (i = 0; i < HIP_RETRANSMIT_QUEUE_SIZE; i++) {
        retrans = &entry->hip_msg_retrans[(entry->next_retrans_slot + i) %
                                          HIP_RETRANSMIT_QUEUE_SIZE];

        if (retrans->count > 0) {
            if (calc_timeval_diff(&retrans->last_transmit, now) >
                retrans->current_backoff) {
                /* @todo: verify that this works over slow ADSL line */
                if (hip_send_pkt(&retrans->saddr,
                                 &retrans->daddr,
                                 entry->nat_mode ? hip_get_local_nat_udp_port() : 0,
                                 entry->peer_udp_port,
                                 retrans->buf,
                                 entry, 0) == 0) {
                    /* Set entry state, if previous state was unassociated
                     * and type is I1. */
                    if (hip_get_msg_type(retrans->buf) == HIP_I1 &&
                        entry->state == HIP_STATE_UNASSOCIATED) {
                        HIP_DEBUG("Resent I1 succcesfully\n");
                        entry->state = HIP_STATE_I1_SENT;
                    }
                } else {
                    HIP_ERROR("Failed to retransmit packet of type %d.\n",
                              hip_get_msg_type(retrans->buf));
                    err = -1;
                }

                retrans->count--;
                gettimeofday(&retrans->last_transmit, NULL);
                update_retrans_backoff(retrans);
                hip_update_select_timeout();
            }
        } else if (hip_get_msg_type(retrans->buf)) {
            hip_clear_retransmission(retrans);
        }
    }

    return err;
}

/**
 * deliver pending retransmissions for all host associations
 *
 * @return zero on success or negative on failure
 */
int hip_scan_retransmissions(void)
{
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    if (hip_for_each_ha(handle_retransmissions, &current_time)) {
        return -1;
    }
    return 0;
}

/**
 * Register a maintenance function. All maintenance functions are called during
 * the periodic maintenance cycle.
 *
 * @param maint_function Pointer to the maintenance function.
 * @param priority Priority of the maintenance function.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_register_maint_function(int (*maint_function)(void),
                                const uint16_t priority)
{
    int                    err       = 0;
    struct maint_function *new_entry = NULL;

    HIP_IFEL(!(new_entry = malloc(sizeof(struct maint_function))),
             -1,
             "Error on allocating memory for a maintenance function entry.\n");

    new_entry->priority = priority;
    new_entry->func_ptr = maint_function;

    maintenance_functions = lmod_register_function(maintenance_functions,
                                                   new_entry,
                                                   priority);
    if (!maintenance_functions) {
        HIP_ERROR("Error on registering a maintenance function.\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * Remove a maintenance function from the list.
 *
 * @param maint_function Pointer to the function which should be unregistered.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_unregister_maint_function(int (*maint_function)(void))
{
    return lmod_unregister_function(maintenance_functions,
                                    maint_function);
}

/**
 * Run all maintenance functions.
 *
 * @return Success =  0
 *         Error   = -1
 */
static int run_maint_functions(void)
{
    int                       err  = 0;
    const struct hip_ll_node *iter = NULL;

    if (maintenance_functions) {
        while ((iter = hip_ll_iterate(maintenance_functions, iter))) {
            ((struct maint_function *) iter->ptr)->func_ptr();
        }
    } else {
        HIP_DEBUG("No maintenance function registered.\n");
    }

    return err;
}

/**
 * Free the memory used for storage of maintenance functions.
 */
void hip_uninit_maint_functions(void)
{
    if (maintenance_functions) {
        hip_ll_uninit(maintenance_functions, free);
        free(maintenance_functions);
    }
}

/**
 * Periodic maintenance.
 *
 * @return zero on success or negative on failure
 */
int hip_periodic_maintenance(void)
{
    static time_t last_maintenance = 0;      // timestamp of last call
    const time_t  now              = time(NULL);
    int           err              = 0;

    if (now < last_maintenance) {
        last_maintenance = now;
        HIP_ERROR("System clock skew detected; internal timestamp reset\n");
        return -1;
    }

    if (now - last_maintenance < maintenance_interval) {
        return 0;
    }

    if (hipd_get_state() == HIPD_STATE_CLOSING) {
        if (force_exit_counter > 0) {
            if (hip_count_open_connections() < 1) {
                hipd_set_state(HIPD_STATE_CLOSED);
            }
        } else {
            hip_exit();
            exit(EXIT_SUCCESS);
        }
        force_exit_counter--;
    }

    /* If some HAs are still remaining after certain grace period
     * in closing or closed state, delete them */
    hip_for_each_ha(hip_purge_closing_ha, NULL);

    if (precreate_counter < 0) {
        if (hip_recreate_all_precreated_r1_packets()) {
            HIP_ERROR("Failed to recreate puzzles.\n");
            /* Allow other maintenance functions to be executed even though
             * R1 precreation failed. */
            err = -1;
        }
        precreate_counter = HIP_R1_PRECREATE_INIT;
    } else {
        precreate_counter--;
    }

    run_maint_functions();

    last_maintenance = now;
    return err;
}

/**
 * Update firewall on host association state. Currently used by the
 * LSI mode in the firewall.
 *
 * @param action HIP_MSG_FW_UPDATE_DB or HIP_MSG_FW_BEX_DONE
 * @param hit_s optional source HIT
 * @param hit_r optional destination HIT
 *
 * @return zero on success or negative on failure
 */
int hipfw_set_bex_data(int action, struct in6_addr *hit_s, struct in6_addr *hit_r)
{
    struct hip_common *msg = NULL;
    int                err = 0, sent = 0, r_is_our;

    if (lsi_status == HIP_MSG_LSI_OFF) {
        goto out_err;
    }

    HIP_DEBUG("Send response to firewall.\n");

    /* Makes sure that the hits are sent always in the same order */
    r_is_our = hip_hidb_hit_is_our(hit_r);

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "alloc\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1,
             "Build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg,
                                      r_is_our ? hit_s : hit_r, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");
    HIP_IFEL(hip_build_param_contents(msg,
                                      r_is_our ? hit_r : hit_s, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");

    sent = hip_sendto_firewall(msg);
    if (sent < 0) {
        HIP_PERROR("Send to firewall failed: ");
        err = -1;
        goto out_err;
    }
    HIP_DEBUG("Sent %d bytes to firewall.\n", sent);

out_err:
    free(msg);
    return err;
}

/**
 * tell firewall to turn on or off the ESP relay mode
 *
 * @param action HIP_MSG_OFFER_FULLRELAY or HIP_MSG_CANCEL_FULLRELAY
 *
 * @return zero on success or negative on failure
 */
int hipfw_set_esp_relay(int action)
{
    struct hip_common *msg = NULL;
    int                err = 0;
    int                sent;

    HIP_DEBUG("Setting ESP relay to %d\n", action);
    if (!(msg = hip_msg_alloc())) {
        return -ENOMEM;
    }
    HIP_IFEL(hip_build_user_hdr(msg,
                                action ? HIP_MSG_OFFER_FULLRELAY : HIP_MSG_CANCEL_FULLRELAY, 0),
             -1, "Build header failed\n");

    sent = hip_sendto_firewall(msg);
    if (sent < 0) {
        HIP_PERROR("Send to firewall failed: ");
        err = -1;
        goto out_err;
    }
    HIP_DEBUG("Sent %d bytes to firewall.\n", sent);

out_err:
    free(msg);
    return err;
}

/**
 * send a message to the HIP firewall
 *
 * @param msg the message to send
 * @return zero on success or negative on error
 */
int hip_sendto_firewall(HIPFW const struct hip_common *msg)
{
#ifdef CONFIG_HIP_FIREWALL
    struct sockaddr_in6 hipfw_addr;
    int n = 0;

    hipfw_addr.sin6_family = AF_INET6;
    hipfw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    hipfw_addr.sin6_addr   = in6addr_loopback;

    hipfw_addr.sin6_family = AF_INET6;
    hipfw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    hipfw_addr.sin6_addr   = in6addr_loopback;

    n = sendto(hip_user_sock,
               msg,
               hip_get_msg_total_len(msg),
               0,
               (struct sockaddr *) &hipfw_addr,
               sizeof(hipfw_addr));
    return n;
#else
    HIP_DEBUG("Firewall is disabled.\n");
    return 0;
#endif // CONFIG_HIP_FIREWALL
}
