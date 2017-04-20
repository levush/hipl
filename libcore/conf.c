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
 * This library is used to configure HIP daemon (hipd) dynamically
 * with the hipconf command line tool. Hipd uses this library also to
 * parse the static configuration from @c hipd.conf (the file has
 * the same syntax as hipconf).
 *
 * All new messages have to be registered in the action_handler
 * array defined at the end of this file. You will have to register
 * also action and type handlers. See conf_get_action(),
 * conf_check_action_argc() and conf_get_type()
 *
 * @brief This file defines functions for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 * @todo    del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 * @todo    adding of new extensions should be made simpler
 */

#define _BSD_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/pem.h>

#include "android/android.h"
#include "config.h"
#include "builder.h"
#include "cert.h"
#include "common.h"
#include "crypto.h"
#include "debug.h"
#include "hostid.h"
#include "ife.h"
#include "message.h"
#include "prefix.h"
#include "protodefs.h"
#include "state.h"
#include "straddr.h"
#include "conf.h"

/**
 * hipconf tool actions. These are numerical values for the first commandline
 * argument. For example in "tools/hipconf daemon get hi default"
 * -command "get" is the action. If you want a new action named as 'NEWACT',
 * define a constant variable which has value between 0 and ACTION_MAX.
 * Probably you also need to increase the value of ACTION_MAX.
 * @see conf_get_action()
 */

/* 0 is reserved */
/* ACTION_ADD 1 in conf.h */
#define ACTION_DEL 2
/* ACTION_NEW 3 in conf.h */
#define ACTION_NAT 4
/* unused, was ACTION_HIP 5 */
#define ACTION_SET 6
#define ACTION_INC 7
#define ACTION_DEC 8
#define ACTION_GET 9
#define ACTION_RUN 10
#define ACTION_LOAD 11
/* unused, was ACTION_DHT 12 */
#define ACTION_HA  13
#define ACTION_RST 14
/* unused, was ACTION_BOS 15 */
#define ACTION_DEBUG 16
/* unused, was ACTION_MHADDR 17 */
/* unused, was ACTION_RESTART 18 */
#define ACTION_LOCATOR 19
/* unused, was ACTION_OPENDHT 20 */
/* unused, was for ACTION_OPPTCP 21 */
#define ACTION_TRANSORDER 22
/* unused, was ACTION_TCPTIMEOUT 23 */
/* unused, was ACTION_HIPPROXY 24 */
#define ACTION_REINIT 25
#define ACTION_HEARTBEAT 26

#define ACTION_HIT_TO_LSI 28
/* unused, was ACTION_BUDDIES 29 */
#define ACTION_NSUPDATE 30
#define ACTION_HIT_TO_IP 31
#define ACTION_HIT_TO_IP_SET 32
#define ACTION_NAT_LOCAL_PORT 33
#define ACTION_NAT_PEER_PORT 34
/* unused, was ACTION_DATAPACKET 35 */
#define ACTION_SHOTGUN 36
#define ACTION_MAP_ID_TO_ADDR 37
#define ACTION_LSI_TO_HIT 38
/* unused, was ACTION_HANDOVER 39 */
#define ACTION_MANUAL_UPDATE 40
#define ACTION_BROADCAST 41
#define ACTION_ACQUIRE 42
/* This parameter defines which HIP version will be used by default */
#define ACTION_DEFAULT_HIP_VERSION 45
#define ACTION_MAX 46 /* exclusive */

/**
 * TYPE_ constant list, as an index for each action_handler function.
 *
 * @note Important! These values are used as array indexes, so keep these
 *       in order. If you add a constant TYPE_NEWTYPE here, the value of
 *       TYPE_NEWTYPE must be a correct index for looking up its corresponding
 *       handler function in action_handler[]. Add values after the last value
 *       and increment TYPE_MAX.
 */
/* 0 is reserved */
#define TYPE_HI            1
#define TYPE_MAP           2
#define TYPE_RST           3
#define TYPE_SERVER        4
/* free slot */
#define TYPE_PUZZLE        6
#define TYPE_NAT           7
/* unused, was TYPE_OPP 8 */
/* unused, was TYPE_BLIND 9 */
#define TYPE_SERVICE       10
#define TYPE_CONFIG        11
#define TYPE_RUN           EXEC_LOADLIB_HIP /* Should be 12 */
#define TYPE_TTL           13
/* free slots */
#define TYPE_HA            16
/* unused, was TYPE_MHADDR 17 */
#define TYPE_DEBUG         18
/* unused, was TYPE_DAEMON 19 */
#define TYPE_LOCATOR       20
/* free slots */
/* unused, was TYPE_OPPTCP 23 */
#define TYPE_ORDER         24
/* free slots */
#define TYPE_HEARTBEAT     27
/* free slots */
#define TYPE_NSUPDATE      32
#define TYPE_HIT_TO_IP     33
#define TYPE_HIT_TO_IP_SET 34
#define TYPE_HIT_TO_LSI    35
#define TYPE_NAT_LOCAL_PORT 36
#define TYPE_NAT_PEER_PORT 37
/* unused, was TYPE_DATAPACKET 38 */
#define TYPE_SHOTGUN       39
#define TYPE_ID_TO_ADDR    40
#define TYPE_LSI_TO_HIT    41
/* unused, was TYPE_HANDOVER 42 */
#define TYPE_MANUAL_UPDATE 43
#define TYPE_BROADCAST     44
#define TYPE_CERTIFICATE   45
#define TYPE_DEFAULT_HIP_VERSION 46
#define TYPE_MAX           47 /* exclusive */

/* #define TYPE_RELAY         22 */

/**
 * The daemon process to be configured by the conf command.
 */
static enum daemon_name { HIP_DAEMON, HIP_FIREWALL, UNKNOWN_KEYWORD } daemon_name;

/**
 * A help string containing the usage of @c hipconf and hipd.conf.
 *
 * @note If you added a new action, do not forget to add a brief usage below
 *       for the action.
 */
static const char *hipconf_usage =
    HIPCONF_HIPD_KEYWORD
    " <command>\n\n"
    "HIP daemon commands:\n"
    "add map <hit> <ip> [lsi]\n"
    "get map <hit | lsi>\n"
    "del hi <hit> | all\n"
    "get hi default | all\n"
    "get ha <hit> | all\n"
    "new|add hi anon|pub rsa|dsa filebasename\n"
    "new hi anon|pub rsa|dsa filebasename keylen\n"
    "new|add hi default (HI must be created as root)\n"
    "new hi default rsa_keybits dsa_keybits\n"
    "get|inc|dec|new puzzle all\n"
    "set puzzle all new_value\n"
    "nat none|plain-udp\n"
    "nat port local <port>\n"
    "nat port peer <port>\n"
    "rst all|peer_hit <peer_HIT>\n"
    "load config default\n"
    "Server side:\n"
    "\tadd|del service rvs|relay|full-relay\n"
    "\treinit service rvs|relay|full-relay\n"
    "Client side:\n"
    "\tadd server rvs|relay|full-relay [HIT] <IP|hostname> <lifetime in seconds>\n"
    "\tdel server rvs|relay|full-relay [HIT] <IP|hostname>\n"
    "heartbeat <seconds> (0 seconds means off)\n"
    "locator on|off|get\n"
    "debug all|medium|low|none\n"
    "transform order <integer> "
    " (1=AES, 2=3DES, 3=NULL and place them to order\n"
    "  like 213 for the order 3DES, AES and NULL)\n"
    "manual-update\n"
    "nsupdate on|off\n"
    "hit-to-ip on|off\n"
    "hit-to-ip-zone <hit-to-ip.zone.>\n"
    "shotgun on|off\n"
    "id-to-addr hit|lsi\n"
    "broadcast on|off\n"
    "acquire certificate <hit> [valid-till_timestamp]\n"
    "default-hip-version 1|2\n"
;

/**
 * A help string containing the usage of @c hipfwconf.
 *
 * @note If you added a new action, do not forget to add a brief usage below
 *       for the action.
 */
static const char *hipfwconf_usage =
    HIPCONF_HIPFW_KEYWORD
    " <command>\n\n"
    "HIP firewall commands:\n"
    "get ha <hit> | all\n";

/**
 * Send a message to hipd or hipfw and optionally receive an answer.
 *
 * @param msg       The message to be sent. The respective answer will be stored
 *                  here as well.
 * @param send_only 1 if no response from hipd should be requested.
 *                  0 if it should block until a response from hipd is received.
 *                  This option has no effect when sending messages to hipfw.
 *
 * @return  0 on success
 *         -1 on error
 */
static int send_receive_message(struct hip_common *msg,
                                const int send_only)
{
    if (daemon_name == HIP_DAEMON) {
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Failed to send user message to the HIP daemon.\n");
            return -1;
        }
    } else if (daemon_name == HIP_FIREWALL) {
        if (hip_send_recv_firewall_info(msg)) {
            HIP_ERROR("Failed to send user message to the HIP firewall.\n");
            return -1;
        }
    } else {
        HIP_ERROR("Destination daemon process unknown.\n");
        return -1;
    }

    return 0;
}

/**
 * Query hipd for the HITs of the local host
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt "all" to query for all HITs or "default" for the default
 * @param optc currently unused
 * @param send_only 1 if no response from hipd should be requested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int get_hits(struct hip_common *msg, const char *opt,
                    UNUSED int optc, int send_only)
{
    int                          err           = 0;
    const struct hip_tlv_common *current_param = NULL;
    const struct hip_hit_info   *data;
    const struct in_addr        *deflsi     = NULL;
    const struct in6_addr       *defhit     = NULL;
    hip_tlv                      param_type = 0;
    char                         hit_s[INET6_ADDRSTRLEN], lsi_s[INET_ADDRSTRLEN];

    if (strcmp(opt, "all") == 0) {
        /* Build a HIP message with socket option to get default HIT. */
        HIP_IFE(hip_build_user_hdr(msg, HIP_MSG_GET_LOCAL_HITS, 0), -1);
        /* Send the message to the daemon. The daemon fills the
         * message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param = hip_get_next_param(msg, current_param))) {
            param_type = hip_get_param_type(current_param);

            if (param_type == HIP_PARAM_HIT_INFO) {
                data = hip_get_param_contents_direct(current_param);
                inet_ntop(AF_INET6, &data->lhi.hit, hit_s, INET6_ADDRSTRLEN);

                if (data->lhi.anonymous) {
                    HIP_INFO("Anonymous");
                } else {
                    HIP_INFO("Public   ");
                }

                if (data->lhi.algo == HIP_HI_RSA) {
                    HIP_INFO(" RSA ");
                } else if (data->lhi.algo == HIP_HI_DSA) {
                    HIP_INFO(" DSA ");
                } else if (data->lhi.algo == HIP_HI_ECDSA) {
                    HIP_INFO(" ECDSA ");
                } else {
                    HIP_INFO(" Unknown algorithm (%d) ", data->lhi.algo);
                }
                HIP_INFO("%s", hit_s);

                inet_ntop(AF_INET, &data->lsi, lsi_s, INET_ADDRSTRLEN);

                HIP_INFO("     LSI %s\n", lsi_s);
            } else {
                HIP_ERROR("Unrelated parameter in user message.\n");
            }
        }
    } else if (strcmp(opt, "default") == 0) {
        /* Build a HIP message with socket option to get default HIT. */
        HIP_IFE(hip_build_user_hdr(msg, HIP_MSG_GET_DEFAULT_HIT, 0), -1);
        /* Send the message to the daemon. The daemon fills the
         * message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param = hip_get_next_param(msg, current_param))) {
            param_type = hip_get_param_type(current_param);

            if (param_type == HIP_PARAM_HIT) {
                defhit = hip_get_param_contents_direct(current_param);
                inet_ntop(AF_INET6, defhit, hit_s, INET6_ADDRSTRLEN);
            } else if (param_type == HIP_PARAM_LSI) {
                deflsi = hip_get_param_contents_direct(current_param);
                inet_ntop(AF_INET, deflsi, lsi_s, INET_ADDRSTRLEN);
            } else {
                HIP_ERROR("Unrelated parameter in user message.\n");
            }
        }

        HIP_INFO("Default HIT: %s\nDefault LSI: %s\n", hit_s, lsi_s);
    } else {
        HIP_ERROR("Invalid argument \"%s\". Use \"default\" or \"all\".\n",
                  opt);
        err = -EINVAL;
        goto out_err;
    }

out_err:
    hip_msg_init(msg);

    return err;
}

/**
 * Flush all run-time host identities from hipd
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt currently unused
 * @param optc currently unused
 * @param action currently unused
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @note this does not flush the host identities from disk
 */
static int conf_handle_hi_del_all(struct hip_common *msg, UNUSED int action,
                                  UNUSED const char *opt[], UNUSED int optc,
                                  int send_only)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;
    const struct hip_hit_info   *data;
    struct       hip_common     *msg_tmp = NULL;

    msg_tmp = hip_msg_alloc();
    if (!msg_tmp) {
        HIP_ERROR("Malloc for msg_tmp failed\n");
        return -ENOMEM;
    }

    HIP_IFEL(hip_build_user_hdr(msg_tmp, HIP_MSG_GET_LOCAL_HITS, 0),
             -1, "Failed to build user message header\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg_tmp, send_only, 0), -1,
             "Sending msg failed.\n");

    while ((param = hip_get_next_param(msg_tmp, param))) {
        data = hip_get_param_contents_direct(param);
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_DEL_LOCAL_HI, 0),
                 -1, "Failed to build user message header\n");

        HIP_IFEL(hip_build_param_contents(msg, &data->lhi.hit,
                                          HIP_PARAM_HIT, sizeof(struct in6_addr)),
                 -1, "Failed to build HIT param\n");

        HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
                 "Sending msg failed.\n");

        hip_msg_init(msg);
    }

    /** @todo deleting HITs from the interface isn't working, so we
     *  restart it */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_RESTART_DUMMY_INTERFACE, 0),
             -1, "Failed to build message header\n");

    HIP_INFO("All HIs deleted.\n");

out_err:
    free(msg_tmp);
    return err;
}

/**
 * Handles the hipconf commands where the type is @c del.
 *
 * @param msg    input/output message for the query/response for hipd
 * @param action currently unused
 * @param opt    "all" or a specific HIT
 * @param optc   1
 * @param send_only
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_hi_del(struct hip_common *msg, int action,
                              const char *opt[], int optc, int send_only)
{
    int             err, ret;
    struct in6_addr hit;

    if (optc != 1) {
        HIP_ERROR("Invalid number of arguments\n");
        return -EINVAL;
    }

    if (!strcmp(opt[0], "all")) {
        return conf_handle_hi_del_all(msg, action, opt, optc, send_only);
    }

    ret = inet_pton(AF_INET6, opt[0], &hit);
    if (ret < 0 && errno == EAFNOSUPPORT) {
        HIP_ERROR("inet_pton: not a valid address family\n");
        return -EAFNOSUPPORT;
    }

    if (ret == 0) {
        HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
        return -EINVAL;
    }

    HIP_HEXDUMP("HIT to delete: ", &hit, sizeof(struct in6_addr));

    if ((err = hip_build_user_hdr(msg, HIP_MSG_DEL_LOCAL_HI, 0))) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return err;
    }

    if ((err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                        sizeof(struct in6_addr)))) {
        HIP_ERROR("build param HIT failed: %s\n", strerror(err));
        return err;
    }

    return 0;
}

/**
 * print a hip_hadb_user_info_state structure
 *
 * @param ha hip_hadb_user_info_state (partial information of hadb)
 * @return zero for success and negative on error
 */
static int conf_print_info_ha(const struct hip_hadb_user_info_state *ha)
{
    HIP_INFO("HA is %s\n", hip_state_str(ha->state));
    if (ha->shotgun_status == HIP_MSG_SHOTGUN_ON) {
        HIP_INFO(" Shotgun mode is on.\n");
    } else {
        HIP_INFO(" Shotgun mode is off.\n");
    }

    if (ha->broadcast_status == HIP_MSG_BROADCAST_ON) {
        HIP_INFO(" Broadcast mode is on.\n");
    } else {
        HIP_INFO(" Broadcast mode is off.\n");
    }

    HIP_INFO_HIT(" Local HIT", &ha->hit_our);
    HIP_INFO_HIT(" Peer  HIT", &ha->hit_peer);
    HIP_DEBUG_LSI(" Local LSI", &ha->lsi_our);
    HIP_DEBUG_LSI(" Peer  LSI", &ha->lsi_peer);
    HIP_INFO_IN6ADDR(" Local IP", &ha->ip_our);
    HIP_INFO(" Local NAT traversal UDP port: %d\n", ha->nat_udp_port_local);
    HIP_INFO_IN6ADDR(" Peer  IP", &ha->ip_peer);
    HIP_INFO(" Peer  NAT traversal UDP port: %d\n", ha->nat_udp_port_peer);
    HIP_INFO(" Peer  hostname: %s\n", &ha->peer_hostname);
    if (ha->heartbeats_on > 0 && ha->state == HIP_STATE_ESTABLISHED) {
        HIP_DEBUG(" Heartbeat %.3f ms mean RTT, "
                  "%.3f ms std dev,\n"
                  " %d packets sent,"
                  " %d packets received,"
                  " %d packet lost\n",
                  ha->heartbeats_mean,
                  ha->heartbeats_variance,
                  ha->heartbeats_sent,
                  ha->heartbeats_received,
                  ha->heartbeats_sent - ha->heartbeats_received);
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_RELAY) {
        HIP_INFO(" Peer has granted us relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_FULLRELAY) {
        HIP_INFO(" Peer has granted us full relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_RVS) {
        HIP_INFO(" Peer has granted us rendezvous service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_UNSUP) {
        HIP_DEBUG(" Peer has granted us an unknown service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_RELAY) {
        HIP_INFO(" Peer has refused to grant us relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_FULLRELAY) {
        HIP_INFO(" Peer has refused to grant us full relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_RVS) {
        HIP_INFO(" Peer has refused to grant us RVS service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_UNSUP) {
        HIP_DEBUG(" Peer has refused to grant us an unknown service\n");
    }

    return 0;
}

/* Non-static functions -> global scope */

/**
 * Map daemon / firewall keyword to its respective enum.
 *
 * @param argv an array of strings (command line args to hipconf)
 * @return HIP_DAEMON in case of hipd keyword
 *         HIP_FIREWALL in case of hipfw keyword
 *         UNKNOWN_KEYWORD else
 */
static enum daemon_name conf_get_process(const char *const argv[])
{
    if (!strcmp(HIPCONF_HIPD_KEYWORD, argv[1])) {
        return HIP_DAEMON;
    } else if (!strcmp(HIPCONF_HIPFW_KEYWORD, argv[1])) {
        return HIP_FIREWALL;
    }

    return UNKNOWN_KEYWORD;
}

/**
 * Map a symbolic hipconf action (=add/del) into a number
 *
 * @param argv an array of strings (command line args to hipconf)
 * @return the numeric action id correspoding to the symbolic text
 * @note If you defined a constant ACTION_NEWACT in conf.h,
 *       you also need to add a proper sentence in the strcmp() series,
 *       like that:
 *       ...
 *       else if (!strcmp("newaction", text))
 *           ret = ACTION_NEWACT;
 *       ...
 */
static int conf_get_action(const char *argv[])
{
    int ret = -1;

    if (!strcmp("add", argv[2])) {
        ret = ACTION_ADD;
    } else if (!strcmp("del", argv[2])) {
        ret = ACTION_DEL;
    } else if (!strcmp("new", argv[2])) {
        ret = ACTION_NEW;
    } else if (!strcmp("get", argv[2])) {
        ret = ACTION_GET;
    } else if (!strcmp("set", argv[2])) {
        ret = ACTION_SET;
    } else if (!strcmp("inc", argv[2])) {
        ret = ACTION_INC;
    } else if (!strcmp("dec", argv[2])) {
        ret = ACTION_DEC;
    } else if (!strcmp("rst", argv[2])) {
        ret = ACTION_RST;
    } else if (!strcmp("run", argv[2])) {
        ret = ACTION_RUN;
    } else if (!strcmp("load", argv[2])) {
        ret = ACTION_LOAD;
    } else if (!strcmp("heartbeat", argv[2])) {
        ret = ACTION_HEARTBEAT;
    } else if (!strcmp("locator", argv[2])) {
        ret = ACTION_LOCATOR;
    } else if (!strcmp("debug", argv[2])) {
        ret = ACTION_DEBUG;
    } else if (!strcmp("transform", argv[2])) {
        ret = ACTION_TRANSORDER;
    } else if (!strcmp("reinit", argv[2])) {
        ret = ACTION_REINIT;
    } else if (!strcmp("manual-update", argv[2])) {
        ret = ACTION_MANUAL_UPDATE;
    } else if (!strcmp("hit-to-lsi", argv[2])) {
        ret = ACTION_HIT_TO_LSI;
    } else if (!strcmp("nsupdate", argv[2])) {
        ret = ACTION_NSUPDATE;
    } else if (!strcmp("hit-to-ip-set", argv[2])) {
        ret = ACTION_HIT_TO_IP_SET;
    } else if (!strcmp("hit-to-ip", argv[2])) {
        ret = ACTION_HIT_TO_IP;
    } else if (!strcmp("shotgun", argv[2])) {
        ret = ACTION_SHOTGUN;
    } else if (!strcmp("lsi-to-hit", argv[2])) {
        ret = ACTION_LSI_TO_HIT;
    } else if (!strcmp("nat", argv[2])) {
        if (!strcmp("port", argv[3])) {
            if (!strcmp("local", argv[4])) {
                ret = ACTION_NAT_LOCAL_PORT;
            } else if (!strcmp("peer", argv[4])) {
                ret = ACTION_NAT_PEER_PORT;
            }
        } else {
            ret = ACTION_NAT;
        }
    } else if (!strcmp("broadcast", argv[2])) {
        ret = ACTION_BROADCAST;
    } else if (!strcmp("acquire", argv[2])) {
        ret = ACTION_ACQUIRE;
    } else if (!strcmp("default-hip-version", argv[2])) {
        ret = ACTION_DEFAULT_HIP_VERSION;
    }

    return ret;
}

/**
 * Get the minimum amount of arguments needed to be given to the action.
 *
 * @note If you defined a constant ACTION_NEWACT in conf.h,
 *       you also need to add a case block for the constant
 *       here in the switch(action) block.
 * @param  action action type
 * @return how many arguments needs to be given at least
 */
static int conf_check_action_argc(int action)
{
    int count = 0;

    switch (action) {
    case ACTION_MANUAL_UPDATE:
        count = 0;
        break;
    case ACTION_NEW:
    case ACTION_NAT:
    case ACTION_DEC:
    case ACTION_RST:
    case ACTION_LOCATOR:
    case ACTION_HEARTBEAT:
    case ACTION_HIT_TO_LSI:
    case ACTION_MAP_ID_TO_ADDR:
    case ACTION_LSI_TO_HIT:
    case ACTION_DEBUG:
    case ACTION_REINIT:
    case ACTION_NSUPDATE:
    case ACTION_HIT_TO_IP:
    case ACTION_HIT_TO_IP_SET:
    case ACTION_BROADCAST:
    case ACTION_DEFAULT_HIP_VERSION:
        count = 1;
        break;
    case ACTION_ADD:
    case ACTION_DEL:
    case ACTION_SET:
    case ACTION_INC:
    case ACTION_GET:
    case ACTION_RUN:
    case ACTION_LOAD:
    case ACTION_HA:
    case ACTION_TRANSORDER:
    case ACTION_NAT_LOCAL_PORT:
    case ACTION_NAT_PEER_PORT:
    case ACTION_ACQUIRE:
        count = 2;
        break;
    default:
        break;
    }

    return count;
}

/**
 * map a symbolic hipconf type (=lhi/map/etc) name to numeric type
 *
 * @param  text the type as a string
 * @param  argv arguments
 * @return the numeric type id correspoding to the symbolic text
 */
static int conf_get_type(const char *text, const char *argv[])
{
    int ret = -1;

    if (!strcmp("hi", text)) {
        ret = TYPE_HI;
    } else if (!strcmp("map", text)) {
        ret = TYPE_MAP;
    } else if (!strcmp("rst", text)) {
        ret = TYPE_RST;
    } else if (!strcmp("server", text)) {
        ret = TYPE_SERVER;
    } else if (!strcmp("puzzle", text)) {
        ret = TYPE_PUZZLE;
    } else if (!strcmp("service", text)) {
        ret = TYPE_SERVICE;
    } else if (!strcmp("normal", text)) {
        ret = TYPE_RUN;
    } else if (!strcmp("ha", text)) {
        ret = TYPE_HA;
    } else if (!strcmp("shotgun", text)) {
        ret = TYPE_SHOTGUN;
    } else if ((!strcmp("all", text)) && (strcmp("rst", argv[2]) == 0)) {
        ret = TYPE_RST;
    } else if ((!strcmp("peer_hit", text)) && (strcmp("rst", argv[2]) == 0)) {
        ret = TYPE_RST;
    } else if (strcmp("nat", argv[2]) == 0) {
        if (argv[3] && strcmp("port", argv[3]) == 0) {
            if (argv[4] && strcmp("local", argv[4]) == 0) {
                ret = TYPE_NAT_LOCAL_PORT;
            } else if (argv[4] && strcmp("peer", argv[4]) == 0) {
                ret = TYPE_NAT_PEER_PORT;
            }
        } else {
            ret = TYPE_NAT;
        }
    } else if (!strcmp("certificate", text)) {
        ret = TYPE_CERTIFICATE;
    } else if (strcmp("locator", argv[2]) == 0) {
        ret = TYPE_LOCATOR;
    } else if (!strcmp("debug", text)) {
        ret = TYPE_DEBUG;
    } else if (!strcmp("order", text)) {
        ret = TYPE_ORDER;
    } else if (strcmp("heartbeat", argv[2]) == 0) {
        ret = TYPE_HEARTBEAT;
    } else if (!strcmp("ttl", text)) {
        ret = TYPE_TTL;
    } else if (!strcmp("config", text)) {
        ret = TYPE_CONFIG;
    } else if (strcmp("manual-update", argv[2]) == 0) {
        ret = TYPE_MANUAL_UPDATE;
    } else if (strcmp("hit-to-lsi", argv[2]) == 0) {
        ret = TYPE_HIT_TO_LSI;
    } else if (strcmp("nsupdate", argv[2]) == 0) {
        ret = TYPE_NSUPDATE;
    } else if (strcmp("hit-to-ip-set", argv[2]) == 0) {
        ret = TYPE_HIT_TO_IP_SET;
    } else if (strcmp("hit-to-ip", argv[2]) == 0) {
        ret = TYPE_HIT_TO_IP;
    } else if (strcmp("lsi-to-hit", argv[2]) == 0) {
        ret = TYPE_LSI_TO_HIT;
    } else if (strcmp("broadcast", argv[2]) == 0) {
        ret = TYPE_BROADCAST;
    } else if (strcmp("default-hip-version", text) == 0) {
        ret = TYPE_DEFAULT_HIP_VERSION;
    } else {
        HIP_DEBUG("ERROR: NO MATCHES FOUND \n");
    }

    return ret;
}

/**
 * Get a type argument index, in argv[].
 *
 * @note If you defined a constant ACTION_NEWACT in conf.h,
 *       you also need to add a case block for the constant
 *       here in the switch(action) block.
 * @param action integer value for an action
 * @return an index for argv[], which indicates the type argument.
 *         Usually either 2 or 3.
 */
static int conf_get_type_arg(int action)
{
    int type_arg = -1;

    switch (action) {
    case ACTION_ADD:
    case ACTION_DEL:
    case ACTION_NEW:
    case ACTION_NAT:
    case ACTION_NAT_LOCAL_PORT:
    case ACTION_NAT_PEER_PORT:
    case ACTION_INC:
    case ACTION_DEC:
    case ACTION_SET:
    case ACTION_GET:
    case ACTION_RUN:
    case ACTION_LOAD:
    case ACTION_HEARTBEAT:
    case ACTION_LOCATOR:
    case ACTION_RST:
    case ACTION_TRANSORDER:
    case ACTION_REINIT:
    case ACTION_NSUPDATE:
    case ACTION_HIT_TO_IP:
    case ACTION_HIT_TO_IP_SET:
    case ACTION_BROADCAST:
    case ACTION_ACQUIRE:
        type_arg = 3;
        break;
    case ACTION_MANUAL_UPDATE:
    case ACTION_HIT_TO_LSI:
    case ACTION_LSI_TO_HIT:
    case ACTION_DEBUG:
    case ACTION_SHOTGUN:
    case ACTION_DEFAULT_HIP_VERSION:
        type_arg = 2;
        break;
    default:
        break;
    }

    return type_arg;
}

/**
 * Resolve a given hostname to a HIT/LSI or IP address depending on match_hip flag
 *
 * @param hostname the hostname
 * @param id the address
 * @param match_hip
 * @return zero for success and negative on error
 */
static int resolve_hostname_to_id(const char *hostname, struct in6_addr *id,
                                  int match_hip)
{
    int              err = 1;
    struct addrinfo *res = NULL, *rp;
    struct in_addr  *in4;
    struct in6_addr *in6;

    HIP_IFEL(getaddrinfo(hostname, NULL, NULL, &res), -1,
             "getaddrinfo failed\n");
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        in4 = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;
        in6 = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;

        if (rp->ai_family == AF_INET6 &&
            (ipv6_addr_is_hit(in6) ? match_hip : !match_hip)) {
            ipv6_addr_copy(id, in6);
            err = 0;
            break;
        } else if (rp->ai_family == AF_INET &&
                   (IS_LSI32(in4->s_addr) ? match_hip : !match_hip)) {
            IPV4_TO_IPV6_MAP(in4, id);
            err = 0;
            break;
        }
    }

out_err:
    freeaddrinfo(res);
    return err;
}

/**
 * Handles the hipconf commands where the type is @c server. Creates a user
 * message from the function parameters @c msg, @c action and @c opt[]. The
 * command line that this function parses is of type:
 * <code>tools/hipconf daemon <b>add</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt; &lt;LIFETIME&gt;</code> or
 * <code>tools/hipconf daemon <b>del</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt;</code>, where <code>&lt;SERVICES&gt;</code> is a list of
 * the services to which we want to register or cancel or registration. The
 * list can consist of any number of the strings @c rvs, @c relay,
 * or any number of service type numbers between 0 and 255. The list can be a
 * combination of these with repetitions allowed. At least one string or
 * service type number must be provided.
 *
 * @param msg    a pointer to a target buffer where the message for HIP daemon
 *               is to put
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in array @c opt.
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 * @note         Currently only action @c add is supported.
 * @todo         If the current machine has more than one IP address
 *               there should be a way to choose which of the addresses
 *               to register to the server.
 * @todo         There are currently four different HITs at the @c dummy0
 *               interface. There should be a way to choose which of the HITs
 *               to register to the server.
 */
static int conf_handle_server(struct hip_common *msg, int action,
                              const char *opt[], int optc, UNUSED int send_only)
{
    hip_hit_t       hit                   = { { { 0 } } };
    struct in6_addr ipv6                  = { { { 0 } } };
    int             err                   = 0, seconds = 0, i = 0, number_of_regtypes = 0, reg_type = 0;
    int             index_of_hit          = 0, index_of_ip = 0, opp_mode = 0;
    uint8_t         lifetime              = 0, *reg_types = NULL;
    time_t          seconds_from_lifetime = 0;

    if (action != ACTION_ADD && action != ACTION_DEL) {
        HIP_ERROR("Only actions \"add\" and \"del\" are supported for \"server\".\n");
        return -1;
    } else if (action == ACTION_ADD) {
        char *tail_ptr = NULL;

        if (optc < 4) {
            if (optc < 3) {
                HIP_ERROR("Missing arguments.\n");
                return -1;
            } else {
                HIP_DEBUG("Opportunistic mode or direct HIT registration \n");
                opp_mode = 1;
            }
        }

        if (!opp_mode) {
            number_of_regtypes = optc - 3;
            index_of_hit       = optc - 3;
            index_of_ip        = optc - 2;
        } else {
            number_of_regtypes = optc - 2;
            index_of_ip        = optc - 2;
        }

        seconds = strtoul(opt[optc - 1], &tail_ptr, 10);
        if (*tail_ptr != '\0' || seconds <= 0 || seconds > 15384774) {
            HIP_ERROR("Invalid lifetime value \"%s\" given.\n"
                      "Please give a lifetime value between 1 and "
                      "15384774 seconds.\n", opt[optc - 1]);
            return -1;
        }
        if (hip_get_lifetime_value(seconds, &lifetime)) {
            HIP_ERROR("Unable to convert seconds to a lifetime value.\n");
            return -1;
        }
        hip_get_lifetime_seconds(lifetime, &seconds_from_lifetime);
    } else if (action == ACTION_DEL) {
        if (optc < 2) {
            HIP_ERROR("Missing arguments.\n");
            err = -1;
            goto out_err;
        } else if (optc < 3) {
            HIP_DEBUG("Opportunistic mode or direct HIT registration \n");
            opp_mode = 1;
        }
        number_of_regtypes = optc - 2 + opp_mode;
        index_of_hit       = optc - 2;
        index_of_ip        = optc - 1;
    }

    if (!opp_mode) {
        /* Check the HIT value. */
        if (inet_pton(AF_INET6, opt[index_of_hit], &hit) <= 0 &&
            resolve_hostname_to_id(opt[index_of_hit], &hit, 1)) {
            HIP_ERROR("'%s' is not a valid HIT.\n", opt[index_of_hit]);
            return -1;
        }
    }
    /* Check the IPv4 or IPV6 value. */

    if (inet_pton(AF_INET6, opt[index_of_ip], &ipv6) <= 0) {
        struct in_addr ipv4;
        if (inet_pton(AF_INET, opt[index_of_ip], &ipv4) <= 0) {
            /* First try to find an IPv4 or IPv6 address. Second,
             * settle for HIT if no routable address found.
             * The second step is required when dnsproxy is running
             * during HIP service registration. */
            for (i = 0; i < 2; i++) {
                err = resolve_hostname_to_id(opt[index_of_ip], &ipv6, i);
                if (err == 0) {
                    break;
                }
            }

            if (err) {
                HIP_ERROR("'%s' is not a valid IPv4 or IPv6 address.\n",
                          opt[index_of_ip]);
                return -1;
            }
        } else {
            IPV4_TO_IPV6_MAP(&ipv4, &ipv6);
        }
    }

    if (optc > 13) {
        HIP_ERROR("Too many services requested.\n");
        return -1;
    }

    reg_types = malloc(number_of_regtypes * sizeof(uint8_t));

    if (reg_types == NULL) {
        HIP_ERROR("Unable to allocate memory for registration types.\n");
        return -ENOMEM;
    }

    /* Every commandline argument in opt[] from '0' to 'optc - 4' should
     * be either one of the predefined strings or a number between
     * 0 and 255 (inclusive). */
    for (; i < number_of_regtypes; i++) {
        if (strlen(opt[i]) > 30) {
            HIP_ERROR("'%s' is not a valid service name.\n", opt[i]);
            err = -1;
            goto out_err;
        }

        if (strcasecmp("rvs", opt[i]) == 0) {
            reg_types[i] = HIP_SERVICE_RENDEZVOUS;
        } else if (strcasecmp("relay", opt[i]) == 0) {
            reg_types[i] = HIP_SERVICE_RELAY;
        } else if (strcasecmp("full-relay", opt[i]) == 0) {
            reg_types[i] = HIP_SERVICE_FULLRELAY;
        }         /* To cope with the atoi() error value we handle the 'zero'
                   * case here. */
        else if (strcasecmp("0", opt[i]) == 0) {
            reg_types[i] = 0;
        } else {
            reg_type = atoi(opt[i]);
            if (reg_type <= 0 || reg_type > 255) {
                HIP_ERROR("'%s' is not a valid service name "
                          "or service number.\n", opt[i]);
                err = -1;
                goto out_err;
            } else {
                reg_types[i] = reg_type;
            }
        }
    }

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_ADD_DEL_SERVER, 0), -1,
             "Failed to build hipconf user message header.\n");

    if (!opp_mode) {
        HIP_IFEL(hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)), -1,
                 "Failed to build HIT parameter to hipconf user message.\n");
    }

    /* Routable address or dnsproxy returning transparently
     * HITs (bug id 880) */
    HIP_IFEL(hip_build_param_contents(msg, &ipv6, HIP_PARAM_IPV6_ADDR,
                                      sizeof(struct in6_addr)), -1,
             "Failed to build IPv6 parameter to hipconf user message.\n");

    HIP_IFEL(hip_build_param_reg_request(msg, lifetime, reg_types,
                                         number_of_regtypes), -1,
             "Failed to build REG_REQUEST parameter to hipconf user message.\n");

    if (action == ACTION_ADD) {
        HIP_INFO("Requesting %u service%s for %d seconds "
                 "(lifetime 0x%x) from %s %s.\n",
                 number_of_regtypes,
                 (number_of_regtypes > 1) ? "s" : "",
                 seconds_from_lifetime, lifetime, opt[index_of_hit],
                 opt[index_of_ip]);
    } else {
        HIP_INFO("Requesting the cancellation of %u service%s from\n"
                 "HIT %s located at\nIP address %s.\n",
                 number_of_regtypes,
                 (number_of_regtypes > 1) ? "s" : "",
                 (opp_mode ? "<unknown>" : opt[index_of_hit]),
                 opt[index_of_ip]);
    }
out_err:
    free(reg_types);
    return err;
}

/** compose a user-message to add a new hit->ip<-lsi mapping
 *
 * @param msg    the target buffer where the message for the HIP daemon is
 *               written to
 * @param opt    the command line arguments after the action and type.
 * @param optc   the number of elements in array @c opt.
 * @return 0 on success, -1 otherwise
 */
static int conf_add_id_to_ip_map(struct hip_common *const msg,
                                 const char *opt[], const int optc)
{
    struct in_addr  lsi, aux;
    struct in6_addr hit, ip6;
    int             err = 0;

    if (optc != 2 && optc != 3) {
        HIP_ERROR("Missing arguments\n");
        return -1;
    }

    if (hip_convert_string_to_address(opt[0], &hit)) {
        HIP_ERROR("string to address conversion failed\n");
        return -1;
    }

    if ((err = hip_convert_string_to_address(opt[1], &ip6))) {
        HIP_ERROR("string to address conversion failed\n");
        return -1;
    }

    if ((err && inet_pton(AF_INET, opt[1], &aux) != 1) && IS_LSI32(aux.s_addr)) {
        HIP_ERROR("Missing IP address before lsi\n");
        return -1;
    }

    if (hip_build_user_hdr(msg, HIP_MSG_ADD_PEER_MAP_HIT_IP, 0)) {
        HIP_ERROR("add peer map failed\n");
        return -1;
    }
    if (hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                 sizeof(struct in6_addr))) {
        HIP_ERROR("build param hit failed\n");
        return -1;
    }

    if (hip_build_param_contents(msg, &ip6, HIP_PARAM_IPV6_ADDR,
                                 sizeof(struct in6_addr))) {
        HIP_ERROR("build param hit failed\n");
        return -1;
    }

    if (optc == 3) {
        if (inet_pton(AF_INET, opt[2], &lsi) != 1) {
            HIP_ERROR("string to address conversion failed\n");
            return -1;
        }
        if (!IS_LSI32(lsi.s_addr)) {
            HIP_ERROR("Wrong LSI value\n");
            return -1;
        }
        if (hip_build_param_contents(msg, &lsi, HIP_PARAM_LSI,
                                     sizeof(struct in_addr))) {
            HIP_ERROR("build param lsi failed\n");
            return -1;
        }
    }

    return err;
}

/**
 * ask hipd to map a HIT or LSI to a locator
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt a HIT or LSI
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int conf_get_id_to_ip_map(struct hip_common *msg, const char *opt[],
                                 int optc, int send_only)
{
    struct in6_addr              hit;
    struct in_addr               lsi;
    const struct in6_addr       *ip;
    struct in_addr               ip4;
    const struct hip_tlv_common *param = NULL;
    char                         addr_str[INET6_ADDRSTRLEN];

    if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        return -1;
    }

    if (inet_pton(AF_INET6, opt[0], &hit) != 1) {
        if (inet_pton(AF_INET, opt[0], &lsi) != 1) {
            HIP_ERROR("inet_pton failed\n");
            return -1;
        }
        IPV4_TO_IPV6_MAP(&lsi, &hit);
    }

    if (hip_build_user_hdr(msg, HIP_MSG_MAP_ID_TO_ADDR, 0)) {
        HIP_ERROR("Failed to build message header\n");
        return -1;
    }
    if (hip_build_param_contents(msg, &hit, HIP_PARAM_IPV6_ADDR,
                                 sizeof(hit))) {
        HIP_ERROR("Failed to build message contents\n");
        return -1;
    }
    if (hip_send_recv_daemon_info(msg, send_only, 0)) {
        HIP_ERROR("Sending message failed\n");
        return -1;
    }

    while ((param = hip_get_next_param(msg, param))) {
        if (hip_get_param_type(param) != HIP_PARAM_IPV6_ADDR) {
            continue;
        }
        ip = hip_get_param_contents_direct(param);
        if (IN6_IS_ADDR_V4MAPPED(ip)) {
            IPV6_TO_IPV4_MAP(ip, &ip4);
            if (!inet_ntop(AF_INET, &ip4, addr_str, INET_ADDRSTRLEN)) {
                HIP_ERROR("inet_ntop() failed\n");
                return -1;
            }
        } else {
            if (!inet_ntop(AF_INET6, ip, addr_str, INET6_ADDRSTRLEN)) {
                HIP_ERROR("inet_ntop() failed\n");
                return -1;
            }
        }

        HIP_INFO("Resolved to IP: %s\n", addr_str);
    }

    hip_msg_init(msg);

    return 0;
}

#define OPT_HI_TYPE   0
#define OPT_HI_FMT    1
#define OPT_HI_FILE   2
#define OPT_HI_KEYLEN 3

/**
 * Handles the hipconf commands where the type is @c hi.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_hi(struct hip_common *msg, int action,
                          const char *opt[], int optc, int send_only)
{
    int         err          = 0, anon = 0, use_default = 0, rsa_key_bits = 0, ecdsa_nid = ECDSA_DEFAULT_CURVE;
    int         dsa_key_bits = 0;
    const char *fmt          = NULL, *file = NULL;

    if (action == ACTION_DEL) {
        return conf_handle_hi_del(msg, action, opt, optc, send_only);
    } else if (action == ACTION_GET) {
        if (optc < 1) {
            HIP_ERROR("Missing arguments.\n");
            return -1;
        } else if (optc > 1) {
            HIP_ERROR("Too many arguments.\n");
            return -1;
        }

        return get_hits(msg, opt[0], 1, send_only);
    } else if (action != ACTION_ADD && action != ACTION_NEW) {
        HIP_ERROR("Only actions \"add\", \"new\", \"del\" and \"get\" "
                  "are supported for \"hi\".\n");
        return -1;
    }

    if (optc < 1) {
        HIP_ERROR("Missing arguments.\n");
        return -1;
    } else if (optc > 4) {
        HIP_ERROR("Too many arguments.\n");
        return -1;
    }

    if (strcmp(opt[0], "pub") == 0) {
        anon = 0;
    } else if (strcmp(opt[0], "anon") == 0) {
        anon = 1;
    } else if (strcmp(opt[OPT_HI_TYPE], "default") == 0) {
        use_default = 1;
    } else {
        HIP_ERROR("Bad HI type %s. Please use \"pub\", \"anon\" or "
                  "\"default\".\n", opt[0]);
        return -EINVAL;
    }

    if (use_default && action == ACTION_ADD) {
        /* Keys must be added one by one for the hip_endpoint structure
         * to fit in the message. */

        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 1, 1,
                                                "dsa", NULL, 0, 0, 0))) {
            return err;
        }
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Sending msg failed.\n");
            return -1;
        }

        hip_msg_init(msg);
        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
                                                "dsa", NULL, 0, 0, 0))) {
            return err;
        }
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Sending msg failed.\n");
            return -1;
        }

        hip_msg_init(msg);
        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 1, 1,
                                                "ecdsa", NULL, 0, 0, 0))) {
            return err;
        }
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Sending msg failed.\n");
            return -1;
        }

        hip_msg_init(msg);
        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
                                                "ecdsa", NULL, 0, 0, 0))) {
            return err;
        }
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Sending msg failed.\n");
            return -1;
        }

        hip_msg_init(msg);
        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 1, 1,
                                                "rsa", NULL, 0, 0, 0))) {
            return err;
        }
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Sending msg failed.\n");
            return -1;
        }

        hip_msg_init(msg);
        err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
                                           "rsa", NULL, 0, 0, 0);
        return err;
    }

    if (use_default) {
        if (optc == 3) {
            rsa_key_bits = atoi(opt[1]);
            dsa_key_bits = atoi(opt[2]);
        } else if (optc != 1) {
            HIP_ERROR("Invalid number of arguments\n");
            return -EINVAL;
        }
    } else {
        if (optc == 4) {
            rsa_key_bits = dsa_key_bits = atoi(opt[OPT_HI_KEYLEN]);
        } else if (optc != 3) {
            HIP_ERROR("Invalid number of arguments\n");
            return -EINVAL;
        }

        fmt  = opt[OPT_HI_FMT];
        file = opt[OPT_HI_FILE];
    }

    if (rsa_key_bits < 384 || rsa_key_bits > HIP_MAX_RSA_KEY_LEN ||
        rsa_key_bits % 64 != 0) {
        rsa_key_bits = RSA_KEY_DEFAULT_BITS;
    }
    if (dsa_key_bits < 512 || dsa_key_bits > HIP_MAX_DSA_KEY_LEN ||
        dsa_key_bits % 64 != 0) {
        dsa_key_bits = DSA_KEY_DEFAULT_BITS;
    }

    return hip_serialize_host_id_action(msg, action, anon, use_default, fmt,
                                        file, rsa_key_bits, dsa_key_bits,
                                        ecdsa_nid);
}

/**
 * Handles the hipconf commands where the type is @c map.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type. (should be the HIT and the corresponding
 *               IPv6 address).
 * @param optc   the number of elements in the array (@b 2).
 * @param send_only
 * @return       zero on success, or negative error value on error.
 * @note         Does not support @c del action.
 */
static int conf_handle_map(struct hip_common *msg, int action,
                           const char *opt[],
                           int optc, UNUSED int send_only)
{
    switch (action) {
    case ACTION_ADD:
        return conf_add_id_to_ip_map(msg, opt, optc);
    case ACTION_GET:
        return conf_get_id_to_ip_map(msg, opt, optc, send_only);
    default:
        return -1;
    }
}

/**
 * Handles the hipconf command heartbeat.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_heartbeat(struct hip_common *msg, UNUSED int action,
                                 const char *opt[], UNUSED int optc,
                                 UNUSED int send_only)
{
    int seconds = 0;

    seconds = atoi(opt[0]);
    if (seconds < 0) {
        HIP_ERROR("Invalid argument\n");
        return -EINVAL;
    }

    if (hip_build_user_hdr(msg, HIP_MSG_HEARTBEAT, 0)) {
        HIP_ERROR("Failed to build user message header\n");
        return -1;
    }

    if (hip_build_param_heartbeat(msg, seconds)) {
        HIP_ERROR("Failed to build param heartbeat\n");
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf transform order command.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_trans_order(struct hip_common *msg,
                                   UNUSED int action, const char *opt[],
                                   int optc, UNUSED int send_only)
{
    int err, transorder, i, k;

    if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        return -EINVAL;
    }

    transorder = atoi(opt[0]);

    /* has to be over 100 three options (and less than 321) */
    if (transorder < 100 && transorder > 322) {
        HIP_ERROR("Invalid argument\n");
        return -EINVAL;
    }

    /* Check individual numbers has to be in range 1 to 3 (3 options) */
    for (i = 0; i < 3; i++) {
        k  = (int) opt[0][i];
        k -= 48;         // easy way to remove junk
        if (k < 0 || k > 3) {
            HIP_ERROR("Invalid argument\n");
            return -EINVAL;
        }
    }

    err = hip_build_user_hdr(msg, HIP_MSG_TRANSFORM_ORDER, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return err;
    }

    err = hip_build_param_transform_order(msg, transorder);
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        return err;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c rst.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_rst(struct hip_common *msg, UNUSED int action,
                           const char *opt[], UNUSED int optc,
                           UNUSED int send_only)
{
    int             err, ret;
    struct in6_addr hit = { { { 0 } } };

    if (strcmp("all", opt[0])) {
        ret = inet_pton(AF_INET6, opt[0], &hit);
        if (ret < 0 && errno == EAFNOSUPPORT) {
            HIP_PERROR("inet_pton: not a valid address family\n");
            return -EAFNOSUPPORT;
        } else if (ret == 0) {
            HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
            return -EINVAL;
        }
    }

    err = hip_build_user_hdr(msg, HIP_MSG_RST, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return err;
    }

    err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                   sizeof(struct in6_addr));
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        return err;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c debug.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only currently unused parameter
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_debug(struct hip_common *msg, UNUSED int action,
                             const char *opt[], int optc, UNUSED int send_only)
{
    int err = 0, status = 0;

    if (optc != 0) {
        HIP_ERROR("Wrong number of arguments. Usage:\nhipconf debug all|medium|low|none\n");
        return -EINVAL;
    }

    if (!strcmp("all", opt[0])) {
        HIP_INFO("Displaying all debugging messages\n");
        status = HIP_MSG_SET_DEBUG_ALL;
    } else if (!strcmp("medium", opt[0])) {
        HIP_INFO("Displaying INFO debugging messages\n");
        status = HIP_MSG_SET_DEBUG_MEDIUM;
    } else if (!strcmp("low", opt[0])) {
        HIP_INFO("Displaying ERROR debugging messages\n");
        status = HIP_MSG_SET_DEBUG_LOW;
    } else if (!strcmp("none", opt[0])) {
        HIP_INFO("Displaying no debugging messages\n");
        status = HIP_MSG_SET_DEBUG_NONE;
    } else {
        HIP_ERROR("Unknown argument\n");
        return -EINVAL;
    }

    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c trigger-update.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @param send_only currently_unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_manual_update(struct hip_common *msg, UNUSED int action,
                                     UNUSED const char *opt[],
                                     UNUSED int optc, UNUSED int send_only)
{
    int err = 0;

    if (hip_build_user_hdr(msg, HIP_MSG_MANUAL_UPDATE_PACKET, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c nat port.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_nat_port(struct hip_common *msg, int action,
                                const char *opt[],
                                UNUSED int optc, UNUSED int send_only)
{
    int err = 0;

    in_port_t port = (in_port_t) atoi(opt[1]);

    if (hip_build_user_hdr(msg, HIP_MSG_SET_NAT_PORT, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    if (action == ACTION_NAT_LOCAL_PORT) {
        if (hip_build_param_nat_port(msg, port, HIP_PARAM_LOCAL_NAT_PORT)) {
            HIP_ERROR("Failed to build nat port parameter.: %s\n", strerror(err));
            return -1;
        }
    } else {
        if (hip_build_param_nat_port(msg, port, HIP_PARAM_PEER_NAT_PORT)) {
            HIP_ERROR("Failed to build nat port parameter.: %s\n", strerror(err));
            return -1;
        }
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c nat.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_nat(struct hip_common *msg, UNUSED int action,
                           const char *opt[], UNUSED int optc,
                           UNUSED int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("plain-udp", opt[0])) {
        status = HIP_MSG_SET_NAT_PLAIN_UDP;
    } else if (!strcmp("none", opt[0])) {
        status = HIP_MSG_SET_NAT_NONE;
    }

    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c locator. You can turn
 * locator sending in BEX on or query the set of local locators with this
 * function.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_locator(struct hip_common *msg, UNUSED int action,
                               const char *opt[], UNUSED int optc,
                               int send_only)
{
    int                       err     = 0, status = 0;
    const struct hip_locator *locator = NULL;

    if (!strcmp("on", opt[0])) {
        status = HIP_MSG_SET_LOCATOR_ON;
    } else if (!strcmp("off", opt[0])) {
        status = HIP_MSG_SET_LOCATOR_OFF;
    } else if (!strcmp("get", opt[0])) {
        status = HIP_MSG_LOCATOR_GET;
    } else {
        HIP_ERROR("bad args\n");
        return -1;
    }
    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }
    if (status == HIP_MSG_LOCATOR_GET) {
        if (hip_send_recv_daemon_info(msg, send_only, 0)) {
            HIP_ERROR("Send recv daemon info failed\n");
            return -1;
        }
        locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
        if (locator) {
            hip_print_locator_addresses(msg);
        } else {
            HIP_DEBUG("No LOCATOR found from daemon msg\n");
        }
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c puzzle.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @param send_only
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_puzzle(struct hip_common *msg, int action,
                              const char *opt[], int optc, int send_only)
{
    int                          err  = 0, ret = 0, msg_type = 0, all, new_val = 0;
    const int                   *diff = NULL;
    hip_hit_t                    hit  = { { { 0 } } }, all_zero_hit = { { { 0 } } };
    char                         hit_s[INET6_ADDRSTRLEN];
    const struct hip_tlv_common *current_param = NULL;
    hip_tlv                      param_type    = 0;

    if (action == ACTION_SET) {
        if (optc != 2) {
            HIP_ERROR("Missing arguments\n");
            err = -EINVAL;
            goto out_err;
        }
    } else if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        err = -EINVAL;
        goto out_err;
    }

    switch (action) {
    case ACTION_NEW:
        msg_type = HIP_MSG_CONF_PUZZLE_NEW;
        break;
    case ACTION_INC:
        msg_type = HIP_MSG_CONF_PUZZLE_INC;
        break;
    case ACTION_DEC:
        msg_type = HIP_MSG_CONF_PUZZLE_DEC;
        break;
    case ACTION_SET:
        msg_type = HIP_MSG_CONF_PUZZLE_SET;
        break;
    case ACTION_GET:
        msg_type = HIP_MSG_CONF_PUZZLE_GET;
        break;
    default:
        err = -1;
    }

    if (err) {
        HIP_ERROR("Action (%d) not supported yet\n", action);
        goto out_err;
    }

    all = !strcmp("all", opt[0]);

    if (!all) {
        ret = inet_pton(AF_INET6, opt[0], &hit);
        if (ret < 0 && errno == EAFNOSUPPORT) {
            HIP_PERROR("inet_pton: not a valid address family\n");
            err = -EAFNOSUPPORT;
            goto out_err;
        } else if (ret == 0) {
            HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
            err = -EINVAL;
            goto out_err;
        }
    }

    /* obtain the new value for set */
    if ((msg_type == HIP_MSG_CONF_PUZZLE_SET) && (optc == 2)) {
        new_val = atoi(opt[1]);
    }

    /* Build a HIP message with socket option to get puzzle difficulty. */
    HIP_IFE(hip_build_user_hdr(msg, msg_type, 0), -1);

    /* attach the hit into the message */
    err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                   sizeof(struct in6_addr));
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out_err;
    }

    /* obtain the result for the get action */
    if (msg_type == HIP_MSG_CONF_PUZZLE_GET) {
        /* Send the message to the daemon. The daemon fills the message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param = hip_get_next_param(msg, current_param))) {
            param_type = hip_get_param_type(current_param);
            if (param_type == HIP_PARAM_HIT) {
                //no need to get the hit from msg
            } else if (param_type == HIP_PARAM_INT) {
                diff = hip_get_param_contents_direct(current_param);
            } else {
                HIP_ERROR("Unrelated parameter in user message.\n");
            }
        }

        HIP_INFO("Puzzle difficulty is: %d\n", *diff);

        if (ipv6_addr_cmp(&all_zero_hit, &hit) != 0) {
            inet_ntop(AF_INET6, &hit, hit_s, INET6_ADDRSTRLEN);
            HIP_INFO("for peer hit: %s\n", hit_s);
        }
    }

    /* attach new val for the set action */
    if (msg_type == HIP_MSG_CONF_PUZZLE_SET) {
        err = hip_build_param_contents(msg, &new_val, HIP_PARAM_INT,
                                       sizeof(int));
        if (err) {
            HIP_ERROR("build param int failed: %s\n", strerror(err));
            goto out_err;
        }
    }

    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }

    if ((msg_type == HIP_MSG_CONF_PUZZLE_GET) ||
        (msg_type == HIP_MSG_CONF_PUZZLE_SET)) {
        goto out_err;
    }

    if (all) {
        HIP_INFO("New puzzle difficulty effective immediately\n");
    } else {
        HIP_INFO("New puzzle difficulty is effective when R1s are next updated\n");
    }

out_err:
    if (msg_type == HIP_MSG_CONF_PUZZLE_GET) {
        hip_msg_init(msg);
    }
    return err;
}

/**
 * Translate a HIT to an LSI
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt remote hit as a string
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int conf_handle_get_peer_lsi(struct hip_common *msg, UNUSED int action,
                                    const char *opt[], UNUSED int optc,
                                    int send_only)
{
    int                          err = 0;
    hip_hit_t                    hit;
    const hip_lsi_t             *lsi;
    char                         lsi_str[INET_ADDRSTRLEN];
    const char                  *hit_str = opt[0];
    const struct hip_tlv_common *param;

    if (inet_pton(AF_INET6, hit_str, &hit) <= 0) {
        HIP_ERROR("Not an IPv6 address\n");
        return -1;
    }
    if (!ipv6_addr_is_hit(&hit)) {
        HIP_ERROR("Not a HIT\n");
        return -1;
    }

    if (hip_build_user_hdr(msg, HIP_MSG_GET_LSI_PEER, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    if (hip_build_param_contents(msg, &hit, HIP_PARAM_HIT, sizeof(hit))) {
        return -1;
    }

    if (hip_send_recv_daemon_info(msg, send_only, 0)) {
        HIP_ERROR("send recv daemon info\n");
        return -1;
    }

    param = hip_get_param(msg, HIP_PARAM_LSI);
    if (!param) {
        HIP_ERROR("No LSI in msg\n");
        return -1;
    }
    lsi = hip_get_param_contents_direct(param);
    if (!inet_ntop(AF_INET, lsi, lsi_str, sizeof(lsi_str))) {
        HIP_ERROR("LSI string conversion failed\n");
        return -1;
    }
    HIP_INFO("HIT %s maps to LSI %s\n", hit_str, lsi_str);

    return 0;
}

/**
 * Handles @c service commands received from @c hipconf.
 *
 * Create a message to the kernel module from the function parameters @c msg,
 * @c action and @c opt[].
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed on
 *               the given mapping.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type (pointer to @b "rvs" or @b "relay").
 * @param optc   the number of elements in the array.
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
static int conf_handle_service(struct hip_common *msg, int action,
                               const char *opt[], int optc,
                               UNUSED int send_only)
{
    if (action != ACTION_ADD && action != ACTION_REINIT && action != ACTION_DEL) {
        HIP_ERROR("Only actions \"add\", \"del\" and \"reinit\" are supported "
                  "for \"service\".\n");
        return -1;
    }
    if (optc < 1) {
        HIP_ERROR("Missing arguments.\n");
        return -1;
    } else if (optc > 1) {
        HIP_ERROR("Too many arguments.\n");
        return -1;
    }

    if (action == ACTION_ADD) {
        if (strcmp(opt[0], "rvs") == 0) {
            HIP_INFO("Adding rendezvous service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_OFFER_RVS, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "relay") == 0) {
            HIP_INFO("Adding HIP UDP relay service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_OFFER_HIPRELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "full-relay") == 0) {
            HIP_INFO("Adding HIP_FULLRELAY service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_OFFER_FULLRELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    } else if (action == ACTION_REINIT) {
        if (strcmp(opt[0], "rvs") == 0) {
            if (hip_build_user_hdr(msg, HIP_MSG_REINIT_RVS, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "relay") == 0) {
            if (hip_build_user_hdr(msg, HIP_MSG_REINIT_RELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "full-relay") == 0) {
            if (hip_build_user_hdr(msg, HIP_MSG_REINIT_FULLRELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    } else if (action == ACTION_DEL) {
        if (strcmp(opt[0], "rvs") == 0) {
            HIP_INFO("Deleting rendezvous service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_CANCEL_RVS, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "relay") == 0) {
            HIP_INFO("Deleting HIP UDP relay service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_CANCEL_HIPRELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else if (strcmp(opt[0], "full-relay") == 0) {
            HIP_INFO("Deleting HIP full relay service.\n");
            if (hip_build_user_hdr(msg, HIP_MSG_CANCEL_FULLRELAY, 0)) {
                HIP_ERROR("Failed to build user message header.\n");
                return -1;
            }
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    }

    return 0;
}

/**
 * Handle e.g. "hipconf daemon run normal firefox".
 * Enables HIP support for the given application using LD_PRELOAD. This means
 * that all getaddrinfo() calls go through the modified libinet6 library.
 * This function is depracated.
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt a string containing the name of the application to LD_PRELOAD
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @todo remove this and related constants
 */
static int conf_handle_run_normal(UNUSED struct hip_common *msg,
                                  UNUSED int action,
                                  UNUSED const char *opt[],
                                  UNUSED int optc,
                                  UNUSED int send_only)
{
    HIP_ERROR("Unsupported\n");
    return -1;
}

/**
 * query and print information on host associations from hipd
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt an array of string containing one string "all"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int conf_handle_ha(struct hip_common *msg, UNUSED int action,
                          const char *opt[], int optc, int send_only)
{
    const struct hip_tlv_common           *current_param = NULL;
    const struct hip_hadb_user_info_state *ha;
    int                                    err = 0;
    struct in6_addr                        hit1;

    HIP_IFEL(optc > 1, -1, "Too many arguments\n");

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_HA_INFO, 0), -1,
             "Building of user msg header failed\n");

    HIP_IFEL(send_receive_message(msg, send_only), -1,
             "send recv info\n");

    while ((current_param = hip_get_next_param(msg, current_param))) {
        ha = hip_get_param_contents_direct(current_param);

        if (!strcmp("all", opt[0])) {
            conf_print_info_ha(ha);
        } else {
            HIP_IFE(hip_convert_string_to_address(opt[0], &hit1), -1);

            if ((ipv6_addr_cmp(&hit1, &ha->hit_our) == 0) ||
                (ipv6_addr_cmp(&hit1, &ha->hit_peer) == 0)) {
                conf_print_info_ha(ha);
            }
        }
    }

out_err:
    hip_msg_init(msg);

    return err;
}

static int conf_handle_nsupdate(struct hip_common *msg, UNUSED int action,
                                const char *opt[], UNUSED int optc,
                                UNUSED int send_only)
{
    int err = 0, status;

    if (!strcmp("on", opt[0])) {
        status = HIP_MSG_NSUPDATE_ON;
    } else if (!strcmp("off", opt[0])) {
        status = HIP_MSG_NSUPDATE_OFF;
    } else {
        HIP_ERROR("bad args\n");
        return -1;
    }
    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Set hit-to-ip extension on of off. The extension "subscribes" the host
 * to DNS resolution for HITs from the configured DNS server.
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @see conf_handle_nsupdate
 * @see conf_handle_hit_to_ip_set
 */
static int conf_handle_hit_to_ip(struct hip_common *msg,
                                 UNUSED const int action,
                                 const char *opt[],
                                 UNUSED const int optc,
                                 UNUSED const int send_only)
{
    int err = 0, status = HIP_MSG_HIT_TO_IP_OFF;

    if (!strcmp("on", opt[0])) {
        status = HIP_MSG_HIT_TO_IP_ON;
    } else if (!strcmp("off", opt[0])) {
        status = HIP_MSG_HIT_TO_IP_OFF;
    } else {
        HIP_ERROR("Invalid option!\n");
    }
    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Set the HIT-to-IP server
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt the ip address of the HIT-to-IP server
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @see conf_handle_hit_to_ip
 */
static int conf_handle_hit_to_ip_set(struct hip_common *msg, UNUSED int action,
                                     const char *opt[], UNUSED int optc,
                                     UNUSED int send_only)
{
    int err      = 0;
    int len_name = strlen(opt[0]);

    HIP_DEBUG("hit-to-ip zone received from user: %s (len = %d (max %d))\n",
              opt[0], len_name, HIT_TO_IP_ZONE_MAX_LEN);
    if (len_name >= HIT_TO_IP_ZONE_MAX_LEN) {
        HIP_ERROR("Name too long (max %s)\n", HIT_TO_IP_ZONE_MAX_LEN);
        return -1;
    }

    err = hip_build_user_hdr(msg, HIP_MSG_HIT_TO_IP_SET, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return err;
    }
    err = hip_build_param_hit_to_ip_set(msg, opt[0]);
    if (err) {
        HIP_ERROR("build param failed: %s\n", strerror(err));
        return err;
    }

    return 0;
}

/**
 * Set shotgun mode on or off. It allows spreading of I1 or UPDATE packet
 * over multiple source and destination address pairs
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int conf_handle_shotgun(struct hip_common *msg, UNUSED const int action,
                               const char *opt[], UNUSED const int optc,
                               UNUSED const int send_only)
{
    int err = 0, status = HIP_MSG_SHOTGUN_OFF;

    if (!strcmp("on", opt[0])) {
        status = HIP_MSG_SHOTGUN_ON;
    } else if (!strcmp("off", opt[0])) {
        status = HIP_MSG_SHOTGUN_OFF;
    } else {
        HIP_ERROR("Invalid option!\n");
    }
    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * translate a remote LSI to a HIT
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt the LSI as a string
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int conf_handle_lsi_to_hit(struct hip_common *msg, UNUSED int action,
                                  const char *opt[], UNUSED int optc,
                                  int send_only)
{
    hip_lsi_t                    lsi;
    const struct in6_addr       *hit;
    const struct hip_tlv_common *param = NULL;

    if (inet_pton(AF_INET, opt[0], &lsi) != 1) {
        HIP_ERROR("inet_pton()\n");
        return -1;
    }
    if (hip_build_user_hdr(msg, HIP_MSG_LSI_TO_HIT, 0)) {
        HIP_ERROR("Failed to build message header\n");
        return -1;
    }
    if (hip_build_param_contents(msg, &lsi, HIP_PARAM_LSI, sizeof(lsi))) {
        HIP_ERROR("Failed to build message contents\n");
        return -1;
    }
    if (hip_send_recv_daemon_info(msg, send_only, 0)) {
        HIP_ERROR("Sending message failed\n");
        return -1;
    }

    while ((param = hip_get_next_param(msg, param))) {
        if (hip_get_param_type(param) != HIP_PARAM_IPV6_ADDR) {
            continue;
        }
        hit = hip_get_param_contents_direct(param);
        HIP_INFO_HIT("Found HIT: ", hit);
    }

    hip_msg_init(msg);

    return 0;
}

#define HIPD_CONFIG_FILE HIPL_SYSCONFDIR "/hipd.conf"

/**
 * Handles the hipconf commands where the type is @c load.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @param send_only currently unused
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_load(UNUSED struct hip_common *msg, UNUSED int action,
                         const char *opt[], int optc, UNUSED int send_only)
{
    int   err        = 0, i, res_len;
    FILE *hip_config = NULL;

    char       *c, line[128], str[128], *token;
    const char *args[64];
    char       *comment, *newline;
    char        fname[sizeof(HIPD_CONFIG_FILE) << 1];

    if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        return -1;
    }

    if (!strcmp(opt[0], "default")) {
        strcpy(fname, HIPD_CONFIG_FILE);
    } else {
        strcpy(fname, opt[0]);
    }

    if (!(hip_config = fopen(fname, "r"))) {
        HIP_ERROR("Error: can't open config file %s.\n", fname);
        return -1;
    }

    while (err == 0 && fgets(line, sizeof(line), hip_config)) {
        /* Remove whitespace */
        c = line;
        while (*c == ' ' || *c == '\t') {
            c++;
        }

        /* Line is a comment or empty */
        if (c[0] == '#' || c[0] == '\n' || c[0] == '\0') {
            continue;
        }

        /* Terminate before the newline */
        newline = strchr(c, '\n');
        if (newline) {
            *newline = '\0';
        }

        /* Terminate before (the first) trailing comment */
        comment = strchr(c, '#');
        if (comment) {
            *comment = '\0';
        }

        /* prefix the contents of the line with" hipconf HIPCONF_HIPD_KEYWORD"
         * Only hipd parses config files as hipconf commands, hardcode it as target */
        res_len = sprintf(str, "hipconf %s %s", HIPCONF_HIPD_KEYWORD, c);
        if (str[res_len] == '\n') {
            str[res_len] = '\0';
        }

        /* split the line into an array of strings and feed it
         * recursively to hipconf */
        i     = 0;
        token = strtok(str, " \t");
        while (token) {
            args[i++] = token;
            token     = strtok(NULL, " \t");
        }
        err = hip_do_hipconf(i, args, 1);
        if (err) {
            HIP_ERROR("Error on the following line: %s\n", line);
            HIP_ERROR("Ignoring error on hipd configuration\n");
            err = 0;
        }
    }

    fclose(hip_config);

    return err;
}

static int conf_handle_broadcast(struct hip_common *msg, UNUSED int action,
                                 const char *opt[], UNUSED int optc,
                                 UNUSED int send_only)
{
    int err = 0, status;

    if (!strcmp("on", opt[0])) {
        status = HIP_MSG_BROADCAST_ON;
    } else if (!strcmp("off", opt[0])) {
        status = HIP_MSG_BROADCAST_OFF;
    } else {
        HIP_ERROR("bad args\n");
        return -1;
    }
    if (hip_build_user_hdr(msg, status, 0)) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c default-hip-version.
 *
 * @param msg       a pointer to the buffer where the message for hipd will
 *                  be written.
 * @param action    unused.
 * @param opt       an array of pointers to the command line arguments after
 *                  the action and type.
 * @param optc      the number of elements in the array.
 * @param send_only unused.
 * @return          zero on success, or negative error value on error.
 */
static int conf_handle_default_hip_version(struct hip_common *msg,
                                           UNUSED int action, const char *opt[],
                                           int optc, UNUSED int send_only)
{
    int status = 0;

    if (optc != 0) {
        HIP_ERROR("Incorrect number of arguments. "
                  "Usage:\nhipconf default-hip-version 1|2\n");
        return -EINVAL;
    }

    if (!strcmp("1", opt[0])) {
        HIP_INFO("Default hip version: 1\n");
        status = HIP_MSG_DEFAULT_HIP_VERSION_1;
    } else if (!strcmp("2", opt[0])) {
        HIP_INFO("Default hip version: 2\n");
        status = HIP_MSG_DEFAULT_HIP_VERSION_2;
    } else {
        HIP_ERROR("Unknown argument\n");
        return -EINVAL;
    }

    if (hip_build_user_hdr(msg, status, 0) < 0) {
        HIP_ERROR("Failed to build the user message header.\n");
        return -1;
    }

    return 0;
}

/**
 * Utility function which compactly checks whether a string represents
 * a positive natural number, since scanf() is too lenient.
 *
 * @param string NULL-terminated string to be checked
 *
 * @return       1 if the only characters in the string are digits,
 *                optionally with one leading '+' sign; 0 otherwise
 */
static int is_pos_natural_number(const char *string)
{
    if (string) {
        size_t len;

        // allow one leading '+'
        if (string[0] == '+') {
            string++;
        }

        if ((len = strlen(string)) > 0) {
            for (size_t i = 0; i < len; i++) {
                if (string[i] < '0' || string[i] > '9') {
                    return 0;
                }
            }
            return 1;
        }
    }
    return 0;
}

/**
 * Process parameters of "hipconf acquire certificate", converting and
 * entering them into a HIP message. Only to be used internally by
 * conf_handle_certificate().
 *
 * @param msg  HIP message to be set up with the parameters
 * @param opt  array of parameter strings
 * @param optc number of parameters (one or two are accepted)
 *
 * @return     0 upon success, or -1 in case of failure
 */
static int conf_handle_certificate_parms(struct hip_common *msg,
                                         const char *opt[],
                                         int optc)
{
    hip_hit_t subject_hit;
    uint32_t  valid_until_h = 0, valid_until_n = 0;
    int       scanf_res     = 0;

    /* turn the HIT string into its binary representation */
    if (optc < 1 || inet_pton(AF_INET6, opt[0], &subject_hit) != 1) {
        return -1;
    }

    /* same for the optional numeric parameter after the HIT */
    if (optc == 2 && is_pos_natural_number(opt[1])) {
        /* Need to use sscanf() here: strtol() won't do since we want the
         * result of the conversion to fit into an uint32_t, whereas strtol()
         * and relatives would write to a variable of platform-dependent
         * size. */
        scanf_res = sscanf(opt[1], "%" SCNu32, &valid_until_h);
    }

    /* optc == 1 as well as optc == 2 is acceptable - the latter is
     * implied if scanf_res is 1. */
    if (optc != 1 && scanf_res != 1) {
        return -1;
    }

    HIP_DEBUG_HIT("Requesting certificate for subject", &subject_hit);

    if (hip_build_user_hdr(msg, HIP_MSG_CERT_X509V3_SIGN, 0)) {
        HIP_ERROR("Failed to build user message header.\n");
        return -1;
    }

    /* The optional parameter following the HIT is meant to indicate the
     * point in time when validity of the issued certificate ends; expressed
     * in "number of seconds since the epoch"; we use a uint32_t for this, so
     * we're creating a year-2106-problem here (be scared). */
    if (scanf_res == 1) {
        valid_until_n = htonl(valid_until_h);
        if (hip_build_param_contents(msg, &valid_until_n,
                                     HIP_PARAM_UINT, sizeof(uint32_t))) {
            HIP_ERROR("Failed to build validity parameter.\n");
            return -1;
        }
    }

    if (hip_build_param_cert_x509_req(msg, &subject_hit)) {
        HIP_ERROR("Failed to build cert_x509_req parameter.\n");
        return -1;
    }

    return 0;
}

/**
 * Handles the hipconf command "acquire certificate".
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed
 *               (error if != ACTION_ACQUIRE).
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (one or two).
 * @param send_only 0 (send message to hipd and wait for result) is expected.
 *
 * @return       0 upon success, or -1 in case of failure.
 */
static int conf_handle_certificate(struct hip_common *msg,
                                   int action,
                                   const char *opt[],
                                   int optc,
                                   int send_only)
{
    X509                            *cert           = NULL;
    const struct hip_cert_x509_resp *response_param = NULL;

    /* It does not make any sense to send a certificate request and then
     * ignore the returned certificate. (I.e., using "acquire certificate"
     * as part of HIPL config files is not a good idea.) */
    if (send_only != 0) {
        return -1;
    }

    /* only react to "hipconf daemon x certificate" if x == "acquire" -
     * then process parameters and set up message accordingly */
    if (action != ACTION_ACQUIRE ||
        conf_handle_certificate_parms(msg, opt, optc)) {
        HIP_ERROR("Invalid arguments.\n");
        return -1;
    }

    /* Send the message to the daemon. "msg" gets overwritten with the
     * response. */
    if (hip_send_recv_daemon_info(msg, 0, 0)) {
        HIP_ERROR("Error sending message to hip daemon.\n");
        return -1;
    }

    /* Check for correct message type of the response, and find the one
     * parameter in it that's relevant. */
    if ((hip_get_msg_type(msg) != HIP_MSG_CERT_X509V3_SIGN) ||
        (!(response_param = hip_get_param(msg, HIP_PARAM_CERT_X509_RESP)))) {
        HIP_ERROR("Received invalid response message for certificate request.\n");
        return -1;
    }

    /* Try to convert DER certificate into the internal OpenSSL
     * structured X509 format, as a simple consistency check */
    const uint32_t der_len_h = ntohl(response_param->der_len);
    if (!(cert = cert_DER_to_X509(response_param->der, der_len_h))) {
        HIP_ERROR("Could not get X509 certificate from DER encoding\n.");
        return -1;
    } else {
        X509_free(cert);
    }

    /* dump the DER encoded certificate to stdout */
    if (fwrite(response_param->der, der_len_h, 1, stdout) != 1) {
        HIP_ERROR("Couldn't output certificate.\n");
        return -1;
    }

    /* Clear the msg (and in particular its message type field)
     * to prevent hip_do_hipconf() from sending it again. */
    hip_msg_init(msg);

    return 0;
}

/**
 * Function pointer array containing pointers to handler functions.
 * Add a handler function for your new action in the action_handler[] array.
 * If you added a handler function here, do not forget to define that function
 * somewhere in this source file. The API for the array is as follows:
 *
 * - Input/output message describes the query message to be sent to hipd. The
 *   message may be overwritten by hipd with a response message from hipd.
 * - The action to take
 * - Arguments for the action
 * - Number of arguments
 * - Wait for a response message from hipd
 *
 * @note You will have to register also action and type handlers. See
 *       conf_get_action(), conf_check_action_argc() and
 *       conf_get_type()
 * @note Keep the elements in the same order as the @c TYPE values are defined
 *       in conf.h because type values are used as @c action_handler array
 *       index. Locations and order of these handlers are important.
 */
static int (*action_handler[])(struct hip_common *, int action,
                               const char *opt[], int optc, int send_only) = {
    NULL,                               /* reserved */
    conf_handle_hi,                     /* 1: TYPE_HI */
    conf_handle_map,                    /* 2: TYPE_MAP */
    conf_handle_rst,                    /* 3: TYPE_RST */
    conf_handle_server,                 /* 4: TYPE_SERVER */
    /* Any client side registration action. */
    NULL,                               /* 5: unused, was TYPE_BOS */
    conf_handle_puzzle,                 /* 6: TYPE_PUZZLE */
    conf_handle_nat,                    /* 7: TYPE_NAT */
    NULL,                               /* 8: unused, was TYPE_OPP */
    NULL,                               /* 9: unused, was TYPE_BLIND */
    conf_handle_service,                /* 10: TYPE_SERVICE */
    /* Any server side registration action. */
    hip_conf_handle_load,               /* 11: TYPE_CONFIG */
    conf_handle_run_normal,             /* 12: TYPE_RUN */
    NULL,                               /* was 13: TYPE_TTL */
    NULL,                               /* unused, was 14: TYPE_GW */
    NULL,                               /* unused, was 15: TYPE_GET */
    conf_handle_ha,                     /* 16: TYPE_HA */
    NULL,                               /* unused, was 17: TYPE_MHADDR */
    conf_handle_debug,                  /* 18: TYPE_DEBUG */
    NULL,                               /* unused, was 19: TYPE_DAEMON */
    conf_handle_locator,                /* 20: TYPE_LOCATOR */
    NULL,                               /* 21: unused, was TYPE_SET */
    NULL,                               /* 22: unused, was TYPE_DHT */
    NULL,                               /* 23: unused, was TYPE_OPPTCP */
    conf_handle_trans_order,            /* 24: TYPE_ORDER */
    NULL,                               /* 25: unused, was TYPE_TCPTIMEOUT */
    NULL,                               /* 26: unused, was TYPE_HIPPROXY */
    conf_handle_heartbeat,              /* 27: TYPE_HEARTBEAT */
    NULL,                               /* 28: unused */
    NULL,                               /* 29: unused */
    NULL,                               /* 30: unused, was TYPE_BUDDIES */
    NULL,                               /* 31: unused, was TYPE_SAVAHR */
    conf_handle_nsupdate,               /* 32: TYPE_NSUPDATE */
    conf_handle_hit_to_ip,              /* 33: TYPE_HIT_TO_IP */
    conf_handle_hit_to_ip_set,          /* 34: TYPE_HIT_TO_IP_SET */
    conf_handle_get_peer_lsi,           /* 35: TYPE_MAP_GET_PEER_LSI */
    conf_handle_nat_port,               /* 36: TYPE_NAT_LOCAL_PORT */
    conf_handle_nat_port,               /* 37: TYPE_PEER_LOCAL_PORT */
    NULL,                               /* 38: unused, was TYPE_DATAPACKET*/
    conf_handle_shotgun,                /* 39: TYPE_SHOTGUN */
    NULL,                               /* 40: unused, was TYPE_ID_TO_ADDR */
    conf_handle_lsi_to_hit,             /* 41: TYPE_LSI_TO_HIT */
    NULL,                               /* 42: unused, was TYPE_HANDOVER */
    conf_handle_manual_update,          /* 43: TYPE_MANUAL_UPDATE */
    conf_handle_broadcast,              /* 44: TYPE_BROADCAST */
    conf_handle_certificate,            /* 45: TYPE_CERTIFICATE */
    conf_handle_default_hip_version,    /* 46: TYPE_DEFAULT_HIP_VERSION */
    NULL     /* TYPE_MAX, the end. */
};

/**
 * hipconf stub used by the hipconf tool and hipd (to read conf file)
 *
 * @param argc the number of arguments
 * @param argv the arguments
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
int hip_do_hipconf(int argc, const char *argv[], int send_only)
{
    int                err    = 0, type_arg = 0;
    long int           action = 0, type     = 0;
    struct hip_common *msg    = NULL;

    /* Check that we have at least one command line argument. */
    if (argc < 3) {
        HIP_ERROR("Invalid arguments.\nUsage to communicate with HIP daemon:\n %s %s\n"
                  "\nUsage to communicate with HIP firewall:\n %s %s\n",
                  argv[0], hipconf_usage, argv[0], hipfwconf_usage);
        return -1;
    }

    /* set context for this conf command */
    daemon_name = conf_get_process(argv);
    if (daemon_name == UNKNOWN_KEYWORD) {
        HIP_ERROR("Invalid target process argument '%s'. Expected '%s' or '%s'.\n",
                  argv[1], HIPCONF_HIPD_KEYWORD, HIPCONF_HIPFW_KEYWORD);
        return -1;
    }

    /* Get a numeric value representing the action. */
    action = conf_get_action(argv);

    if (action == -1) {
        HIP_ERROR("Invalid action argument '%s'\n", argv[2]);
        return -1;
    }

    /* Check that we have at least the minimum number of arguments
     * for the given action. */
    if (argc < conf_check_action_argc(action) + 3) {
        HIP_ERROR("Not enough arguments given for the action '%s'\n", argv[2]);
        return -1;
    }

    /* Is this redundant? What does it do? -Lauri 19.03.2008 19:46. */
    if ((type_arg = conf_get_type_arg(action)) < 0) {
        HIP_ERROR("Could not parse type\n");
        return -1;
    }

    type = conf_get_type(argv[type_arg], argv);
    if (type <= 0 || type > TYPE_MAX) {
        HIP_ERROR("Invalid type argument '%s' %d\n", argv[type_arg], type);
        return -1;
    }

    /* Get the type argument for the given action. */
    if (!(msg = malloc(HIP_MAX_PACKET))) {
        HIP_ERROR("malloc failed.\n");
        return -ENOMEM;
    }
    hip_msg_init(msg);

    HIP_IFEL(*action_handler[type] == NULL, 0, "Unhandled action, ignore\n");

    /* Call handler function from the handler function pointer
     * array at index "type" with given commandline arguments.
     * The functions build a hip_common message. */
    if (argc == 4) {
        err = (*action_handler[type])(msg, action, &argv[3], argc - 4, send_only);
    } else {
        err = (*action_handler[type])(msg, action, &argv[4], argc - 4, send_only);
    }

    if (err != 0) {
        HIP_ERROR("Failed to send user message.\n");
        goto out_err;
    }

    /* hipconf daemon new hi does not involve any messages to hipd */
    if (hip_get_msg_type(msg) == 0) {
        goto out_err;
    }

    send_receive_message(msg, send_only);

    HIP_INFO("User message was sent successfully to the HIP daemon.\n");

out_err:
    free(msg);

    if (err) {
        HIP_ERROR("(Check syntax for hipconf. Is the daemon running or root"
                  " privilege needed?)\n");
    }

    return err;
}
