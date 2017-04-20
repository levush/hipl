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
 * This file defines initialization functions for the HIP daemon.
 *
 * @note    HIPU: BSD platform needs to be autodetected in hip_set_lowcapability
 */

#define _BSD_SOURCE

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/rtnetlink.h>

#include "android/android.h"
#include "libcore/capability.h"
#include "libcore/common.h"
#include "libcore/conf.h"
#include "libcore/crypto.h"
#include "libcore/debug.h"
#include "libcore/filemanip.h"
#include "libcore/hip_udp.h"
#include "libcore/hostid.h"
#include "libcore/hostsfiles.h"
#include "libcore/ife.h"
#include "libcore/modularization.h"
#include "libcore/performance.h"
#include "libcore/straddr.h"
#include "libcore/gpl/nlink.h"
#include "libcore/gpl/xfrmapi.h"
#include "modules/hipd_modules.h"
#include "config.h"
#include "accessor.h"
#include "close.h"
#include "dh.h"
#include "esp_prot_hipd_msg.h"
#include "esp_prot_light_update.h"
#include "hadb.h"
#include "hidb.h"
#include "hip_socket.h"
#include "hipd.h"
#include "hiprelay.h"
#include "input.h"
#include "maintenance.h"
#include "nat.h"
#include "netdev.h"
#include "nsupdate.h"
#include "output.h"
#include "pkt_handling.h"
#include "registration.h"
#include "user.h"
#include "init.h"

/**
 * HIP daemon lock file is used to prevent multiple instances
 * of the daemon to start and to record current daemon pid.
 */
#define HIP_DAEMON_LOCK_FILE     HIPL_LOCKDIR    "/hipd.lock"

/** Maximum size of a modprobe command line */
#define MODPROBE_MAX_LINE       64


/** ICMPV6_FILTER related stuff */
#define BIT_CLEAR(nr, addr) do { ((uint32_t *) (addr))[(nr) >> 5] &= ~(1U << ((nr) & 31)); } while (0)
#define BIT_SET(nr,   addr) do { ((uint32_t *) (addr))[(nr) >> 5] |=  (1U << ((nr) & 31)); } while (0)
#define BIT_TEST(nr,  addr) do { ((uint32_t *) (addr))[(nr) >> 5] &   (1U << ((nr) & 31)); } while (0)

#ifndef ICMP6_FILTER_WILLPASS
#define ICMP6_FILTER_WILLPASS(type, filterp) (BIT_TEST((type),  filterp) == 0)
#define ICMP6_FILTER_WILLBLOCK(type, filterp) BIT_TEST((type),  filterp)
#define ICMP6_FILTER_SETPASS(type, filterp)   BIT_CLEAR((type), filterp)
#define ICMP6_FILTER_SETBLOCK(type, filterp)  BIT_SET((type),   filterp)
#define ICMP6_FILTER_SETPASSALL(filterp)  memset(filterp,    0, sizeof(struct icmp6_filter))
#define ICMP6_FILTER_SETBLOCKALL(filterp) memset(filterp, 0xFF, sizeof(struct icmp6_filter))
#endif
/** end ICMPV6_FILTER related stuff */

#define HIPL_USER_DIR ".hipl"
#define HIPL_USER_RSA_KEY_NAME "libhipl_rsa_key"

/* Flag to show if hipl is running in libhip mode (=1) or normal mode (=0).
 *
 * This variable should NOT be accessed directly. Always use the accessor
 * functions instead.
 */
static bool hipd_library_mode = false;

/**
 * Test if the library mode is on.
 *
 * @return true if the library mode is on, false otherwise.
 */
bool hipl_is_libhip_mode(void)
{
    return hipd_library_mode;
}

/**
 * Turn on library mode.
 */
void hipl_set_libhip_mode(void)
{
    hipd_library_mode = true;
}

/* Startup flags of the HIPD. Keep the around, for they will be used at exit */
static uint64_t sflags;

/* The value of the default HIP version loaded from hipd.conf. Its accessor
 * functions are hip_set_default_version() and hip_get_default_version().
 */
static uint8_t hip_default_hip_version = 1;

/******************************************************************************/
/**
 * Catch SIGCHLD.
 *
 * @param signum the signal number to catch
 */
static void sig_chld(int signum)
{
    int status;
    int pid;

    signal(signum, sig_chld);

    /* Get child process status, so it will not be left as zombie for long time. */
    while ((pid = wait3(&status, WNOHANG, 0)) > 0) {
        /* Maybe do something.. */
    }
}

/**
 * initialize OS-dependent variables
 */
static void set_os_dep_variables(void)
{
    struct utsname un;
    int            rel[4] = { 0 };

    uname(&un);

    HIP_DEBUG("sysname=%s nodename=%s release=%s version=%s machine=%s\n",
              un.sysname, un.nodename, un.release, un.version, un.machine);

    sscanf(un.release, "%d.%d.%d.%d", &rel[0], &rel[1], &rel[2], &rel[3]);

    /*
     * 2.6.19 and above introduced some changes to kernel API names:
     * - XFRM_BEET changed from 2 to 4
     * - crypto algo names changed
     */
    if (rel[0] <= 2 && rel[1] <= 6 && rel[2] < 19) {
        hip_xfrm_set_beet(2);
        hip_xfrm_set_algo_names(0);
    } else {
        hip_xfrm_set_beet(4);         /* BEET mode */
        hip_xfrm_set_algo_names(1);
    }
    /* This requires new kernel versions (the 2.6.18 patch) - jk */
    hip_xfrm_set_default_sa_prefix_len(128);
}

/**
 * Initialize a raw ipv4 socket.
 * @param proto the protocol for the raw socket
 * @return      positive fd on success, -1 otherwise
 */
static int init_raw_sock_v4(int proto)
{
    int on = 1, off = 0, err = 0;
    int sock;

    sock = socket(AF_INET, SOCK_RAW, proto);
    set_cloexec_flag(sock, 1);
    HIP_IFEL(sock <= 0, -1, "Raw socket v4 creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(sock, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

    return sock;

out_err:
    return -1;
}

/**
 * Probe kernel modules.
 */

/** CryptoAPI cipher and hashe modules */
static const char *kernel_crypto_mod[] = {
    "crypto_null", "aes", "des"
};

/** Tunneling, IPsec, interface and control modules */
static const char *kernel_net_mod[] = {
    "xfrm4_mode_beet", "xfrm6_mode_beet",
    "esp4",            "esp6",
    "xfrm_user",       "dummy",
};

/**
 * Firm check of the required kernel modules.
 * This function assumes the all the required modules are compiled as
 * "modules" (as opposed to "built-in").
 * @return  0 if all the required modules are loaded, nonzero otherwise
 */
static int check_kernel_modules(void)
{
    int         net_total, crypto_total, count;
    char        str[MODPROBE_MAX_LINE];
    struct stat sbuf;

    net_total    = sizeof(kernel_net_mod)    / sizeof(kernel_net_mod[0]);
    crypto_total = sizeof(kernel_crypto_mod) / sizeof(kernel_crypto_mod[0]);

    for (count = 0; count < crypto_total; count++) {
        snprintf(str, sizeof(str), "grep %s /proc/crypto > /dev/null",
                 kernel_crypto_mod[count]);
        if (system(str)) {
            HIP_ERROR("The %s kernel module is not loaded\n",
                      kernel_crypto_mod[count]);
            return ENOENT;
        }
    }

    for (count = 0; count < net_total; count++) {
        snprintf(str, sizeof(str), "/sys/module/%s", kernel_net_mod[count]);
        if (stat(str, &sbuf)) {
            HIP_INFO("The %s kernel module is not loaded\n",
                     kernel_net_mod[count]);
        }
    }

    return 0;
}

/**
 * Probe for kernel modules (Linux specific).
 * @return  0 on success
 */
static int probe_kernel_modules(void)
{
    int         count;
    char        cmd[MODPROBE_MAX_LINE];
    int         net_total, crypto_total;
    struct stat sbuf;

    net_total    = sizeof(kernel_net_mod)    / sizeof(kernel_net_mod[0]);
    crypto_total = sizeof(kernel_crypto_mod) / sizeof(kernel_crypto_mod[0]);

    /* no, this check should NOT be performed at ./configure time */
    if (stat("/sbin/modprobe", &sbuf)) {
        HIP_INFO("The modprobe tool is not installed, will not load modules\n");
        if (check_kernel_modules()) {
            return -1;
        }
    }

    /* Crypto module loading is treated separately, because algorithms
     * show up in procfs. If they are not there and modprobe also fails,
     * then overall failure is guaranteed
     */
    for (count = 0; count < crypto_total; count++) {
        snprintf(cmd, sizeof(cmd), "grep %s /proc/crypto > /dev/null",
                 kernel_crypto_mod[count]);
        if (system(cmd)) {
            HIP_DEBUG("Crypto module %s not present, attempting modprobe\n");
            snprintf(cmd, sizeof(cmd), "/sbin/modprobe %s 2> /dev/null",
                     kernel_crypto_mod[count]);
            if (system(cmd)) {
                HIP_ERROR("Unable to load %s!\n", kernel_crypto_mod[count]);
                return ENOENT;
            }
        }
    }

    /* network module loading */
    for (count = 0; count < net_total; count++) {
        /* we still suppress false alarms from modprobe */
        snprintf(cmd, sizeof(cmd), "/sbin/modprobe %s 2> /dev/null",
                 kernel_net_mod[count]);
        if (system(cmd)) {
            HIP_ERROR("Ignoring failure to load %s!\n", kernel_net_mod[count]);
        }
    }

    return 0;
}

/**
 * Remove a single module from the kernel, rmmod style (not modprobe).
 * @param name  name of the module
 * @return      0 on success, negative otherwise
 */
static inline int rmmod(const char *name)
{
    return syscall(__NR_delete_module, name, O_NONBLOCK);
}

/**
 * Initialize random seed.
 */
static int init_random_seed(void)
{
    struct timeval  tv;
    struct timezone tz;
    struct {
        struct timeval tv;
        pid_t          pid;
        long int       rand;
    } rand_data;
    int err = 0;

    err = gettimeofday(&tv, &tz);
    srandom(tv.tv_usec);

    memcpy(&rand_data.tv, &tv, sizeof(tv));
    rand_data.pid  = getpid();
    rand_data.rand = random();

    RAND_seed(&rand_data, sizeof(rand_data));

    return err;
}

/**
 * Init raw ipv6 socket
 * @param proto protocol for the socket
 * @return      positive socket fd on success, -1 otherwise
 */
static int init_raw_sock_v6(int proto)
{
    int on = 1, off = 0, err = 0;
    int sock;

    sock = socket(AF_INET6, SOCK_RAW, proto);
    set_cloexec_flag(sock, 1);
    HIP_IFEL(sock <= 0, -1, "Raw socket creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

    return sock;

out_err:
    return -1;
}

/**
 * Initialize local host IDs.
 *
 * @return zero on success or negative on failure
 */
static int init_host_ids(void)
{
    int                err = 0;
    struct stat        status;
    struct hip_common *user_msg = NULL;
    hip_hit_t          default_hit;
    hip_lsi_t          default_lsi;

    /* We are first serializing a message with HIs and then
     * deserializing it. This building and parsing causes
     * a minor overhead, but as a result we can reuse the code
     * with hipconf. */

    HIP_IFE(!(user_msg = hip_msg_alloc()), -1);

    /* Create default keys if necessary. */

    if (stat(DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX,
             &status) && errno == ENOENT) {
        HIP_IFEL(hip_serialize_host_id_action(user_msg, ACTION_NEW, 0, 1,
                                              NULL, NULL, RSA_KEY_DEFAULT_BITS,
                                              DSA_KEY_DEFAULT_BITS, ECDSA_DEFAULT_CURVE),
                 1, "Failed to create keys to %s\n", HIPL_SYSCONFDIR);
    }

    /* Retrieve the keys to hipd */
    /* Three steps because multiple large keys will not fit in the same message */

    /* DSA keys and RSA anonymous are not loaded by default until bug id
     * 592127 is properly solved. Run hipconf daemon add hi default if you want to
     * enable non-default HITs. */

    /* rsa pub */
    hip_msg_init(user_msg);
    if ((err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
                                            0, 1, "rsa", NULL, 0, 0, 0))) {
        HIP_ERROR("Could not load default keys (RSA pub)\n");
        goto out_err;
    }

    if ((err = hip_handle_add_local_hi(user_msg))) {
        HIP_ERROR("Adding of keys failed (RSA pub)\n");
        goto out_err;
    }

    HIP_DEBUG("Keys added\n");
    hip_get_default_hit(&default_hit);
    hip_get_default_lsi(&default_lsi);

    HIP_DEBUG_HIT("default_hit ", &default_hit);
    HIP_DEBUG_LSI("default_lsi ", &default_lsi);
    hip_hidb_associate_default_hit_lsi(&default_hit, &default_lsi);

out_err:
    free(user_msg);
    return err;
}

/* Needed if the configuration file for certs did not exist  */
#define HIP_CERT_INIT_DAYS 10

/**
 * Initialize certificates for the local host
 *
 * @return zero on success or negative on failure
 */
static int init_certs(void)
{
    int                   err = 0;
    char                  hit[41];
    FILE                 *conf_file;
    struct local_host_id *entry;
    char                  hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

    HIP_IFEL(gethostname(hostname, sizeof(hostname)), -1,
             "gethostname failed\n");

    conf_file = fopen(HIP_CERT_CONF_PATH, "r");
    if (!conf_file) {
        HIP_DEBUG("Configuration file did NOT exist creating it and "
                  "filling it with default information\n");
        /* Fetch the first RSA HIT */
        entry = hip_get_hostid_entry_by_lhi_and_algo(NULL, HIP_HI_RSA, -1);
        if (entry == NULL) {
            HIP_DEBUG("Failed to get the first RSA HI");
            goto out_err;
        }
        hip_in6_ntop(&entry->hit, hit);
        conf_file = fopen(HIP_CERT_CONF_PATH, "w+");
        fprintf(conf_file,
                "# Section containing SPKI related information\n"
                "#\n"
                "# issuerhit = what hit is to be used when signing\n"
                "# days = how long is this key valid\n"
                "\n"
                "[ hip_spki ]\n"
                "issuerhit = %s\n"
                "days = %d\n"
                "\n"
                "# Section containing HIP related information\n"
                "#\n"
                "# issuerhit = what hit is to be used when signing\n"
                "# days = how long is this key valid\n"
                "\n"
                "[ hip_x509v3 ]\n"
                "issuerhit = %s\n"
                "days = %d\n"
                "\n"
                "#Section containing the name section for the x509v3 issuer name"
                "\n"
                "[ hip_x509v3_name ]\n"
                "issuerhit = %s\n"
                "\n"
                "# Uncomment this section to add x509 extensions\n"
                "# to the certificate\n"
                "#\n"
                "# DO NOT use subjectAltName, issuerAltName or\n"
                "# basicConstraints implementation uses them already\n"
                "# All other extensions are allowed\n"
                "\n"
                "# [ hip_x509v3_extensions ]\n",
                hit, HIP_CERT_INIT_DAYS,
                hit, HIP_CERT_INIT_DAYS,
                hit /* TODO SAMU: removed because not used:*/  /*, hostname*/);
    } else {
        HIP_DEBUG("Configuration file existed exiting init_certs\n");
    }
    fclose(conf_file);

out_err:
    return err;
}

static void init_packet_types(void)
{
    lmod_register_packet_type(HIP_I1,        "HIP_I1");
    lmod_register_packet_type(HIP_R1,        "HIP_R1");
    lmod_register_packet_type(HIP_I2,        "HIP_I2");
    lmod_register_packet_type(HIP_R2,        "HIP_R2");
    lmod_register_packet_type(HIP_NOTIFY,    "HIP_NOTIFY");
    lmod_register_packet_type(HIP_CLOSE,     "HIP_CLOSE");
    lmod_register_packet_type(HIP_CLOSE_ACK, "HIP_CLOSE_ACK");
    lmod_register_packet_type(HIP_UPDATE,    "HIP_UPDATE");
    lmod_register_packet_type(HIP_LUPDATE,   "HIP_LUPDATE");
}

static void init_handle_functions(void)
{
    HIP_DEBUG("Initialize handle functions.\n");

    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I1_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I1_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I1_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I1_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I2_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I2_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I2_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_I2_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_R2_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_R2_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_R2_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_R2_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_ESTABLISHED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_ESTABLISHED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_ESTABLISHED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_ESTABLISHED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSING, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSING, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSING, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSING, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_CLOSED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_NONE, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_NONE, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_NONE, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_ALL, HIP_I1, HIP_STATE_NONE, &hip_send_r1,   40000);

    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I1_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_check_i2,             20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_handle_i2_in_i2_sent, 21000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_handle_i2,            30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_I2_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_R2_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_ESTABLISHED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSING, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_CLOSED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_setup_ipsec_sa, 30500);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_ALL, HIP_I2, HIP_STATE_NONE, &hip_send_r2, 50000);

    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I1_SENT, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_I2_SENT, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSING, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_ALL, HIP_R1, HIP_STATE_CLOSED, &hip_send_i2, 50000);

    hip_register_handle_function(HIP_ALL, HIP_R2, HIP_STATE_I2_SENT, &hip_check_r2,  20000);
    hip_register_handle_function(HIP_ALL, HIP_R2, HIP_STATE_I2_SENT, &hip_handle_r2, 30000);
    hip_register_handle_function(HIP_ALL, HIP_R2, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_ALL, HIP_R2, HIP_STATE_I2_SENT, &hip_setup_ipsec_sa, 30500);

    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_I1_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_I1_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_I2_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_I2_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_R2_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_R2_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_ESTABLISHED, &hip_check_notify, 20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_ESTABLISHED, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_CLOSING, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_CLOSING, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_CLOSED, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_ALL, HIP_NOTIFY, HIP_STATE_CLOSED, &hip_handle_notify, 30000);

    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_check_packet,     20000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_update_retransmissions, 25000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_create_response,  30000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_send_response,    40000);

    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_check_packet,     20000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_update_retransmissions, 25000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_create_response,  30000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_send_response,    40000);

    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_close_ack_check_packet,  20000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_update_retransmissions,  25000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_close_ack_handle_packet, 30000);

    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_close_ack_check_packet,  20000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_update_retransmissions,  25000);
    hip_register_handle_function(HIP_ALL, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_close_ack_handle_packet, 30000);

    hip_register_handle_function(HIP_ALL, HIP_LUPDATE, HIP_STATE_ESTABLISHED, &esp_prot_handle_light_update, 20000);
    hip_register_handle_function(HIP_ALL, HIP_LUPDATE, HIP_STATE_R2_SENT,     &esp_prot_handle_light_update, 20000);
}

static int libhip_init_handle_functions(void)
{
    HIP_DEBUG("Initialize handle functions for libhip.\n");

    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_UNASSOCIATED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I1_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I1_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I1_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I1_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I2_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I2_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I2_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_I2_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_R2_SENT, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_R2_SENT, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_R2_SENT, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_R2_SENT, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_ESTABLISHED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_ESTABLISHED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_ESTABLISHED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_ESTABLISHED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSING, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSING, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSING, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSING, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSED, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSED, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSED, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_CLOSED, &hip_send_r1,   40000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_NONE, &hip_check_i1,  20000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_NONE, &hip_handle_i1, 30000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_NONE, &hip_update_retransmissions, 35000);
    hip_register_handle_function(HIP_V1, HIP_I1, HIP_STATE_NONE, &hip_send_r1,   40000);

    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_UNASSOCIATED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I1_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_check_i2,             20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_handle_i2_in_i2_sent, 21000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_handle_i2,            30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_I2_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_R2_SENT, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_ESTABLISHED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSING, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_CLOSED, &hip_send_r2, 50000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_check_i2,  20000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_handle_i2, 30000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_update_retransmissions, 30250);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_create_r2, 40000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_add_rvs_reg_from, 41000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_hmac2_and_sign, 42000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_add_rvs_relay_to, 43000);
    hip_register_handle_function(HIP_V1, HIP_I2, HIP_STATE_NONE, &hip_send_r2, 50000);

    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I1_SENT, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_I2_SENT, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSING, &hip_send_i2,   50000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_check_r1,  20000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_handle_r1, 30000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_update_retransmissions, 30500);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_build_esp_info, 31000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_build_solution, 32000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_handle_diffie_hellman, 33000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &esp_prot_r1_handle_transforms, 34000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_create_i2, 40000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_add_signed_echo_response, 41000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_mac_and_sign_handler, 42000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_add_unsigned_echo_response, 43000);
    hip_register_handle_function(HIP_V1, HIP_R1, HIP_STATE_CLOSED, &hip_send_i2, 50000);

    hip_register_handle_function(HIP_V1, HIP_R2, HIP_STATE_I2_SENT, &hip_check_r2,  20000);
    hip_register_handle_function(HIP_V1, HIP_R2, HIP_STATE_I2_SENT, &hip_handle_r2, 30000);
    hip_register_handle_function(HIP_V1, HIP_R2, HIP_STATE_I2_SENT, &hip_update_retransmissions, 30250);

    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_I1_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_I1_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_I2_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_I2_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_R2_SENT, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_R2_SENT, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_ESTABLISHED, &hip_check_notify, 20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_ESTABLISHED, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_CLOSING, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_CLOSING, &hip_handle_notify, 30000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_CLOSED, &hip_check_notify,  20000);
    hip_register_handle_function(HIP_V1, HIP_NOTIFY, HIP_STATE_CLOSED, &hip_handle_notify, 30000);

    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_check_packet,     20000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_update_retransmissions, 25000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_create_response,  30000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_close_send_response,    40000);

    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_check_packet,     20000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_update_retransmissions, 25000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_create_response,  30000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE, HIP_STATE_CLOSING,  &hip_close_send_response,    40000);

    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_close_ack_check_packet,  20000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_update_retransmissions,  25000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_close_ack_handle_packet, 30000);

    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_close_ack_check_packet,  20000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_update_retransmissions,  25000);
    hip_register_handle_function(HIP_V1, HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_close_ack_handle_packet, 30000);

    hip_register_handle_function(HIP_V1, HIP_LUPDATE, HIP_STATE_ESTABLISHED, &esp_prot_handle_light_update, 20000);
    hip_register_handle_function(HIP_V1, HIP_LUPDATE, HIP_STATE_R2_SENT,     &esp_prot_handle_light_update, 20000);

    return 0;
}

/**
 * set or unset close-on-exec flag for a given file descriptor
 *
 * @param desc the file descriptor
 * @param value 1 if to set or zero for unset
 * @return the previous flags
 */
int set_cloexec_flag(int desc, int value)
{
    int oldflags = fcntl(desc, F_GETFD, 0);
    /* If reading the flags failed, return error indication now.*/
    if (oldflags < 0) {
        return oldflags;
    }
    /* Set just the flag we want to set. */

    if (value != 0) {
        oldflags |=  FD_CLOEXEC;
    } else {
        oldflags &= ~FD_CLOEXEC;
    }
    /* Store modified flag word in the descriptor. */
    return fcntl(desc, F_SETFD, oldflags);
}

/**
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(void)
{
    hip_delete_default_prefix_sp_pair();
    /* Close SAs with all peers */
    // hip_send_close(NULL);

    hip_delete_all_sp();

    hip_delete_all_addresses();

    set_up_device(HIP_HIT_DEV, 0);
    hip_remove_iface_all_local_hits();

    /* Next line is needed only if RVS or hiprelay is in use. */
    hip_uninit_services();

    hip_uninit_handle_functions();

    hip_user_uninit_handles();

    hip_uninit_maint_functions();

    lmod_uninit_packet_types();

    lmod_uninit_parameter_types();

    lmod_uninit_state_init_functions();

    lmod_uninit_state_uninit_functions();

#ifdef CONFIG_HIP_RVS
    HIP_INFO("Uninitializing RVS / HIP relay database and whitelist.\n");
    hip_relay_uninit();
#endif

    if (hip_raw_sock_input_v6) {
        HIP_INFO("hip_raw_sock_input_v6\n");
        close(hip_raw_sock_input_v6);
    }

    if (hip_raw_sock_output_v6) {
        HIP_INFO("hip_raw_sock_output_v6\n");
        close(hip_raw_sock_output_v6);
    }

    if (hip_raw_sock_input_v4) {
        HIP_INFO("hip_raw_sock_input_v4\n");
        close(hip_raw_sock_input_v4);
    }

    if (hip_raw_sock_output_v4) {
        HIP_INFO("hip_raw_sock_output_v4\n");
        close(hip_raw_sock_output_v4);
    }

    if (hip_nat_sock_input_udp) {
        HIP_INFO("hip_nat_sock_input_udp\n");
        close(hip_nat_sock_input_udp);
    }

    if (hip_nat_sock_output_udp) {
        HIP_INFO("hip_nat_sock_output_udp\n");
        close(hip_nat_sock_output_udp);
    }

    if (hip_nat_sock_input_udp_v6) {
        HIP_INFO("hip_nat_sock_input_udp_v6\n");
        close(hip_nat_sock_input_udp_v6);
    }

    if (hip_nat_sock_output_udp_v6) {
        HIP_INFO("hip_nat_sock_output_udp_v6\n");
        close(hip_nat_sock_output_udp_v6);
    }

    hip_uninit_hadb();
    hip_uninit_host_id_dbs();

    if (hip_user_sock) {
        HIP_INFO("hip_user_sock\n");
        close(hip_user_sock);
    }
    if (hip_nl_ipsec.fd) {
        HIP_INFO("hip_nl_ipsec.fd\n");
        rtnl_close(&hip_nl_ipsec);
    }
    if (hip_nl_route.fd) {
        HIP_INFO("hip_nl_route.fd\n");
        rtnl_close(&hip_nl_route);
    }

    hip_remove_lock_file(HIP_DAEMON_LOCK_FILE);

#ifdef CONFIG_HIP_PERFORMANCE
    /* Deallocate memory of perf_set after finishing all of tests */
    hip_perf_destroy(perf_set);
#endif

    hip_unregister_sockets();

    hip_dh_uninit();

    lmod_uninit_disabled_modules();
}

/**
 * Signal handler: exit gracefully by sending CLOSE to all peers
 *
 * @param signum signal the signal hipd received from OS
 */
static void hip_close(int signum)
{
    static int terminate = 0;

    HIP_ERROR("Caught signal: %d\n", signum);
    terminate++;

    /* Close SAs with all peers */
    if (terminate == 1) {
        hip_send_close(NULL, 1);
        hipd_set_state(HIPD_STATE_CLOSING);
        HIP_DEBUG("Starting to close HIP daemon...\n");
    } else if (terminate == 2) {
        HIP_DEBUG("Send still once this signal to force daemon exit...\n");
    } else if (terminate > 2) {
        HIP_DEBUG("Terminating daemon.\n");
        hip_exit();
        exit(EXIT_SUCCESS);
    }
}

/**
 * Main initialization function for HIP daemon.
 * @param flags startup flags
 * @return      zero on success or negative on failure
 */
int hipd_init(const uint64_t flags)
{
    int                 err     = 0, certerr = 0, i, j;
    int                 killold = (flags & HIPD_START_KILL_OLD) > 0;
    unsigned int        mtu_val = HIP_HIT_DEV_MTU;
    char                str[64];
    struct sockaddr_in6 daemon_addr = { 0 };

    /* Keep the flags around: they will be used at kernel module removal */
    sflags = flags;

    /* Open daemon lock file and read pid from it. */
    HIP_IFEL(hip_create_lock_file(HIP_DAEMON_LOCK_FILE, killold), -1,
             "locking failed\n");

    hip_init_hostid_db();

    set_os_dep_variables();

    init_packet_types();

    init_handle_functions();

    hip_register_maint_function(&hip_nat_refresh_port,         10000);
    hip_register_maint_function(&hip_relht_maintenance,        20000);
    hip_register_maint_function(&hip_registration_maintenance, 30000);

    if (sflags & HIPD_START_LOAD_KMOD) {
        err = probe_kernel_modules();
        if (err) {
            HIP_ERROR("Unable to load the required kernel modules!\n");
            goto out_err;
        }
    }

    /* Register signal handlers */
    signal(SIGINT, hip_close);
    signal(SIGTERM, hip_close);
    signal(SIGCHLD, sig_chld);

    HIP_IFEL(hip_init_cipher() < 0, -1, "Unable to init ciphers.\n");

    HIP_IFE(init_random_seed(), -1);

    hip_init_hadb();

    /* Resolve our current addresses, afterwards the events from kernel
     * will maintain the list. This needs to be done before opening
     * NETLINK_ROUTE! See the comment about address_count global var. */
    HIP_DEBUG("Initializing the netdev_init_addresses\n");

    hip_netdev_init_addresses();

    if (rtnl_open_byproto(&hip_nl_route,
                          RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
                          | RTMGRP_IPV4_IFADDR | IPPROTO_IP,
                          NETLINK_ROUTE) < 0) {
        err = 1;
        HIP_ERROR("Routing socket error: %s\n", strerror(errno));
        goto out_err;
    }

    /* Open the netlink socket for address and IF events */
    if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0) {
        HIP_ERROR("Netlink address and IF events socket error: %s\n",
                  strerror(errno));
        err = 1;
        goto out_err;
    }

    hip_xfrm_set_nl_ipsec(&hip_nl_ipsec);

    hip_raw_sock_output_v6 = init_raw_sock_v6(IPPROTO_HIP);
    HIP_IFEL(hip_raw_sock_output_v6 < 0, -1, "raw sock output v6\n");

    hip_raw_sock_output_v4 = init_raw_sock_v4(IPPROTO_HIP);
    HIP_IFEL(hip_raw_sock_output_v4 < 0, -1, "raw sock output v4\n");

    /* hip_nat_sock_input should be initialized after hip_nat_sock_output
     * because for the sockets bound to the same address/port, only the last
     * socket seems to receive the packets. The NAT input socket is a normal
     * UDP socket whereas NAT output socket is a raw socket. A raw output
     * socket better supports the "shotgun" extension (sending packets
     * from multiple source addresses). */

    hip_nat_sock_output_udp = init_raw_sock_v4(IPPROTO_UDP);
    HIP_IFEL(hip_nat_sock_output_udp < 0, -1, "raw sock output udp\n");

    hip_raw_sock_input_v6 = init_raw_sock_v6(IPPROTO_HIP);
    HIP_IFEL(hip_raw_sock_input_v6 < 0, -1, "raw sock input v6\n");

    hip_raw_sock_input_v4 = init_raw_sock_v4(IPPROTO_HIP);
    HIP_IFEL(hip_raw_sock_input_v4 < 0, -1, "raw sock input v4\n");

    HIP_IFEL(hip_create_nat_sock_udp(&hip_nat_sock_input_udp, 0, 0), -1, "raw sock input udp\n");

    HIP_DEBUG("hip_raw_sock_v6 input = %d\n",   hip_raw_sock_input_v6);
    HIP_DEBUG("hip_raw_sock_v6 output = %d\n",  hip_raw_sock_output_v6);
    HIP_DEBUG("hip_raw_sock_v4 input = %d\n",   hip_raw_sock_input_v4);
    HIP_DEBUG("hip_raw_sock_v4 output = %d\n",  hip_raw_sock_output_v4);
    HIP_DEBUG("hip_nat_sock_udp input = %d\n",  hip_nat_sock_input_udp);
    HIP_DEBUG("hip_nat_sock_udp output = %d\n", hip_nat_sock_output_udp);

    if (flags & HIPD_START_FLUSH_IPSEC) {
        hip_flush_all_sa();
        hip_flush_all_policy();
    }

    HIP_DEBUG("Setting SP\n");
    hip_delete_default_prefix_sp_pair();
    HIP_IFE(hip_setup_default_sp_prefix_pair(), -1);

    HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
    set_up_device(HIP_HIT_DEV, 0);
    HIP_IFE(set_up_device(HIP_HIT_DEV, 1), -1);
    HIP_DEBUG("Lowering MTU of dev " HIP_HIT_DEV " to %u\n", mtu_val);
    snprintf(str, sizeof(str), "ifconfig %s mtu %u", HIP_HIT_DEV, mtu_val);
    /* MTU is set using system call rather than in do_chflags to avoid
     * chicken and egg problems in hipd start up. */
    if (system(str) == -1) {
        HIP_ERROR("Exec %s failed", str);
    }


    HIP_IFE(init_host_ids(), -1);

    hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL(hip_user_sock < 0, -1,
             "Could not create socket for user communication.\n");
    daemon_addr.sin6_family = AF_INET6;
    daemon_addr.sin6_port   = htons(HIP_DAEMON_LOCAL_PORT);
    daemon_addr.sin6_addr   = in6addr_loopback;
    set_cloexec_flag(hip_user_sock, 1);

    HIP_IFEL(bind(hip_user_sock, (struct sockaddr *) &daemon_addr,
                  sizeof(daemon_addr)), -1,
             "Bind on daemon addr failed\n");

    const char *cfile = "default";
    if (hip_conf_handle_load(NULL, 0, &cfile, 1, 1) == -1) {
        HIP_ERROR("Loading configuration file failed.\n");
        return -1;
    }

    certerr = 0;
    certerr = init_certs();
    if (certerr < 0) {
        HIP_DEBUG("Initializing cert configuration file returned error\n");
    }

    /* Service initialization. */
    hip_init_services();

#ifdef CONFIG_HIP_RVS
    HIP_INFO("Initializing HIP relay / RVS.\n");
    if (hip_relay_init() == -ENOENT) {
        return -ENOENT;
    }
#endif

#ifndef CONFIG_HIP_ANDROID
    if (flags & HIPD_START_LOWCAP) {
        HIP_IFEL(hip_set_lowcapability(), -1, "Failed to set capabilities\n");
    }
#endif /* CONFIG_HIP_ANDROID */

    if (hip_get_nsupdate_status()) {
        nsupdate(1);
    }

    /* Initialize modules */
    HIP_INFO("Initializing modules.\n");
    for (i = 0; i < hipd_num_modules; i++) {
        HIP_DEBUG("module: %s\n", hipd_modules[i].name);
        if (lmod_module_disabled(hipd_modules[i].name)) {
            HIP_DEBUG("state:  DISABLED\n");
            continue;
        } else {
            HIP_DEBUG("state:  ENABLED\n");
            /* Check dependencies */
            for (j = 0; j < hipd_modules[i].num_required_modules; j++) {
                HIP_IFEL(lmod_module_disabled(hipd_modules[i].required_modules_hipd[j]),
                         -1,
                         "The module <%s> is required by <%s>, but was disabled.\n",
                         hipd_modules[i].required_modules_hipd[j],
                         hipd_modules[i].name);
            }
        }
        HIP_IFEL(hipd_modules[i].init_function(),
                 -1,
                 "Module initialization failed.\n");
    }

    hip_register_sockets();

out_err:
    return err;
}

/**
 * Initialization function for libhipl.
 *
 * @param debug_level debug level for log output.
 * @return            0 on success, negative number on error.
 */
int hipl_lib_init(enum logdebug debug_level)
{
    int                err         = 0;
    int                keypath_len = 0;
    char              *key_path    = NULL;
    struct hip_common *msg         = NULL;
    struct passwd     *pwd;

    hipl_set_libhip_mode();
    hip_nat_status = 1;

    /* disable hip_firewall */
    lsi_status = HIP_MSG_LSI_OFF;

    hip_set_logdebug(debug_level);

    hip_init_hadb();
    hip_init_hostid_db();
    hip_netdev_init_addresses();
    libhip_init_handle_functions();

    /* Load default key from ~/.hipl/ */
    if ((pwd = getpwuid(getuid())) == NULL) {
        return -1;
    }

    /* +3 because we need 2 slashes and a NULL for termination */
    keypath_len = strlen(pwd->pw_dir) +
                  strlen(HIPL_USER_DIR) +
                  strlen(HIPL_USER_RSA_KEY_NAME) +
                  strlen(DEFAULT_PUB_HI_FILE_NAME_SUFFIX) + 3;
    if ((key_path = malloc(keypath_len)) == NULL) {
        HIP_ERROR("malloc() failed\n");
        return -ENOMEM;
    }

    HIP_IFEL(snprintf(key_path, keypath_len, "%s/%s/%s%s", pwd->pw_dir,
                      HIPL_USER_DIR,
                      HIPL_USER_RSA_KEY_NAME,
                      DEFAULT_PUB_HI_FILE_NAME_SUFFIX) < 0,
             -1, "snprintf() failed");

    HIP_DEBUG("Using key: %s\n", key_path);
    HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "hip_msg_alloc()");
    if (hip_serialize_host_id_action(msg, ACTION_ADD, 0, 0, "rsa",
                                     key_path, 0, 0, 0)) {
        hip_msg_init(msg);
        HIP_IFEL(hip_serialize_host_id_action(msg, ACTION_NEW, 0, 0, "rsa",
                                              key_path, RSA_KEY_DEFAULT_BITS,
                                              DSA_KEY_DEFAULT_BITS,
                                              ECDSA_DEFAULT_CURVE), -1,
                 "Fail to create local key at %s.", key_path);

        hip_msg_init(msg);
        HIP_IFEL(hip_serialize_host_id_action(msg, ACTION_ADD, 0, 0, "rsa",
                                              key_path, 0, 0, 0), -1,
                 "Fail to load local key at %s.", key_path);
    }
    HIP_IFE(hip_handle_add_local_hi(msg), -1);

out_err:
    free(msg);
    free(key_path);
    return err;
}

/**
 * create a socket to handle UDP encapsulation of HIP control
 * packets
 *
 * @param hip_nat_sock_udp the socket to initialize
 * @param addr the address to which the socket should be bound
 * @param is_output one if the socket is to be used for output
 *                  or zero for input
 * @return zero on success or negative on failure
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output)
{
    int                on = 1, off = 0, err = 0;
    struct sockaddr_in myaddr;
    int                type, protocol;

    if (is_output) {
        type     = SOCK_RAW;
        protocol = IPPROTO_UDP;
    } else {
        type     = SOCK_DGRAM;
        protocol = 0;
    }

    HIP_DEBUG("\n");

    if ((*hip_nat_sock_udp = socket(AF_INET, type, protocol)) < 0) {
        HIP_ERROR("Can not open socket for UDP\n");
        return -1;
    }
    set_cloexec_flag(*hip_nat_sock_udp, 1);
    err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp pktinfo failed\n");
    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp recverr failed\n");
    if (!is_output) {
        int encap_on = HIP_UDP_ENCAP_ESPINUDP;
        err = setsockopt(*hip_nat_sock_udp, SOL_UDP, HIP_UDP_ENCAP, &encap_on, sizeof(encap_on));
    }
    HIP_IFEL(err, -1, "setsockopt udp encap failed\n");
    err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");
    err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");

    if (is_output) {
        err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on));
    }
    HIP_IFEL(err, -1, "setsockopt hdr include failed\n");

    if (addr) {
        memcpy(&myaddr, addr, sizeof(struct sockaddr_in));
    } else {
        myaddr.sin_family = AF_INET;
        /** @todo Change this inaddr_any -- Abi */
        myaddr.sin_addr.s_addr = INADDR_ANY;
        myaddr.sin_port        = htons(hip_get_local_nat_udp_port());
    }

    err = bind(*hip_nat_sock_udp, (struct sockaddr *) &myaddr, sizeof(myaddr));
    if (err < 0) {
        HIP_PERROR("Unable to bind udp socket to port\n");
        err = -1;
        goto out_err;
    }

    HIP_DEBUG_INADDR("UDP socket created and bound to addr", (struct in_addr *) &myaddr.sin_addr.s_addr);

out_err:
    return err;
}

/**
 * Set the default HIP version to be used for outgoing I1 messages.
 *
 * @param version HIP version to be used in I1 message by default. It should
 *                be greater than 0 and less than the @c HIP_MAX_VERSION.
 * @return 0 on success, -1 on failure.
 */
int hip_set_default_version(uint8_t version)
{
    if (version <= 0 || version >= HIP_MAX_VERSION) {
        HIP_ERROR("invalid default-hip-version: %d", version);
        return -1;
    }

    hip_default_hip_version = version;

    return 0;
}

/**
 * Get the default HIP verison parameter.
 *
 * @return the default HIP version.
 */
uint8_t hip_get_default_version(void)
{
    return hip_default_hip_version;
}
