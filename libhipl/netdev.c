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
 * This file contains a collection of address management related functions including:
 * - an up-to-date cache of localhost addresses
 * - whitelist functionality to exclude some (e.g. expensive or incompatible) network interfaces
 *   from the cache
 * - utility functions for couting, searching, deleting and adding addresses from the cache
 * - automatic determination of source address for a packet if one has not been given (source
 *   routing)
 * - automatic mapping of a remote HIT or LSI to its corresponding IP address(es) through
 *   HADB, hosts files or DNS when no mapping was not given (e.g. in referral scenarios)
 * - triggering of base exchange
 *
 * @brief Localhost address cache and related management functions
 */

#define _BSD_SOURCE

#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>

/* Needed for in6_addr on android but conflicts with netinet/in.h on linux */
#ifdef CONFIG_HIP_ANDROID
#include <linux/in6.h>
#endif /* CONFIG_HIP_ANDROID */

#include "libcore/builder.h"
#include "libcore/common.h"
#include "libcore/conf.h"
#include "libcore/debug.h"
#include "libcore/hip_udp.h"
#include "libcore/hit.h"
#include "libcore/hostsfiles.h"
#include "libcore/ife.h"
#include "libcore/linkedlist.h"
#include "libcore/list.h"
#include "libcore/prefix.h"
#include "libcore/gpl/nlink.h"
#include "config.h"
#include "accessor.h"
#include "hadb.h"
#include "init.h"
#include "hidb.h"
#include "hipd.h"
#include "hit_to_ip.h"
#include "maintenance.h"
#include "output.h"
#include "netdev.h"


/**
 * We really don't expect more than a handfull of interfaces to be on
 * our white list.
 */
#define HIP_NETDEV_MAX_WHITE_LIST 5

#define FA_IGNORE 0
#define FA_ADD 1

/** Maximum lenght of the address family string */
#define FAM_STR_MAX               32

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec;
/** For getting/setting routes and adding HITs (it was not possible to use
 *  nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route;

/* We are caching the IP addresses of the host here. The reason is that during
 * in hip_handle_acquire it is not possible to call getifaddrs (it creates
 * a new netlink socket and seems like only one can be open per process).
 * Feel free to experiment by porting the required functionality from
 * iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
 * variable and most of the functions referencing them unnecessary -miika
 */
int            address_count;
HIP_HASHTABLE *addresses;

int hip_broadcast_status = HIP_MSG_BROADCAST_OFF;

int hip_use_userspace_data_packet_mode =  0;
/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
 *  0 = none = default, AF_INET, AF_INET6 */
int suppress_af_family =  0;
/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. */
hip_transform_suite hip_nat_status                     =  0;
int                 address_change_time_counter        = -1;
int                 hip_wait_addr_changes_to_stabilize =  1;

/**
 * This is the white list. For every interface, which is in our white list,
 * this array has a fixed size, because there seems to be no need at this
 * moment to deal with dynamic memory - which would complicate the code
 * and cost size and performance at least equal if not more to this fixed
 * size array.
 * Free slots are signaled by the value -1.
 */
static int hip_netdev_white_list[HIP_NETDEV_MAX_WHITE_LIST];
static int hip_netdev_white_list_count = 0;

/**
 * Add a network interface index number to the list of white listed
 * network interfaces.
 *
 * @param if_index the network interface index to be white listed
 */
static void netdev_white_list_add_index(int if_index)
{
    if (hip_netdev_white_list_count < HIP_NETDEV_MAX_WHITE_LIST) {
        hip_netdev_white_list[hip_netdev_white_list_count++] = if_index;
    } else {
        /* We should NEVER run out of white list slots!!! */
        HIP_DIE("Error: ran out of space for white listed interfaces!\n");
    }
}

/**
 * Test if the given network interface index is white listed.
 *
 * @param if_index the index of the network interface to be tested
 * @return 1 if the index is whitelisted or zero otherwise
 */
static int netdev_is_in_white_list(int if_index)
{
    int i = 0;
    for (i = 0; i < hip_netdev_white_list_count; i++) {
        if (hip_netdev_white_list[i] == if_index) {
            return 1;
        }
    }
    return 0;
}

/**
 * Add a network interface index number to the list of white listed
 * network interfaces by name.
 *
 * @param device_name the name of the device to be white listed
 * @return 1 on success, 0 on error
 */
int hip_netdev_white_list_add(const char *const device_name)
{
    struct ifreq ifr;
    int          sock = 0;
    int          ret  = 0;

    strncpy(ifr.ifr_name, device_name, IF_NAMESIZE);
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) {
        ret = 1;
        netdev_white_list_add_index(ifr.ifr_ifindex);
        HIP_DEBUG("Adding device <%s> to white list with index <%i>.\n",
                  device_name,
                  ifr.ifr_ifindex);
    } else {
        ret = 0;
    }

    if (sock) {
        close(sock);
    }
    return ret;
}

/**
 * hash function for the addresses hash table
 *
 * @param ptr a pointer to a netdev_address structure
 * @return the calculated hash to index the parameter
 */
static unsigned long netdev_hash(const void *ptr)
{
    const struct netdev_address *na = (const struct netdev_address *) ptr;
    union hip_hash               hash;

    /* TODO: A cryptographically secure hash is unnecessarily expensive for
     * a hash table. Something cheaper, like an XOR, would do just fine. */
    hip_build_digest(HIP_DIGEST_SHA1, &na->addr,
                     sizeof(struct sockaddr_storage), hash.serialized);

    /* TODO: Returning only a long is all the more reason to move
     * to a cheaper hash function. */
    return hash.chunked[0];
}

/**
 * equality function for the addresses hash table
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1 a pointer to a netdev_address structure
 * @param ptr2 a pointer to a netdev_address structure
 * @return 0 if the given pointers match or 1 otherwise
 */
static int netdev_match(const void *ptr1, const void *ptr2)
{
    const struct netdev_address *na1 = (const struct netdev_address *) ptr1;
    const struct netdev_address *na2 = (const struct netdev_address *) ptr2;
    return memcmp(&na1->addr, &na2->addr, sizeof(na1->addr));
}

/**
 * Filters addresses that are allowed for this host.
 *
 * @param addr a pointer to a socket address structure.
 * @return     FA_ADD if the given address @c addr is allowed to be one of the
 *             addresses of this host, FA_IGNORE otherwise.
 */
static int filter_address(const struct sockaddr *const addr)
{
    char                   s[INET6_ADDRSTRLEN];
    const struct in6_addr *a_in6;
    in_addr_t              a_in;
    HIP_DEBUG("Filtering the address family %d \n", addr->sa_family);
    switch (addr->sa_family) {
    case AF_INET6:
        a_in6 = &((const struct sockaddr_in6 *) addr)->sin6_addr;
        inet_ntop(AF_INET6, a_in6, s, INET6_ADDRSTRLEN);

        HIP_DEBUG("IPv6 address to filter is %s.\n", s);

        if (suppress_af_family == AF_INET) {
            HIP_DEBUG("Address ignored: address family "
                      "suppression set to IPv4 addresses.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_UNSPECIFIED(a_in6)) {
            HIP_DEBUG("Address ignored: UNSPECIFIED.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_LOOPBACK(a_in6)) {
            HIP_DEBUG("Address ignored: IPV6_LOOPBACK.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_MULTICAST(a_in6)) {
            HIP_DEBUG("Address ignored: MULTICAST.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_LINKLOCAL(a_in6)) {
            HIP_DEBUG("Address ignored: LINKLOCAL.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_V4MAPPED(a_in6)) {
            HIP_DEBUG("Address ignored: V4MAPPED.\n");
            return FA_IGNORE;
        } else if (IN6_IS_ADDR_V4COMPAT(a_in6)) {
            HIP_DEBUG("Address ignored: V4COMPAT.\n");
            return FA_IGNORE;
        } else if (ipv6_addr_is_hit(a_in6)) {
            HIP_DEBUG("Address ignored: address is HIT.\n");
            return FA_IGNORE;
        } else {
            return FA_ADD;
        }
        break;

    case AF_INET:
        a_in = ((const struct sockaddr_in *) addr)->sin_addr.s_addr;
        inet_ntop(AF_INET, &((const struct sockaddr_in *) addr)->sin_addr, s,
                  INET6_ADDRSTRLEN);

        HIP_DEBUG("IPv4 address to filter is %s.\n", s);

        if (suppress_af_family == AF_INET6) {
            HIP_DEBUG("Address ignored: address family "
                      "suppression set to IPv6 addresses.\n");
            return FA_IGNORE;
        } else if (a_in == INADDR_ANY) {
            HIP_DEBUG("Address ignored: INADDR_ANY.\n");
            return FA_IGNORE;
        } else if (a_in == INADDR_BROADCAST) {
            HIP_DEBUG("Address ignored: INADDR_BROADCAST.\n");
            return FA_IGNORE;
        } else if (IN_MULTICAST(ntohs(a_in))) {
            HIP_DEBUG("Address ignored: MULTICAST.\n");
            return FA_IGNORE;
        } else if (IS_LSI32(a_in)) {
            HIP_DEBUG("Address ignored: LSI32.\n");
            return FA_IGNORE;
        } else if (IS_IPV4_LOOPBACK(a_in)) {
            HIP_DEBUG("Address ignored: IPV4_LOOPBACK.\n");
            return FA_IGNORE;
        } else if (IS_LSI((const struct sockaddr_in *) addr)) {
            HIP_DEBUG("Address ignored: address is LSI.\n");
            return FA_IGNORE;
        } else {
            return FA_ADD;
        }
        break;

    default:
        HIP_DEBUG("Address ignored: address family is unknown.\n");
        return FA_IGNORE;
    }
}

/**
 * Test if the given address family exists in the list of cached addresses of the localhost.
 * Can be used to e.g. determine if it possible to send a packet to a peer because both
 * parties should have a matching IP address family.
 *
 * @param addr addr the address to be tested (IPv4 address in IPv6 mapped format) for family
 * @return one if the address is recorded in the cache and zero otherwise
 */
static int exists_address_family_in_list(const struct in6_addr *addr)
{
    struct netdev_address *n;
    LHASH_NODE            *tmp, *t;
    int                    c;
    int                    mapped = IN6_IS_ADDR_V4MAPPED(addr);

    list_for_each_safe(tmp, t, addresses, c) {
        n = list_entry(tmp);

        if (IN6_IS_ADDR_V4MAPPED((const struct in6_addr *) hip_cast_sa_addr((struct sockaddr *) &n->addr)) == mapped) {
            return 1;
        }
    }

    return 0;
}

/**
 * Test if the given address with the given network interface index exists in the cache
 *
 * @param addr A sockaddr structure containing the address to be checked. An IPv6 socket
 *             address structure can also contain an IPv4 address in IPv6-mapped format.
 * @param ifindex the network interface index
 * @return one if the index exists in the cache or zero otherwise
 */
int hip_exists_address_in_list(struct sockaddr *addr, int ifindex)
{
    struct netdev_address *n;
    LHASH_NODE            *tmp, *t;
    int                    c;
    int                    err = 0;
    const struct in6_addr *in6;
    const struct in_addr  *in;

    list_for_each_safe(tmp, t, addresses, c) {
        int mapped       = 0;
        int addr_match   = 0;
        int family_match = 0;
        n = list_entry(tmp);

        mapped = hip_sockaddr_is_v6_mapped((struct sockaddr *) (&n->addr));
        HIP_DEBUG("mapped=%d\n", mapped);

        if (mapped) {
            in6 = hip_cast_sa_addr((struct sockaddr *) (&n->addr));

            HIP_IFEL(!(in = hip_cast_sa_addr(addr)),
                     -1, "unable to cast address\n");

            addr_match   = IPV6_EQ_IPV4(in6, in);
            family_match = 1;
        } else if (!mapped && addr->sa_family == AF_INET6) {
            addr_match = !memcmp(hip_cast_sa_addr((struct sockaddr *) &n->addr),
                                 hip_cast_sa_addr(addr),
                                 hip_sa_addr_len(&n->addr));
            family_match = n->addr.ss_family == addr->sa_family;
        } else { /* addr->sa_family == AF_INET */
            HIP_DEBUG("Addr given was not IPv6 nor IPv4.\n");
        }

        HIP_DEBUG("n->addr.ss_family=%d, addr->sa_family=%d, "
                  "n->if_index=%d, ifindex=%d\n",
                  n->addr.ss_family, addr->sa_family, n->if_index, ifindex);
        if (n->addr.ss_family == AF_INET6) {
            HIP_DEBUG_IN6ADDR("addr6", hip_cast_sa_addr((struct sockaddr *) (&n->addr)));
        } else if (n->addr.ss_family == AF_INET) {
            HIP_DEBUG_INADDR("addr4", hip_cast_sa_addr((struct sockaddr *) (&n->addr)));
        }
        if ((n->if_index == ifindex || ifindex == -1) &&
            family_match && addr_match) {
            HIP_DEBUG("Address exist in the list\n");

            err = 1;
            goto out_err;
        }
    }

    HIP_DEBUG("Address does not exist in the list\n");

out_err:
    return err;
}

/**
 * Add an address to the address cache of localhost addresses. IPv4
 * addresses can be in the IPv6 mapped format. Also rendezvous and
 * relay addresses may be added here to include them in address
 * advertisements (UPDATE control message with a LOCATOR parameter) to
 * peers.
 *
 * @param addr a pointer to a socket address structure.
 * @param ifindex network device interface index.
 * @param flags flags
 */
void hip_add_address_to_list(struct sockaddr *addr, int ifindex, int flags)
{
    struct netdev_address *n;

    if (hip_exists_address_in_list(addr, ifindex)) {
        return;
    }

    /* filter_address() prints enough debug info of the address, no need to
     * print address related debug info here. */
    if (filter_address(addr)) {
        HIP_DEBUG("Address passed the address filter test.\n");
    } else {
        HIP_DEBUG("Address failed the address filter test.\n");
        return;
    }

    if ((n = calloc(1, sizeof(struct netdev_address))) == NULL) {
        HIP_ERROR("Error when allocating memory to a network device address.\n");
        return;
    }

    /* Convert IPv4 address to IPv6 */
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in6 temp = { 0 };
        temp.sin6_family = AF_INET6;
        IPV4_TO_IPV6_MAP(&((struct sockaddr_in *) addr)->sin_addr,
                         &temp.sin6_addr);
        memcpy(&n->addr, &temp, hip_sockaddr_len(&temp));
    } else {
        memcpy(&n->addr, addr, hip_sockaddr_len(addr));
    }

    n->if_index = ifindex;
    list_add(n, addresses);
    address_count++;
    n->flags = flags;

    HIP_DEBUG("Added a new IPv6 address to ifindex2spi map. The map has "
              "%d addresses.\n", address_count);
}

/**
 * Delete an address from address cache of localhost addresses
 *
 * @param addr A sockaddr structure containing the address to be deleted.
 *             IPv4 addresses can be in IPv6-mapped format.
 * @param ifindex the network interface on which the address is attached to
 */
static void delete_address_from_list(struct sockaddr *addr, int ifindex)
{
    struct netdev_address *n;
    LHASH_NODE            *item, *tmp;
    int                    i, deleted = 0;
    struct sockaddr_in6    addr_sin6;

    if (addr && addr->sa_family == AF_INET) {
        addr_sin6.sin6_family = AF_INET6;
        IPV4_TO_IPV6_MAP(((struct in_addr *) hip_cast_sa_addr(addr)),
                         ((struct in6_addr *) hip_cast_sa_addr((struct sockaddr *) &addr_sin6)));
    } else if (addr && addr->sa_family == AF_INET6) {
        memcpy(&addr_sin6, addr, sizeof(addr_sin6));
    }

    HIP_DEBUG_HIT("Address to delete = ", hip_cast_sa_addr((struct sockaddr *) &addr_sin6));

    list_for_each_safe(item, tmp, addresses, i) {
        n       = list_entry(item);
        deleted = 0;
        /* remove from list if if_index matches */
        if (!addr) {
            if (n->if_index == ifindex) {
                HIP_DEBUG_IN6ADDR("Deleting address",
                                  hip_cast_sa_addr((struct sockaddr *) &n->addr));
                list_del(n, addresses);
                deleted = 1;
            }
        } else {
            /* remove from list if address matches */
            if (ipv6_addr_cmp(hip_cast_sa_addr((struct sockaddr *) &n->addr),
                              hip_cast_sa_addr((struct sockaddr *) &addr_sin6)) == 0) {
                HIP_DEBUG_IN6ADDR("Deleting address",
                                  hip_cast_sa_addr((struct sockaddr *) &n->addr));
                list_del(n, addresses);
                deleted = 1;
            }
        }
        if (deleted) {
            address_count--;
        }
    }

    if (address_count < 0) {
        HIP_ERROR("BUG: address_count < 0\n", address_count);
    }
}

/**
 * Delete and deallocate the address cache
 */
void hip_delete_all_addresses(void)
{
    struct netdev_address *n;
    LHASH_NODE            *item, *tmp;
    int                    i;

    if (address_count) {
        list_for_each_safe(item, tmp, addresses, i)
        {
            n = list_entry(item);
            HIP_DEBUG_HIT("address to be deleted\n", hip_cast_sa_addr((struct sockaddr *) &n->addr));
            list_del(n, addresses);
            free(n);
            address_count--;
        }
        if (address_count != 0) {
            HIP_DEBUG("address_count %d != 0\n", address_count);
        }
    }
    hip_ht_uninit(addresses);
}

/**
 * Get the interface index of a socket address.
 *
 * @param addr a pointer to a socket address whose interface index is to be
 *              searched.
 * @return interface index if the network address is bound to one, zero if
 *         no interface index was found.
 */
static int netdev_find_if(struct sockaddr *addr)
{
    struct netdev_address *n    = NULL;
    LHASH_NODE            *item = NULL, *tmp = NULL;
    int                    i    = 0;

#ifdef CONFIG_HIP_DEBUG /* Debug block. */
    {
        char ipv6_str[INET6_ADDRSTRLEN] = { 0 };
        char fam_str[FAM_STR_MAX];

        if (addr->sa_family == AF_INET6) {
            strncpy(fam_str, "AF_INET6", FAM_STR_MAX);
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *) addr)->sin6_addr,
                      ipv6_str, INET6_ADDRSTRLEN);
        } else if (addr->sa_family == AF_INET) {
            strncpy(fam_str, "AF_INET", FAM_STR_MAX);
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *) addr)->sin_addr,
                      ipv6_str, INET6_ADDRSTRLEN);
        } else {
            strncpy(fam_str, "not AF_INET or AF_INET6", FAM_STR_MAX);
        }

        HIP_DEBUG("Trying to find interface index for a network "
                  "device with IP address %s of address family %s.\n",
                  ipv6_str, fam_str);
    }
#endif
    /* Loop through all elements in list "addresses" and break if the loop
     * address matches the search address. The "addresses" list stores
     * socket address storages. */
    list_for_each_safe(item, tmp, addresses, i)
    {
        n = list_entry(item);
        if (((n->addr.ss_family == addr->sa_family) &&
             ((memcmp(hip_cast_sa_addr((struct sockaddr *) &n->addr),
                      hip_cast_sa_addr(addr),
                      hip_sa_addr_len(addr)) == 0))) ||
            IPV6_EQ_IPV4(&((struct sockaddr_in6 *) &n->addr)->sin6_addr,
                         &((struct sockaddr_in *) addr)->sin_addr)) {
            HIP_DEBUG("Matching network device index is %d.\n", n->if_index);
            return n->if_index;
        }
    }

    HIP_DEBUG("No matching network device index found.\n");
    return 0;
}

/**
 * Get interface index of the given network address.
 *
 * Base exchange IPv6 addresses need to be put into ifindex2spi map, so we need
 * a function that gets the ifindex of the network device which has the address
 * @c addr.
 *
 * @param  addr a pointer to an IPv6 address whose interface index is to be
 *              searched.
 * @return interface index if the network address is bound to one, zero if
 *         no interface index was found and negative in error case.
 * @todo The caller of this should be generalized to both IPv4 and IPv6
 *       so that this function can be removed (tkoponen).
 */
int hip_devaddr2ifindex(struct in6_addr *addr)
{
    struct sockaddr_in6 a;
    a.sin6_family = AF_INET6;
    ipv6_addr_copy(&a.sin6_addr, addr);
    return netdev_find_if((struct sockaddr *) &a);
}

/**
 * Initialize the address cache of localhost addresses
 *
 * @return zero on success and non-zero on error
 * @todo This creates a new NETLINK socket (via getifaddrs), so this has to be
 *       run before the global NETLINK socket is opened. We did not have the time
 *       and energy to import all of the necessary functionality from iproute2.
 */
int hip_netdev_init_addresses(void)
{
    struct ifaddrs *g_ifaces = NULL, *g_iface = NULL;
    int             err      = 0, if_index = 0;

    /* Initialize address list */
    HIP_DEBUG("Initializing addresses...\n");
    addresses = hip_ht_init(netdev_hash, netdev_match);

    HIP_IFEL(getifaddrs(&g_ifaces), -1,
             "getifaddrs failed\n");

    for (g_iface = g_ifaces; g_iface; g_iface = g_iface->ifa_next) {
        if (!g_iface->ifa_addr) {
            continue;
        }
        if (hip_exists_address_in_list(g_iface->ifa_addr, if_index)) {
            continue;
        }
        HIP_IFEL(!(if_index = if_nametoindex(g_iface->ifa_name)),
                 -1, "if_nametoindex failed\n");
        /* Check if our interface is in the whitelist */
        if ((hip_netdev_white_list_count > 0) && (!netdev_is_in_white_list(if_index))) {
            continue;
        }

        hip_add_address_to_list(g_iface->ifa_addr, if_index, 0);
    }

out_err:
    if (g_ifaces) {
        freeifaddrs(g_ifaces);
    }
    return err;
}

/**
 * Try to map a given HIT or an LSI to a routable IP address using local host association
 * data base, hosts files or DNS (in the presented order).
 *
 * @param hit a HIT to map to a LSI
 * @param lsi an LSI to map to an IP address
 * @param addr output argument to which this function writes the address if found
 * @return zero on success and non-zero on error
 * @note Either HIT or LSI must be given. If both are given, the HIT is preferred.
 * @todo move this to some other file (this file contains local IP address management, not remote)
 */
int hip_map_id_to_addr(const hip_hit_t *hit, const hip_lsi_t *lsi,
                       struct in6_addr *addr)
{
    int                    err = -1, res, skip_namelookup = 0; /* Assume that resolving fails */
    hip_hit_t              hit2;
    struct hip_hadb_state *ha = NULL;

    HIP_ASSERT(hit || lsi);

    /* Search first from hadb */

    if (hit && !ipv6_addr_any(hit)) {
        ha = hip_hadb_try_to_find_by_peer_hit(hit);
    } else {
        ha = hip_hadb_try_to_find_by_peer_lsi(lsi);
    }

    if (ha && !ipv6_addr_any(&ha->peer_addr)) {
        ipv6_addr_copy(addr, &ha->peer_addr);
        HIP_DEBUG("Found peer address from hadb, skipping hosts look up\n");
        err = 0;
        goto out_err;
    }

    /* Try to resolve the HIT or LSI to a hostname from HIPL_SYSCONFDIR/hosts,
     * then resolve the hostname to an IP, and a HIT or LSI,
     * depending on dst_hit value.
     * If dst_hit is a HIT -> find LSI and hostname
     * If dst_hit is an LSI -> find HIT and hostname */

    /* try to resolve HIT to IPv4/IPv6 address by 'HIPL_SYSCONFDIR/hosts'
     * and '/etc/hosts' files
     */
    HIP_IFEL(!hip_map_id_to_ip_from_hosts_files(hit, lsi, addr),
             0, "hip_map_id_to_ip_from_hosts_files succeeded\n");

    if (hit) {
        ipv6_addr_copy(&hit2, hit);
    } else {
        if (hip_map_lsi_to_hit_from_hosts_files(lsi, &hit2)) {
            skip_namelookup = 1;
        }
    }

    /* Check for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net records in DNS */
    if (hip_get_hit_to_ip_status() && !skip_namelookup) {
        HIP_DEBUG("looking for hit-to-ip record in dns\n");
        HIP_DEBUG("operation may take a while..\n");
        res = hip_hit_to_ip(hit, addr);

        if (res == 0) {
            HIP_DEBUG_IN6ADDR("found hit-to-ip addr ", addr);
            err = 0;
            goto out_err;
        }
    }

    HIP_DEBUG_IN6ADDR("Found addr: ", addr);

out_err:
    return err;
}

/**
 * Create a HIP association (if one does not exist already) and
 * trigger a base exchange with an I1 packet using the given
 * arguments. This function also supports HIP-based loopback
 * connectivity and hiccups (data packet) extensions.
 *
 * @param src_hit_in The source HIT for the I1. Alternatively, NULL if default
 *                   HIT is suitable
 * @param dst_hit_in The destination HIT. This HIT cannot be a "pseudo HIT" as
 *                   used by the opportunistic mode. Use hip_send_i1() function
 *                   instead with opportunistic mode.
 * @param src_lsi_in Optional source LSI corresponding to the source HIT
 * @param dst_lsi_in Optional destination LSI corresponding to the destination HIT
 * @param src_addr_in Source address for the I1 (IPv4 address in IPv6 mapped format)
 * @param dst_addr_in Destination address for the I1 (IPv4 address in IPv6 mapped format)
 * @return zero on success and non-zero on error
 * @note HITs can be NULL if the LSIs are non-NULL (and vice versa).
 * @note The locators (addresses) can be NULL. This function will
 *       try to map the HITs or LSIs to IP addresses. IPv4 broadcast
 *       will be used as a last resort.
 * @todo move this function to some other file
 */
int netdev_trigger_bex(const hip_hit_t *src_hit_in,
                       const hip_hit_t *dst_hit_in,
                       const hip_lsi_t *src_lsi_in,
                       const hip_lsi_t *dst_lsi_in,
                       const struct in6_addr *src_addr_in,
                       const struct in6_addr *dst_addr_in)
{
    int                     err                      = 0, if_index = 0, is_ipv4_locator;
    int                     reuse_hadb_local_address = 0, ha_nat_mode = hip_nat_status;
    int                     old_global_nat_mode      = hip_nat_status;
    in_port_t               ha_local_port;
    in_port_t               ha_peer_port;
    struct hip_hadb_state  *entry       = NULL;
    int                     is_loopback = 0;
    hip_lsi_t               dlsi, slsi;
    struct in6_addr         dhit, shit, saddr;
    struct in6_addr        *src_hit, *dst_hit, *src_addr, *dst_addr;
    struct in_addr         *src_lsi, *dst_lsi;
    struct in6_addr         daddr;
    struct sockaddr_storage ss_addr;
    struct sockaddr        *addr;

    ha_local_port =
        (hip_nat_status ? hip_get_local_nat_udp_port() : 0);
    ha_peer_port =
        (hip_nat_status ? hip_get_peer_nat_udp_port() : 0);

    addr = (struct sockaddr *) &ss_addr;

    /* Make sure that dst_hit is not a NULL pointer */
    hip_copy_in6addr_null_check(&dhit, dst_hit_in);
    dst_hit = &dhit;
    HIP_DEBUG_HIT("dst hit", dst_hit);

    /* Make sure that src_hit is not a NULL pointer */
    hip_copy_in6addr_null_check(&shit, src_hit_in);
    if (!src_hit_in) {
        hip_get_default_hit(&shit);
    }
    src_hit = &shit;
    HIP_DEBUG_HIT("src hit", src_hit);

    /* Make sure that dst_lsi is not a NULL pointer */
    hip_copy_inaddr_null_check(&dlsi, dst_lsi_in);
    dst_lsi = &dlsi;
    HIP_DEBUG_LSI("dst lsi", dst_lsi);

    /* Make sure that src_lsi is not a NULL pointer */
    hip_copy_inaddr_null_check(&slsi, src_lsi_in);
    src_lsi = &slsi;
    HIP_DEBUG_LSI("src lsi", src_lsi);

    /* Make sure that dst_addr is not a NULL pointer */
    hip_copy_in6addr_null_check(&daddr, dst_addr_in);
    dst_addr = &daddr;
    HIP_DEBUG_IN6ADDR("dst addr", dst_addr);

    /* Make sure that src_addr is not a NULL pointer */
    hip_copy_in6addr_null_check(&saddr, src_addr_in);
    src_addr = &saddr;
    HIP_DEBUG_IN6ADDR("src addr", src_addr);

    /* Only LSIs specified, but no HITs. Try to map LSIs to HITs
     * using hadb or hosts files. */

    if (src_lsi->s_addr && dst_lsi->s_addr && ipv6_addr_any(dst_hit)) {
        entry = hip_hadb_try_to_find_by_pair_lsi(src_lsi, dst_lsi);
        if (entry) {
            /* peer info already mapped because of e.g.
             * hipconf command */
            ipv6_addr_copy(dst_hit, &entry->hit_peer);
            src_hit = &entry->hit_our;
        } else {
            err = hip_map_lsi_to_hit_from_hosts_files(dst_lsi,
                                                      dst_hit);
            HIP_IFEL(err, -1, "Failed to map LSI to HIT\n");
        }
        if (ipv6_addr_any(src_hit)) {
            hip_get_default_hit(src_hit);
        }
    }

    HIP_DEBUG_HIT("src hit", src_hit);

    /* Now we should have at least source HIT and destination HIT.
     * Sometimes we get deformed HITs from kernel, skip them */
    HIP_IFEL(!(ipv6_addr_is_hit(src_hit) && ipv6_addr_is_hit(dst_hit) &&
               hip_hidb_hit_is_our(src_hit) &&
               hit_is_real_hit(dst_hit)), -1,
             "Received rubbish from netlink, skip\n");

    /* Existing entry found. No need for peer IP checks */
    entry = hip_hadb_find_byhits(src_hit, dst_hit);
    if (entry && !ipv6_addr_any(&entry->our_addr)) {
        reuse_hadb_local_address = 1;
        entry->hip_version       = hip_get_default_version();
        goto send_i1;
    }

    /* Search for destination HIT if it wasn't specified yet.
     * Assume that look up fails by default. */
    err = 1;
    HIP_DEBUG("No entry found; find first IP matching\n");

    if (err && !ipv6_addr_any(dst_addr)) {
        /* Destination address given; no need to look up */
        err = 0;
    }

    /* Map peer address to loopback if hit is ours  */
    if (err && hip_hidb_hit_is_our(dst_hit)) {
        struct in6_addr lpback = IN6ADDR_LOOPBACK_INIT;
        ipv6_addr_copy(dst_addr, &lpback);
        ipv6_addr_copy(src_addr, &lpback);
        is_loopback              = 1;
        reuse_hadb_local_address = 1;
        err                      = 0;
    }

    /* Look up peer ip from hadb entries */
    if (err) {
        /* Search HADB for existing entries */
        entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
        if (entry) {
            HIP_DEBUG_IN6ADDR("reusing HA",
                              &entry->peer_addr);
            ipv6_addr_copy(dst_addr, &entry->peer_addr);
            ha_local_port = entry->local_udp_port;
            ha_peer_port  = entry->peer_udp_port;
            ha_nat_mode   = entry->nat_mode;
            err           = 0;
        }
    }

    /* Try to look up peer ip from hosts files and DNS */
    if (err) {
        err = hip_map_id_to_addr(dst_hit, dst_lsi, dst_addr);
    }

    /* No peer address found; set it to broadcast address
     * as a last resource */
    if (err && hip_broadcast_status == HIP_MSG_BROADCAST_ON) {
        struct in_addr bcast = { INADDR_BROADCAST };
        /* IPv6 multicast failed to bind() to link local,
         * so using IPv4 here -mk */
        HIP_DEBUG("No information of peer found, trying broadcast\n");
        IPV4_TO_IPV6_MAP(&bcast, dst_addr);
        err = 0;
    }

    /* Next, create state into HADB. Make sure that we choose the right
     * NAT mode and source IP address in case there was some related HAs
     * with the peer that gave use hints on the best NAT mode or source
     * address. */

    /** @todo changing global state won't work with threads */
    hip_nat_status = ha_nat_mode;

    /* To make it follow the same route as it was doing before locators */
    HIP_IFEL(hip_hadb_add_peer_info(dst_hit, dst_addr,
                                    dst_lsi, NULL), -1,
             "map failed\n");

    /* restore nat status */
    hip_nat_status = old_global_nat_mode;

    HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)), -1,
             "Internal lookup error\n");

    if (is_loopback) {
        ipv6_addr_copy(&entry->our_addr, src_addr);
    }

    /* Preserve NAT status with peer */
    entry->local_udp_port = ha_local_port;
    entry->peer_udp_port  = ha_peer_port;
    entry->nat_mode       = ha_nat_mode;
    entry->hip_version    = hip_get_default_version();

    reuse_hadb_local_address = 1;

send_i1:

    HIP_DEBUG("Checking for older queued I1 transmissions.\n");
    for (unsigned int i = 0; i < HIP_RETRANSMIT_QUEUE_SIZE; i++) {
        if (entry->hip_msg_retrans[i].count > 0
            && hip_get_msg_type(entry->hip_msg_retrans[i].buf) == HIP_I1) {
            HIP_DEBUG("I1 was already sent, ignoring\n");
            goto out_err;
        }
    }
    HIP_DEBUG("Expired retransmissions, sending i1\n");

    is_ipv4_locator = IN6_IS_ADDR_V4MAPPED(&entry->peer_addr);

    addr->sa_family = is_ipv4_locator ? AF_INET : AF_INET6;

    if (!reuse_hadb_local_address && src_addr) {
        ipv6_addr_copy(&entry->our_addr, src_addr);
    }

    memcpy(hip_cast_sa_addr(addr), &entry->our_addr,
           hip_sa_addr_len(addr));

    HIP_DEBUG_HIT("our hit", &entry->hit_our);
    HIP_DEBUG_HIT("peer hit", &entry->hit_peer);
    HIP_DEBUG_IN6ADDR("peer locator", &entry->peer_addr);
    HIP_DEBUG_IN6ADDR("our locator", &entry->our_addr);

    if_index = hip_devaddr2ifindex(&entry->our_addr);
    HIP_IFEL(if_index < 0, -1, "if_index NOT determined\n");
    /* we could try also hip_select_source_address() here on failure,
     * but it seems to fail too */

    HIP_DEBUG("Using ifindex %d\n", if_index);

    switch (entry->hip_version) {
    case HIP_V1:
        if (hip_send_i1(&entry->hit_our, &entry->hit_peer, entry) < 0) {
            HIP_ERROR("Failed to send the I1(v1) message.\n");
            return -1;
        }
        break;

    case HIP_V2:
        if (hip_send_i1_v2(&entry->hit_our, &entry->hit_peer, entry) < 0) {
            HIP_ERROR("Failed to send the I1(v2) message.\n");
            return -1;
        }
        break;

    default:
        HIP_ERROR("Unknown HIP version: %d\n", entry->hip_version);
        return -1;
    }

out_err:

    return err;
}

/**
 * Handle an "acquire" message from the kernel by triggering a base exchange.
 *
 * @param msg a netlink "acquire" message
 * @return zero on success and non-zero on error
 * @todo move this to some other file
 */
static int netdev_handle_acquire(struct nlmsghdr *msg)
{
    hip_hit_t                *src_hit  = NULL, *dst_hit = NULL;
    hip_lsi_t                *src_lsi  = NULL, *dst_lsi = NULL;
    struct in6_addr          *src_addr = NULL, *dst_addr = NULL;
    struct xfrm_user_acquire *acq;
    struct hip_hadb_state    *entry;
    int                       err = 0;

    HIP_DEBUG("Acquire (pid: %d) \n", msg->nlmsg_pid);

    acq     = (struct xfrm_user_acquire *) NLMSG_DATA(msg);
    src_hit = (hip_hit_t *) &acq->sel.saddr;
    dst_hit = (hip_hit_t *) &acq->sel.daddr;

    HIP_DEBUG_HIT("src HIT", src_hit);
    HIP_DEBUG_HIT("dst HIT", dst_hit);
    HIP_DEBUG("acq->sel.ifindex=%d\n", acq->sel.ifindex);

    entry = hip_hadb_find_byhits(src_hit, dst_hit);

    if (entry) {
        HIP_IFEL(entry->state == HIP_STATE_ESTABLISHED, 0,
                 "State established, not triggering bex\n");

        src_lsi = &entry->lsi_our;
        dst_lsi = &entry->lsi_peer;
    }

    err = netdev_trigger_bex(src_hit, dst_hit, src_lsi, dst_lsi, src_addr, dst_addr);

out_err:

    return err;
}

/**
 * A wrapper for netdev_trigger_bex() to trigger a base exchange. The
 * difference to the other function is that the arguments are contained in
 * one single HIP message.
 *
 * @param msg the HIP user message containing HITs, LSIs and addresses as
 *            parameters
 * @return zero on success and non-zero on error
 * @todo move this to some other file
 */
int hip_netdev_trigger_bex_msg(const struct hip_common *msg)
{
    const hip_hit_t             *our_hit  = NULL, *peer_hit  = NULL;
    const hip_lsi_t             *our_lsi  = NULL, *peer_lsi  = NULL;
    const struct in6_addr       *our_addr = NULL, *peer_addr = NULL;
    const struct hip_tlv_common *param;
    int                          err = 0;

    HIP_DUMP_MSG(msg);

    /* Destination HIT */
    param = hip_get_param(msg, HIP_PARAM_HIT);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        peer_hit = hip_get_param_contents_direct(param);

        if (ipv6_addr_is_null(peer_hit)) {
            peer_hit = NULL;
        } else {
            HIP_DEBUG_HIT("trigger_msg_peer_hit:", peer_hit);
        }
    }

    /* Source HIT */
    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        our_hit = hip_get_param_contents_direct(param);

        if (ipv6_addr_is_null(our_hit)) {
            our_hit = NULL;
        } else {
            HIP_DEBUG_HIT("trigger_msg_ourr_hit:", our_hit);
        }
    }

    /* Peer LSI */
    param = hip_get_param(msg, HIP_PARAM_LSI);
    if (param) {
        peer_lsi = hip_get_param_contents_direct(param);
        HIP_DEBUG_LSI("trigger_msg_peer_lsi:", peer_lsi);
    }

    /** @todo: check if peer lsi is all zeroes? */

    /* Local LSI */
    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_LSI) {
        our_lsi = hip_get_param_contents_direct(param);
        HIP_DEBUG_LSI("trigger_msg_our_lsi:", our_lsi);
    }

    /** @todo: check if local lsi is all zeroes? */

    /* Destination IP */
    param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
    if (param) {
        peer_addr = hip_get_param_contents_direct(param);
    }

    /* Source IP */
    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR) {
        our_addr = hip_get_param_contents_direct(param);
    }

    HIP_DEBUG_IN6ADDR("trigger_msg_our_addr:", our_addr);

    err = netdev_trigger_bex(our_hit, peer_hit,
                             our_lsi, peer_lsi,
                             our_addr, peer_addr);

    return err;
}

/**
 * Add or delete an address to the cache of localhost addresses. This
 * function also checks if the address is already on the list when adding
 * or absent from the list when deleting.
 *
 * @param addr The address to be added to the cache. IPv4 addresses
 *             can be in IPv6 mapped format.
 * @param is_add 1 if the address is to be added or 0 if to be deleted
 * @param interface_index the network interface index for the address
 */
static void update_address_list(struct sockaddr *addr, int is_add,
                                int interface_index)
{
    int addr_exists = 0;

    addr_exists = hip_exists_address_in_list(addr, interface_index);
    HIP_DEBUG("is_add = %d, exists = %d\n", is_add, addr_exists);
    if ((is_add && addr_exists) ||
        (!is_add && !addr_exists)) {
        HIP_DEBUG("Address %s discarded.\n",
                  (is_add ? "add" : "del"));
        return;
    }

    if (is_add) {
        hip_add_address_to_list(addr, interface_index, 0);
    } else {
        delete_address_from_list(addr, interface_index);
    }
}

/**
 * Netlink event handler. Handles IPsec acquire messages (triggering
 * of base exchange) and updates the cache of local addresses when
 * address changes occur.
 *
 * @param msg a netlink message
 * @param len the length of the netlink message in bytes
 * @param arg argument to pass (needed because of the callaback nature)
 * @return zero on success and non-zero on error
 */
int hip_netdev_event(struct nlmsghdr *msg, int len, UNUSED void *arg)
{
    int                     err = 0, l = 0, is_add = 0, exists;
    struct sockaddr_storage ss_addr;
    struct ifinfomsg       *ifinfo = NULL; /* link layer specific message */
    struct ifaddrmsg       *ifa    = NULL; /* interface address message */
    struct rtattr          *rta    = NULL, *tb[IFA_MAX + 1] = { 0 };
    struct sockaddr        *addr   = NULL;

    addr = (struct sockaddr *) &ss_addr;

    for (/* VOID */; NLMSG_OK(msg, (uint32_t) len);
                   msg = NLMSG_NEXT(msg, len)) {
        int ifindex;
        ifinfo  = (struct ifinfomsg *) NLMSG_DATA(msg);
        ifindex = ifinfo->ifi_index;


        HIP_DEBUG("handling msg type %d ifindex=%d\n",
                  msg->nlmsg_type, ifindex);
        switch (msg->nlmsg_type) {
        case RTM_NEWLINK:
            HIP_DEBUG("RTM_NEWLINK\n");
            /* wait for RTM_NEWADDR to add addresses */
            break;
        case RTM_DELLINK:
            HIP_DEBUG("RTM_DELLINK\n");
            break;
        /* Add or delete address from addresses */
        case RTM_NEWADDR:
        case RTM_DELADDR:
            HIP_DEBUG("RTM_NEWADDR/DELADDR\n");
            ifa = (struct ifaddrmsg *) NLMSG_DATA(msg);
            rta = IFA_RTA(ifa);
            l   = msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

            /* Check if our interface is in the whitelist */
            if ((hip_netdev_white_list_count > 0) &&
                (!netdev_is_in_white_list(ifindex))) {
                continue;
            }

            if ((ifa->ifa_family != AF_INET) &&
                (ifa->ifa_family != AF_INET6)) {
                continue;
            }

            is_add = (msg->nlmsg_type == RTM_NEWADDR) ? 1 : 0;

            /* parse list of attributes into table
             * (same as parse_rtattr()) */
            while (RTA_OK(rta, l)) {
                if (rta->rta_type <= IFA_MAX) {
                    tb[rta->rta_type] = rta;
                }
                rta = RTA_NEXT(rta, l);
            }
            /* fix tb entry for inet6 */
            if (!tb[IFA_LOCAL]) {
                tb[IFA_LOCAL] = tb[IFA_ADDRESS];
            }
            if (!tb[IFA_ADDRESS]) {
                tb[IFA_ADDRESS] = tb[IFA_LOCAL];
            }

            if (!tb[IFA_LOCAL]) {
                continue;
            }
            addr->sa_family = ifa->ifa_family;
            memcpy(hip_cast_sa_addr(addr), RTA_DATA(tb[IFA_LOCAL]),
                   RTA_PAYLOAD(tb[IFA_LOCAL]));
            HIP_DEBUG("Address event=%s ifindex=%d\n",
                      is_add ? "add" : "del", ifa->ifa_index);

            if (addr->sa_family == AF_INET) {
                HIP_DEBUG_LSI("Addr", hip_cast_sa_addr(addr));
            } else if (addr->sa_family == AF_INET6) {
                HIP_DEBUG_HIT("Addr", hip_cast_sa_addr(addr));
            } else {
                HIP_DEBUG("Unknown addr family in addr\n");
            }

            /* Trying to add an existing address or deleting a non-existing
             * address */
            exists = hip_exists_address_in_list(addr, ifa->ifa_index);
            HIP_IFEL((exists && is_add) || (!exists && !is_add), -1,
                     "Address change discarded (exists=%d, is_add=%d)\n",
                     exists, is_add);

            update_address_list(addr, is_add, ifa->ifa_index);

            if (hip_wait_addr_changes_to_stabilize) {
                address_change_time_counter = HIP_ADDRESS_CHANGE_WAIT_INTERVAL;
            } else {
                address_change_time_counter = 1;
            }

            if (err) {
                goto out_err;
            }

            break;
        case XFRMGRP_ACQUIRE:
            /* This seems never to occur */
            return -1;
            break;
        case XFRMGRP_EXPIRE:
            HIP_DEBUG("received expiration, ignored\n");
            return 0;
            break;
        case XFRM_MSG_GETSA:
            return -1;
            break;
        case XFRM_MSG_ALLOCSPI:
            return -1;
            break;
        case XFRM_MSG_ACQUIRE:
            HIP_DEBUG("handled msg XFRM_MSG_ACQUIRE\n");
            return netdev_handle_acquire(msg);
            break;
        case XFRM_MSG_EXPIRE:
            return -1;
            break;
        case XFRM_MSG_UPDPOLICY:
            return -1;
            break;
        case XFRM_MSG_UPDSA:
            return -1;
            break;
        case XFRM_MSG_POLEXPIRE:
            return -1;
            break;
        default:
            HIP_DEBUG("unhandled msg type %d\n", msg->nlmsg_type);
            break;
        }
    }

out_err:
    return 0;
}

/**
 * Add or remove a HIT on the local virtual interface to enable HIT-based
 * connectivity. The interface is defined in the ::HIP_HIT_DEV constant.
 *
 * @param local_hit The HIT to be added or removed.
 * @param add       Add @a local_hit if true, remove otherwise.
 * @return          Zero on success, non-zero on failure.
 */
static int manage_iface_local_hit(const hip_hit_t *const local_hit, const bool add)
{
    int            err = 0;
    char           hit_str[INET6_ADDRSTRLEN + 2];
    struct idxmap *idxmap[16] = { 0 };

    hip_convert_hit_to_str(local_hit, HIP_HIT_PREFIX_STR, hit_str);
    HIP_DEBUG("%s HIT: %s\n", (add ? "Adding" : "Removing"), hit_str);

    HIP_IFE(hip_ipaddr_modify(&hip_nl_route, (add ? RTM_NEWADDR : RTM_DELADDR),
                              AF_INET6, hit_str, HIP_HIT_DEV, idxmap), -1);

out_err:

    return err;
}

/**
 * Remove a HIT from the local virtual interface to disable HIT-based
 * connectivity. The interface is defined in the ::HIP_HIT_DEV constant.
 *
 * @param local_hit The HIT to be removed.
 * @return          Zero on success, non-zero on failure.
 *
 * @see manage_iface_local_hit()
 */
static int remove_iface_local_hit(const hip_hit_t *const local_hit)
{
    return manage_iface_local_hit(local_hit, false);
}

/**
 * Add a HIT on the local virtual interface to enable HIT-based
 * connectivity. The interface is defined in the ::HIP_HIT_DEV constant.
 *
 * @param local_hit The HIT to be added
 * @return          Zero on success, non-zero on failure.
 *
 * @note Adding just the HIT is not enough, a route has to be added as well.
 * @see manage_iface_local_hit()
 */
int hip_add_iface_local_hit(const hip_hit_t *const local_hit)
{
    /* Re-assigning the current address (if hipd didn't exit
     * properly and left the device as-is, for example) would not
     * trigger RTM_NEWADDR and, most importantly, not set up the needed
     * routes automatically. So we try to clear the address first.
     */
    remove_iface_local_hit(local_hit);

    return manage_iface_local_hit(local_hit, true);
}

/**
 * Remove the HIT given by @a entry from the virtual interface.
 *
 * @param entry  The hit is determined by entry->hit
 * @param opaque Ignored: added to comply with hip_for_each_hi() callback
 *               signature.
 * @return       Zero on success, non-zero on failure.
 *
 * @see hip_remove_iface_all_local_hits()
 */
static int remove_iface_hit_by_host_id(struct local_host_id *entry,
                                       UNUSED void *opaque)
{
    return manage_iface_local_hit(&entry->hit, false);
}

/**
 * Remove all local HITs from the virtual interface.
 */
int hip_remove_iface_all_local_hits(void)
{
    return hip_for_each_hi(remove_iface_hit_by_host_id, NULL);
}

/**
 * Add a route to a local HIT
 *
 * @param local_hit the local HIT for which a route should be added
 * @return zero on success and non-zero on error
 */
int hip_add_iface_local_route(const hip_hit_t *local_hit)
{
    int  err = 0;
    char hit_str[INET6_ADDRSTRLEN + 2];

    hip_convert_hit_to_str(local_hit, HIP_HIT_FULL_PREFIX_STR, hit_str);
    HIP_DEBUG("Adding local HIT route: %s\n", hit_str);
    HIP_IFE(hip_iproute_modify(&hip_nl_route, RTM_NEWROUTE,
                               NLM_F_CREATE | NLM_F_EXCL,
                               AF_INET6, hit_str, HIP_HIT_DEV),
            -1);

out_err:

    return err;
}

/**
 * Given a destination address, ask the kernel routing for the corresponding
 * source address
 *
 * @param src The chosen source address will be written here. IPv4 addresses
 *            will be in IPv6-mapped format.
 * @param dst The destination address. IPv4 addresses must be in
 *            in IPv6-mapped format.
 * @return zero on success and non-zero on failure
 */
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst)
{
    int             err        = 0;
    int             family     = AF_INET6;
    struct idxmap  *idxmap[16] = { 0 };
    struct in6_addr lpback     = IN6ADDR_LOOPBACK_INIT;

    HIP_DEBUG_IN6ADDR("dst", dst);

    /* Required for loopback connections */
    if (!ipv6_addr_cmp(dst, &lpback)) {
        ipv6_addr_copy(src, dst);
        goto out_err;
    }

    HIP_IFEL(!exists_address_family_in_list(dst), -1, "No address of the same family\n");

    if (ipv6_addr_is_teredo(dst)) {
        struct netdev_address *na;
        const struct in6_addr *in6;
        LHASH_NODE            *n, *t;
        int                    c;

        list_for_each_safe(n, t, addresses, c) {
            na  = list_entry(n);
            in6 = hip_cast_sa_addr((struct sockaddr *) &na->addr);
            if (ipv6_addr_is_teredo(in6)) {
                ipv6_addr_copy(src, in6);
            }
        }
        HIP_IFEL(err, -1, "No src addr found for Teredo\n");
    } else {
        HIP_IFEL(hip_iproute_get(&hip_nl_route, src, dst, NULL, NULL, family, idxmap), -1, "Finding ip route failed\n");
    }

    HIP_DEBUG_IN6ADDR("src", src);

out_err:
    return err;
}
