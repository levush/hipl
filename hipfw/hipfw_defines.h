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

#ifndef HIPL_HIPFW_FIREWALL_DEFINES_H
#define HIPL_HIPFW_FIREWALL_DEFINES_H

#define _BSD_SOURCE

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "libcore/common.h"
#include "libcore/linkedlist.h"
#include "libcore/protodefs.h"
#include "config.h"
#include "common_types.h"
#include "esp_prot_defines.h"

#define MIDAUTH_DEFAULT_NONCE_LENGTH 20

enum hipfw_pkt_type {
    OTHER_PACKET = 0,
    HIP_PACKET,
    ESP_PACKET,
    FW_PROTO_NUM
};

/**
 *  @note Backwards-compatibility header with the depracated libipq library
 */
typedef struct hip_ipq_packet_msg {
    unsigned long  packet_id;
    unsigned int   hook;
    char           indev_name[IFNAMSIZ];
    char           outdev_name[IFNAMSIZ];
    size_t         data_len;
    unsigned char *payload;
} hip_ipq_packet_msg;

/**
 * @note When adding new members, check if hip_fw_context_enable_write() needs
 *       to be updated as well.
 * @see hip_fw_context_enable_write()
 * @see hip_fw_context_enable_write_inplace()
 */
struct hip_fw_context {
    // queued packet
    hip_ipq_packet_msg *ipq_packet;

    // IP layer information
    int             ip_version;   /* 4, 6 */
    int             ip_hdr_len;
    struct in6_addr src, dst;
    union {
        struct ip6_hdr *ipv6;
        struct ip      *ipv4;
    } ip_hdr;

    // transport layer information
    enum hipfw_pkt_type packet_type; // HIP_PACKET, ESP_PACKET, etc
    union {
        struct hip_esp    *esp;
        struct hip_common *hip;
    } transport_hdr;
    struct udphdr *udp_encap_hdr;

    int modified;
};

/********** State table structures **************/

struct esp_address {
    struct in6_addr dst_addr;
    uint32_t       *update_id;  // NULL or pointer to the update id from the packet
    // that announced this address.
    // when ack with the update id is seen all esp_addresses with
    // NULL update_id can be removed.
};

struct esp_tuple {
    uint32_t      spi;
    uint32_t      spi_update_id;
    struct hip_ll dst_addresses;
    struct tuple *tuple;
    /* tracking of the ESP SEQ number */
    uint32_t seq_no;
    /* members needed for ESP protection extension */
    uint8_t       esp_prot_tfm;
    uint32_t      hash_item_length;
    uint32_t      hash_tree_depth;
    long          num_hchains;
    unsigned char active_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    // need for verification of anchor updates
    unsigned char  first_active_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    unsigned char  next_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    int            active_root_length;
    unsigned char *active_roots[MAX_NUM_PARALLEL_HCHAINS];
    int            next_root_length[MAX_NUM_PARALLEL_HCHAINS];
    unsigned char *next_roots[MAX_NUM_PARALLEL_HCHAINS];
    /** List temporarily storing anchor elements until the consecutive update
     *  msg reveals that all on-path devices know the new anchor. */
    struct hip_ll anchor_cache;
    /** buffer storing hashes of previous packets for cumulative authentication */
    struct esp_cumulative_item hash_buffer[MAX_RING_BUFFER_SIZE];
};

struct hip_data {
    struct in6_addr src_hit;
    struct in6_addr dst_hit;
    int             pub_key_type;
    void           *src_pub_key;
    int             (*verify)(void *, struct hip_common *);
};

struct hip_tuple {
    struct hip_data *data;
    struct tuple    *tuple;
};

struct tuple {
    struct hip_tuple  *hip_tuple;
    in_port_t          src_port;
    in_port_t          dst_port;
    struct slist      *esp_tuples;
    int                direction;
    struct connection *connection;
    int                hook;            /**< iptables chain this tuple originates from. */
    uint32_t           lupdate_seq;
    int                esp_relay;
    struct in6_addr    esp_relay_daddr;
    in_port_t          esp_relay_dport;
    uint8_t            midauth_nonce[MIDAUTH_DEFAULT_NONCE_LENGTH];
};

struct connection {
    struct tuple original;
    struct tuple reply;
    int          verify_responder;
    int          state;
    time_t       timestamp;
    /* members needed for iptables setup */
    bool udp_encap;         /**< UDP encapsulation enabled? (NAT extension) */
    /* members needed for ESP protection extension */
    int     num_esp_prot_tfms;
    uint8_t esp_prot_tfms[MAX_NUM_TRANSFORMS];
};

#endif /* HIPL_HIPFW_FIREWALL_DEFINES_H */
