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
 * This file defines Host Identity Protocol (HIP) header and parameter related
 * constants and structures.
 */

#ifndef HIPL_LIBCORE_STATE_H
#define HIPL_LIBCORE_STATE_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>

#include "android/android.h"
#include "config.h"
#include "hashtable.h"
#include "modularization.h"
#include "protodefs.h"
#include "statistics.h"

#define HIP_ENDPOINT_FLAG_PUBKEY           0
#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
/* Other flags: keep them to the power of two! */


/**
 * HIP association states
 *
 * HIP states as specifed in section 4.4.1.\ of draft-ietf-hip-base-10.
 *
 * The states are: UNASSOCIATED, I1-SENT, I2-SENT, R2-SENT ESTABLISHED, CLOSING,
 * CLOSED, E-FAILED.
 */
/* When adding new states update hip_state_str(). */
enum hip_state {
    HIP_STATE_NONE,         /**< no state, structure unused */
    HIP_STATE_UNASSOCIATED, /**< state machine start */
    HIP_STATE_I1_SENT,      /**< initiating base exchange */
    HIP_STATE_I2_SENT,      /**< waiting to complete base exchange */
    HIP_STATE_R2_SENT,      /**< waiting to complete base exchange */
    HIP_STATE_ESTABLISHED,  /**< HIP association established */
    HIP_STATE_FAILED,       /**< HIP exchange failed */
    HIP_STATE_CLOSING,      /**< HIP association closing, no data can be sent */
    HIP_STATE_CLOSED,       /**< HIP association closed, no data can be sent */
    HIP_STATE_R1_SENT,      /**< R1 sent; only used by HIP firewall */
    HIP_STATE_U1_SENT,      /**< UPDATE 1 sent; only used by HIP firewall */
    HIP_STATE_U2_SENT       /**< UPDATE 2 sent; only used by HIP firewall */
};

const char *hip_state_str(enum hip_state state);

/**
 * @todo add description
 */
#define HIP_MAX_HA_STATE                16

/* #define PEER_ADDR_STATE_UNVERIFIED       1 */
#define PEER_ADDR_STATE_ACTIVE           2

/** for the triple nat mode*/
#define HIP_NAT_MODE_NONE               0
#define HIP_NAT_MODE_PLAIN_UDP          1

#define HIP_SPI_DIRECTION_OUT           1
#define HIP_SPI_DIRECTION_IN            2

#define HIP_FLAG_CONTROL_TRAFFIC_ONLY 0x1

/**
 * HIP host association state.
 */
enum hip_ha_state {
    HIP_HA_STATE_INVALID = 0,
    HIP_HA_STATE_VALID   = 1,
};

/* The maximum number of retransmissions to queue. */
#define HIP_RETRANSMIT_QUEUE_SIZE 3

/**
 * A data structure for handling retransmission. Used inside host association
 * database entries.
 */
struct hip_msg_retrans {
    int                count;
    uint64_t           current_backoff;
    struct timeval     last_transmit;
    struct in6_addr    saddr;
    struct in6_addr    daddr;
    struct hip_common *buf;
};

struct hip_peer_addr_list_item {
    struct in6_addr address;
};

struct hip_spi_in_item {
    uint32_t spi;
    uint32_t new_spi;             /* SPI is changed to this when rekeying */
    /* ifindex if the netdev to which this is related to */
    int           ifindex;
    unsigned long timestamp;        /* when SA was created */
    uint32_t      esp_info_spi_out;        /* UPDATE, the stored outbound
                                            * SPI related to the inbound
                                            * SPI we sent in reply (useless?)*/
    uint16_t keymat_index;             /* advertised keymat index */
    /* the Update ID in SEQ parameter these SPI are related to */
    struct hip_esp_info stored_received_esp_info;
};

struct hip_spi_out_item {
    uint32_t        spi;
    uint32_t        new_spi;        /* spi is changed to this when rekeying */
    HIP_HASHTABLE  *peer_addr_list;    /* Peer's IPv6 addresses */
    struct in6_addr preferred_address;
};

/* If you need to add a new boolean type variable to this structure, consider
 * adding a control value to the local_controls and/or peer_controls bitmask
 * field(s) instead of adding yet another integer. Lauri 24.01.2008. */
/** A data structure defining host association database state i.e.\ a HIP
 *  association between two hosts. Each successful base exchange between two
 *  different hosts leads to a new @c hip_hadb_state with @c state set to
 *  @c HIP_STATE_ESTABLISHED. */
struct hip_hadb_state {
    /** Our Host Identity Tag (HIT). */
    hip_hit_t hit_our;
    /** Peer's Host Identity Tag (HIT). */
    hip_hit_t hit_peer;
    /** Information about the usage of the host association related to
     *  locking stuff which is currently unimplemented because the daemon
     *  is single threaded. When zero, the host association can be freed. */
    enum hip_ha_state ha_state;
    /** Counter to tear down a HA in CLOSING or CLOSED state */
    int purge_timeout;
    /** The state of this host association. */
    enum hip_state state;
    /** Our control values related to this host association.
     *  @see hip_ha_controls */
    hip_controls local_controls;
    /** Peer control values related to this host association.
     *  @see hip_ha_controls */
    hip_controls peer_controls;
    /** If this host association is from a local HIT to a local HIT this
     *  is non-zero, otherwise zero. */
    int is_loopback;
    /** Preferred peer IP address to use when sending data to peer. */
    struct in6_addr peer_addr;
    /** Our IP address. */
    struct in6_addr our_addr;
    /** Rendezvour server address used to connect to the peer; */
    struct in6_addr *rendezvous_addr;
    /** Peer's Local Scope Identifier (LSI). A Local Scope Identifier is a
     *  32-bit localized representation for a Host Identity.*/
    hip_lsi_t lsi_peer;
    /** Our Local Scope Identifier (LSI). A Local Scope Identifier is a
     *  32-bit localized representation for a Host Identity.*/
    hip_lsi_t lsi_our;
    /** ESP transform type */
    int esp_transform;
    /** HIP transform type */
    int hip_transform;
    /** ESP extension protection transform */
    uint8_t esp_prot_transform;
    /** ESP extension protection parameter */
    int esp_prot_param;
    /** ESP extension protection local_anchor */
    unsigned char esp_local_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** another local anchor used for UPDATE messages */
    unsigned char esp_local_update_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** ESP extension protection peer_anchor */
    unsigned char esp_peer_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** another peer anchor used for UPDATE messages */
    unsigned char esp_peer_update_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    /** needed for offset calculation when using htrees */
    uint32_t esp_local_active_length;
    uint32_t esp_local_update_length;
    uint32_t esp_peer_active_length;
    uint32_t esp_peer_update_length;
    /** root needed in case of hierarchical hchain linking */
    uint8_t       esp_root_length;
    unsigned char esp_root[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
    int           hash_item_length;
    /** parameters needed for soft-updates of hchains */
    /** Stored outgoing UPDATE ID counter. */
    uint32_t light_update_id_out;
    /** Stored incoming UPDATE ID counter. */
    uint32_t light_update_id_in;
    /** retranmission */
    uint8_t light_update_retrans;
    /** Something to do with the birthday paradox.
     *  @todo Please clarify what this field is. */
    uint64_t birthday;
    /** A pointer to the Diffie-Hellman shared key. */
    char *dh_shared_key;
    /** The length of the Diffie-Hellman shared key. */
    size_t dh_shared_key_len;
    /** A boolean value indicating whether there is a NAT between this host
     *  and the peer. */
    hip_transform_suite nat_mode;
    /* this might seem redundant as dst_port == hip_get_nat_udp_port(), but it makes
     * port handling easier in other functions */
    in_port_t local_udp_port;
    /** NAT mangled port (source port of I2 packet). */
    in_port_t peer_udp_port;
    /* The Initiator computes the keys when it receives R1. The keys are
     * needed only when R2 is received. We store them here in the mean
     * time. */
    /** For outgoing HIP packets. */
    struct hip_crypto_key hip_enc_out;
    /** For outgoing HIP packets. */
    struct hip_crypto_key hip_hmac_out;
    /** For outgoing ESP packets. */
    struct hip_crypto_key esp_out;
    /** For outgoing ESP packets. */
    struct hip_crypto_key auth_out;
    /** For incoming HIP packets. */
    struct hip_crypto_key hip_enc_in;
    /** For incoming HIP packets. */
    struct hip_crypto_key hip_hmac_in;
    /** For incoming ESP packets. */
    struct hip_crypto_key esp_in;
    /** For incoming ESP packets. */
    struct hip_crypto_key auth_in;
    /** The byte offset index in draft chapter HIP KEYMAT. */
    uint16_t current_keymat_index;
    /** The one byte index number used during the keymat calculation. */
    uint8_t keymat_calc_index;
    /** For @c esp_info. */
    uint16_t esp_keymat_index;
    /* Last Kn, where n is @c keymat_calc_index. */
    unsigned char current_keymat_K[HIP_AH_SHA_LEN];
    /** Our public host identity. */
    struct hip_host_id *our_pub;
    /** Our private host identity. */
    struct hip_host_id *our_priv;
    /** Keys in OpenSSL RSA or DSA format */
    void *our_priv_key;
    void *peer_pub_key;
    /** A function pointer to a function that signs our host identity. */
    int (*sign)(void *, struct hip_common *);
    /** Peer's public host identity. */
    struct hip_host_id *peer_pub;
    /** A function pointer to a function that verifies peer's host identity. */
    int (*verify)(void *, struct hip_common *);
    /** For retransmission. */
    uint8_t puzzle_solution[PUZZLE_LENGTH];
    /** LOCATOR parameter. Just tmp save if sent in R1 no @c esp_info so
     *  keeping it here 'till the hip_update_locator_parameter can be done.
     *  @todo Remove this kludge. */
    struct hip_locator *locator;
    /** For retransmission. */
    uint8_t puzzle_i[PUZZLE_LENGTH];
    /** Used for UPDATE and CLOSE. When we sent multiple identical UPDATE
     * packets between different address combinations, we don't modify
     * the opaque data. */
    unsigned char echo_data[4];

    HIP_HASHTABLE *peer_addr_list_to_be_added;
    /** The slot in our struct hip_msg_retrans array which will be used to save
     *  the next retransmission. */
    unsigned int next_retrans_slot;
    /** For storing retransmission related data. */
    struct hip_msg_retrans hip_msg_retrans[HIP_RETRANSMIT_QUEUE_SIZE];
    /** peer hostname */
    uint8_t peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    /** Counters of heartbeats (ICMPv6s) */
    int                    heartbeats_sent;
    struct statistics_data heartbeats_statistics;

    struct timeval bex_start;
    struct timeval bex_end;

    uint32_t             pacing;
    uint8_t              ice_control_role;
    struct hip_esp_info *nat_esp_info;

    /** disable SAs on this HA (currently used only by full relay) */
    int disable_sas;

    char hip_nat_key[HIP_MAX_KEY_LEN];
    /**reflexive address(NAT box out bound) when register to relay or RVS */
    struct in6_addr local_reflexive_address;
    /**reflexive address port (NAT box out bound) when register to relay or RVS */
    in_port_t local_reflexive_udp_port;

    unsigned spi_inbound_current;
    unsigned spi_outbound_old;
    unsigned spi_outbound_new;

    /* The HIP version in use for this HA pair */
    uint8_t hip_version;
    /* modular state */
    struct modular_state *hip_modular_state;
} __attribute__((packed));

/** A data structure defining host association information that is sent
 *  to the userspace */
struct hip_hadb_user_info_state {
    hip_hit_t       hit_our;
    hip_hit_t       hit_peer;
    struct in6_addr ip_our;
    struct in6_addr ip_peer;
    hip_lsi_t       lsi_our;
    hip_lsi_t       lsi_peer;
    uint8_t         peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    int             state;
    int             heartbeats_on;
    int             heartbeats_sent;
    int             heartbeats_received;
    double          heartbeats_mean;
    double          heartbeats_variance;
    in_port_t       nat_udp_port_local;
    in_port_t       nat_udp_port_peer;
    int             shotgun_status;
    int             broadcast_status;
    hip_controls    peer_controls;
    struct timeval  bex_duration;
};

#endif /* HIPL_LIBCORE_STATE_H */
