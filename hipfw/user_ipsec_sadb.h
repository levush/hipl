/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * Stores security association for IPsec connections and makes them
 * accessasible through HITs and (dst IP, spi).
 *
 * @brief Security association database for IPsec connections
 */

#ifndef HIPL_HIPFW_USER_IPSEC_SADB_H
#define HIPL_HIPFW_USER_IPSEC_SADB_H

#include <stdint.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <sys/time.h>

#include "libcore/esp_prot_common.h"
#include "libcore/hashchain.h"
#include "esp_prot_defines.h"


#define BEET_MODE 3 /* mode: 1-transport, 2-tunnel, 3-beet -> right now we only support mode 3 */

/* IPsec Security Association entry */
struct hip_sa_entry {
    int             direction;             /* direction of the SA: inbound/outbound */
    uint32_t        spi;                   /* IPsec SPI number */
    uint32_t        mode;                  /* ESP mode :  1-transport, 2-tunnel, 3-beet */
    struct in6_addr src_addr;              /* source address of outer IP header */
    struct in6_addr dst_addr;              /* destination address of outer IP header */
    struct in6_addr inner_src_addr;        /* inner source addresses for tunnel and BEET SAs */
    struct in6_addr inner_dst_addr;        /* inner destination addresses for tunnel and BEET SAs */
    uint8_t         encap_mode;            /* encapsulation mode: 0 - none, 1 - udp */
    uint16_t        src_port;              /* src port for UDP encaps. ESP */
    uint16_t        dst_port;              /* dst port for UDP encaps. ESP */
    /****************** crypto parameters *******************/
    int                    ealg;           /* crypto transform in use */
    struct hip_crypto_key *auth_key;       /* raw authentication key */
    struct hip_crypto_key *enc_key;        /* raw encryption key */
    des_key_schedule       ks[3];          /* 3-DES keys */
    AES_KEY                aes_key;        /* AES key */
    BF_KEY                 bf_key;         /* BLOWFISH key */
    /******************** statistics *************************/
    uint64_t       lifetime;               /* seconds until expiration */
    uint64_t       bytes;                  /* bytes transmitted */
    struct timeval usetime;                /* last used timestamp */
    struct timeval usetime_ka;             /* last used timestamp, including keep-alives */
    uint32_t       sequence;               /* ESP sequence number counter */
    /*********** esp protection extension params *************/
    /* for both directions */
    uint8_t esp_prot_transform;                /* mode used for securing ipsec traffic */
    /* for outbound direction */
    void                      *active_hash_items[MAX_NUM_PARALLEL_HCHAINS]; /* active item can be a hchain or a htree */
    void                      *next_hash_items[MAX_NUM_PARALLEL_HCHAINS]; /* update item can be a hchain or a htree */
    int                        active_item_length; /* length of the active hash item */
    int                        update_item_length; /* length of the update hash item */
    uint8_t                    update_item_acked[MAX_NUM_PARALLEL_HCHAINS]; /* ack from peer that update succeeded */
    int                        last_used_chain; /* in case of parallel hchains, stores last used for round robin */
    struct esp_cumulative_item hash_buffer[MAX_RING_BUFFER_SIZE];    /* packet hash buffer for the cumulative packet auth */
    uint32_t                   next_free;       /* next buffer entry to be used for cumulative packet auth */
};

int hip_sadb_init(void);
void hip_sadb_uninit(void);
int hip_sadb_add(int direction,
                 uint32_t spi,
                 uint32_t mode,
                 const struct in6_addr *src_addr,
                 const struct in6_addr *dst_addr,
                 const struct in6_addr *inner_src_addr,
                 const struct in6_addr *inner_dst_addr,
                 uint8_t encap_mode, uint16_t local_port,
                 uint16_t peer_port,
                 int ealg,
                 const struct hip_crypto_key *auth_key,
                 const struct hip_crypto_key *enc_key,
                 uint64_t lifetime,
                 uint8_t esp_prot_transform,
                 uint32_t hash_item_length,
                 uint16_t esp_num_anchors,
                 unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                 int retransmission,
                 int update);
int hip_sadb_delete(const struct in6_addr *dst_addr,
                    uint32_t spi);
void hip_sadb_flush(void);
struct hip_sa_entry *hip_sa_entry_find_inbound(const struct in6_addr *dst_addr,
                                               uint32_t spi);
struct hip_sa_entry *hip_sa_entry_find_outbound(const struct in6_addr *src_hit,
                                                const struct in6_addr *dst_hit);

#endif /* HIPL_HIPFW_USER_IPSEC_SADB_H */
