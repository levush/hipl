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

#ifndef HIPL_MODULES_UPDATE_HIPD_UPDATE_H
#define HIPL_MODULES_UPDATE_HIPD_UPDATE_H

#include <stdint.h>
#include <netinet/in.h>

#include "libcore/protodefs.h"

/* the different mobility message types */
#define HIP_UPDATE_LOCATOR              0
#define HIP_UPDATE_ECHO_REQUEST         1
#define HIP_UPDATE_ECHO_RESPONSE        2
#define HIP_UPDATE_ESP_ANCHOR           3
#define HIP_UPDATE_ESP_ANCHOR_ACK       4

/* locator parameter types */
#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1
#define HIP_LOCATOR_LOCATOR_TYPE_UDP     2

/**
 * The maximum number of locators the current implementation supports per
 * update message. This number is arbitrarily chosen. It may be increased
 * at the expense of more memory being used per struct update_state
 * instance.
 */
#define HIP_MAX_LOCATORS 16

enum update_types { UNKNOWN_UPDATE_PACKET, FIRST_UPDATE_PACKET,
                    SECOND_UPDATE_PACKET, THIRD_UPDATE_PACKET };

struct update_state {
    /**
     * The set of locators we received in the initial UPDATE packet.
     *
     * Hipd sends UPDATE packets including ECHO_REQUESTS to all these
     * addresses.
     */
    struct in6_addr addresses_to_send_echo_request[HIP_MAX_LOCATORS];

    /**
     * The number of valid entries in the addresses_to_send_echo_request
     * array.
     */
    unsigned valid_locators;

    /** UPDATE ID of the latest outgoing UPDATE packet. */
    uint32_t update_id_out;

    /** UPDATE ID of the oldest not yet acknowledged outgoing UPDATE packet.
     *  Usually this value is equal to @c update_id_out. The only exception is
     *  when more than one UPDATE packet is yet to be acknowledged by the peer. */
    uint32_t update_id_out_lower_bound;

    /** UPDATE ID of the latest incoming UPDATE packet. */
    uint32_t update_id_in;
};

struct hip_locator {
    hip_tlv     type;
    hip_tlv_len length;
    /* fixed part ends */
} __attribute__((packed));

/**
 * locator type 0 and locator type 1 header
 */
struct hip_locator_header {
    uint8_t  traffic_type;
    uint8_t  locator_type;
    uint8_t  locator_length;
    uint8_t  reserved;        /**< last bit is P (preferred) */
    uint32_t lifetime;
}  __attribute__((packed));

/**
 * type 0 locator item
 */
struct hip_locator_type_0 {
    struct hip_locator_header header;
    struct in6_addr           address;
}  __attribute__((packed));

/**
 * type 1 locator item
 */
struct hip_locator_type_1 {
    struct hip_locator_header header;
    /* The locator field comprises the 32-bit ESP SPI and address (IPv6 or IPv4-in-IPv6)
     * (c.f. http://tools.ietf.org/html/rfc5206#section-4.2) */
    uint32_t        esp_spi;
    struct in6_addr address;
}  __attribute__((packed));

/**
 * it is a union of both type1 and type2 locator.
 */
union hip_locator_info_addr {
    struct hip_locator_type_0 type0;
    struct hip_locator_type_1 type1;
} __attribute__((packed));

uint32_t hip_update_get_out_id(const struct update_state *const state);

int hip_trigger_update(struct hip_hadb_state *const hadb_entry);

enum update_types hip_classify_update_type(const struct hip_common *const hip_msg);

int hip_update_init(void);

#endif /* HIPL_MODULES_UPDATE_HIPD_UPDATE_H */
