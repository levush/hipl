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
 *
 * This file facilitates buiding of mobility and multi-homing-specific
 * parameters.
 */

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "libcore/builder.h"
#include "libcore/ife.h"
#include "libcore/list.h"
#include "libcore/prefix.h"
#include "libhipl/hadb.h"
#include "libhipl/netdev.h"
#include "update_builder.h"

enum hip_locator_traffic_type {
    HIP_LOCATOR_TRAFFIC_TYPE_DUAL,
    HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL
};

/**
 * build and append a HIP SEQ parameter to a message
 *
 * @param msg the message where the parameter will be appended
 * @param update_id Update ID
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_seq(struct hip_common *const msg, const uint32_t update_id)
{
    int            err = 0;
    struct hip_seq seq;

    hip_set_param_type((struct hip_tlv_common *) &seq, HIP_PARAM_SEQ);
    hip_calc_param_len((struct hip_tlv_common *) &seq,
                       sizeof(struct hip_seq) - sizeof(struct hip_tlv_common));
    seq.update_id = htonl(update_id);
    err           = hip_build_param(msg, &seq);
    return err;
}

/**
 * build and append a HIP ACK parameter to a message
 *
 * @param msg the message where the parameter will be appended
 * @param peer_update_id peer Update ID
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_ack(struct hip_common *const msg,
                        const uint32_t peer_update_id)
{
    int            err = 0;
    struct hip_ack ack;

    hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_ACK);
    hip_calc_param_len((struct hip_tlv_common *) &ack,
                       sizeof(struct hip_ack) - sizeof(struct hip_tlv_common));
    ack.peer_update_id = htonl(peer_update_id);
    err                = hip_build_param(msg, &ack);
    return err;
}

/**
 * Build a HIP locator parameter.
 *
 * @param msg           the message where the REA will be appended
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_locator(struct hip_common *const msg)
{
    int                        err          = 0, i = 0, count = 0, addrs_len;
    struct hip_locator        *locator      = NULL;
    struct hip_locator_type_1 *locator_item = NULL;
    struct hip_hadb_state     *ha           = NULL;
    LHASH_NODE                *item         = NULL, *tmp = NULL;
    struct netdev_address     *n;

    addrs_len = address_count * sizeof(struct hip_locator_type_1);
    HIP_IFEL(!(locator = malloc(sizeof(struct hip_locator) + addrs_len)),
             -ENOMEM, "Could not allocate space for locator parameter\n");

    HIP_IFEL(!(ha = hip_hadb_find_byhits(&msg->hit_sender, &msg->hit_receiver)),
             -1, "Could not retrieve HA\n");

    hip_set_param_type((struct hip_tlv_common *) locator, HIP_PARAM_LOCATOR);

    hip_calc_generic_param_len((struct hip_tlv_common *) locator,
                               sizeof(struct hip_locator),
                               addrs_len);

    /* build all locator info items from cached addresses */
    locator_item = (struct hip_locator_type_1 *) (locator + 1);
    list_for_each_safe(item, tmp, addresses, i) {
        n = list_entry(item);
        HIP_DEBUG_IN6ADDR("Add address:", hip_cast_sa_addr(((struct sockaddr *) &n->addr)));
        HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr((struct sockaddr *) &n->addr)));
        memcpy(&locator_item[count].address,
               hip_cast_sa_addr((struct sockaddr *) &n->addr),
               sizeof(struct in6_addr));
        if (n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY) {
            locator_item[count].header.traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL;
        } else {
            locator_item[count].header.traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
        }
        locator_item[count].header.locator_type   = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
        locator_item[count].header.locator_length = sizeof(struct in6_addr) / 4;
        locator_item[count].header.reserved       = 0;
        locator_item[count].esp_spi               = htonl(ha->spi_inbound_current);
        count++;
    }

    HIP_IFE(hip_build_param(msg, locator), -1);

out_err:
    free(locator);
    return err;
}
