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
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 */

#ifndef HIPL_LIBHIPL_ESP_PROT_HIPD_MSG_H
#define HIPL_LIBHIPL_ESP_PROT_HIPD_MSG_H

#include <stdint.h>

#include "libcore/common.h"
#include "libcore/protodefs.h"
#include "libcore/state.h"

#define ESP_PROT_UNKNOWN_UPDATE_PACKET     0
#define ESP_PROT_FIRST_UPDATE_PACKET     1
#define ESP_PROT_SECOND_UPDATE_PACKET    2

int esp_prot_set_preferred_transforms(const struct hip_common *msg);
int esp_prot_handle_trigger_update_msg(const struct hip_common *msg);
int esp_prot_handle_anchor_change_msg(const struct hip_common *msg);
int esp_prot_sa_add(struct hip_hadb_state *entry, struct hip_common *msg,
                    const int direction, const int update);
int esp_prot_r1_add_transforms(struct hip_common *msg);
int esp_prot_r1_handle_transforms(UNUSED const uint8_t packet_type,
                                  UNUSED const enum hip_state ha_state,
                                  struct hip_packet_context *ctx);
int esp_prot_i2_add_anchor(struct hip_packet_context *ctx);
int esp_prot_i2_handle_anchor(struct hip_packet_context *ctx);
int esp_prot_r2_add_anchor(struct hip_common *r2, struct hip_hadb_state *entry);
int esp_prot_r2_handle_anchor(struct hip_hadb_state *entry,
                              const struct hip_common *input_msg);
int esp_prot_update_type(const struct hip_common *recv_update);
int esp_prot_handle_first_update_packet(const struct hip_common *recv_update,
                                        struct hip_hadb_state *entry,
                                        const struct in6_addr *src_ip,
                                        const struct in6_addr *dst_ip);
int esp_prot_handle_second_update_packet(struct hip_hadb_state *entry,
                                         const struct in6_addr *src_ip,
                                         const struct in6_addr *dst_ip);
int esp_prot_update_add_anchor(struct hip_common *update,
                               struct hip_hadb_state *entry);
int esp_prot_update_handle_anchor(const struct hip_common *recv_update,
                                  struct hip_hadb_state *entry,
                                  uint32_t *spi);

#endif /* HIPL_LIBHIPL_ESP_PROT_HIPD_MSG_H */
