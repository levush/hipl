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
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/esp_prot_common.h"
#include "libcore/hip_udp.h"
#include "libcore/ife.h"
#include "libcore/protodefs.h"
#include "libcore/gpl/xfrmapi.h"
#include "modules/update/hipd/update_builder.h"
#include "cookie.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_light_update.h"
#include "hadb.h"
#include "hipd.h"
#include "output.h"
#include "esp_prot_hipd_msg.h"

/** @todo Remove this dependency from core to UPDATE module */
#include "modules/update/hipd/update.h"

static uint8_t esp_prot_transforms[MAX_NUM_TRANSFORMS];

int  esp_prot_active               = 0;
int  esp_prot_num_transforms       = 0;
long esp_prot_num_parallel_hchains = 0;

/**
 * Sends second update message for a public-key-based anchor element update
 *
 * @param recv_update   received first update message
 * @param entry         host association for the received update
 * @param src_ip        src ip address
 * @param dst_ip        dst ip address
 * @param spi           spi of IPsec association
 * @return              0 on success, < 0 in case of an error
 */
static int esp_prot_send_update_response(const struct hip_common *recv_update,
                                         struct hip_hadb_state *entry,
                                         const struct in6_addr *src_ip,
                                         const struct in6_addr *dst_ip,
                                         const uint32_t spi)
{
    struct       hip_common *resp_update = NULL;
    const struct hip_seq    *seq         = NULL;
    uint16_t                 mask        = 0;
    int                      err         = 0;

    HIP_IFEL(!(seq = hip_get_param(recv_update, HIP_PARAM_SEQ)),
             -1,
             "SEQ not found\n");

    HIP_IFEL(!(resp_update = hip_msg_alloc()), -ENOMEM, "out of memory\n");

    hip_build_network_hdr(resp_update,
                          HIP_UPDATE,
                          mask,
                          &recv_update->hit_receiver,
                          &recv_update->hit_sender,
                          entry->hip_version);

    /* Add ESP_INFO */
    HIP_IFEL(hip_build_param_esp_info(resp_update,
                                      entry->current_keymat_index,
                                      spi,
                                      spi),
             -1,
             "Building of ESP_INFO param failed\n");

    /* Add ACK */
    HIP_IFEL(hip_build_param_ack(resp_update, ntohl(seq->update_id)),
             -1,
             "Building of ACK failed\n");

    /* Add HMAC */
    HIP_IFEL(hip_build_param_hmac_contents(resp_update, &entry->hip_hmac_out),
             -1,
             "Building of HMAC failed\n");

    /* Add SIGNATURE */
    HIP_IFEL(entry->sign(entry->our_priv_key, resp_update), -EINVAL,
             "Could not sign UPDATE. Failing\n");

    HIP_IFEL(hip_send_pkt(src_ip,
                          dst_ip,
                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                          entry->peer_udp_port,
                          resp_update,
                          entry,
                          0),
             -1,
             "failed to send ANCHOR-UPDATE\n");

out_err:
    return err;
}

/**
 * Selects the preferred ESP protection extension transform from the set of
 * local and peer preferred transforms
 *
 * @param num_transforms    amount of transforms in the transforms array passed
 * @param transforms        the transforms array
 * @return                  the overall preferred transform
 */
static uint8_t esp_prot_select_transform(const int num_transforms,
                                         const uint8_t transforms[])
{
    uint8_t transform = ESP_PROT_TFM_UNUSED;
    int     err       = 0, i, j;

    for (i = 0; i < esp_prot_num_transforms; i++) {
        for (j = 0; j < num_transforms; j++) {
            if (esp_prot_transforms[i] == transforms[j]) {
                HIP_DEBUG("found matching transform: %u\n",
                          esp_prot_transforms[i]);

                transform = esp_prot_transforms[i];
                goto out_err;
            }
        }
    }

    HIP_ERROR("NO matching transform found\n");
    transform = ESP_PROT_TFM_UNUSED;

out_err:
    if (err) {
        transform = ESP_PROT_TFM_UNUSED;
    }

    return transform;
}

/********************** user-messages *********************/

/** sets the preferred ESP protection extension transforms array transferred
 * from the firewall
 *
 * @param msg   the user-message sent by the firewall
 * @return      0 if ok, != 0 else
 */
int esp_prot_set_preferred_transforms(const struct hip_common *msg)
{
    const struct hip_tlv_common *param = NULL;
    int                          err   = 0, i;

    param           = hip_get_param(msg, HIP_PARAM_INT);
    esp_prot_active = *((const int *)
                        hip_get_param_contents_direct(param));
    HIP_DEBUG("esp_prot_active: %i\n", esp_prot_active);

    // process message and store the preferred transforms
    param                   = hip_get_next_param(msg, param);
    esp_prot_num_transforms = *((const int *)
                                hip_get_param_contents_direct(param));
    HIP_DEBUG("esp protection num_transforms: %i\n", esp_prot_num_transforms);

    param                         = hip_get_next_param(msg, param);
    esp_prot_num_parallel_hchains = *((const long *)
                                      hip_get_param_contents_direct(param));
    HIP_DEBUG("esp_prot_num_parallel_hchains: %i\n", esp_prot_num_parallel_hchains);

    for (i = 0; i < MAX_NUM_TRANSFORMS; i++) {
        if (i < esp_prot_num_transforms) {
            param                  = hip_get_next_param(msg, param);
            esp_prot_transforms[i] = *((const uint8_t *)
                                       hip_get_param_contents_direct(param));
            HIP_DEBUG("esp protection transform %i: %u\n", i + 1, esp_prot_transforms[i]);
        } else {
            esp_prot_transforms[i] = 0;
        }
    }

    // this works as we always have to send at least ESP_PROT_TFM_UNUSED
    if (esp_prot_active) {
        HIP_DEBUG("switched to esp protection extension\n");
    } else {
        anchor_db_uninit();
        HIP_DEBUG("switched to normal esp mode\n");
    }

    /* we have to make sure that the precalculated R1s include the esp
     * protection extension transform */
    HIP_DEBUG("recreate all R1s\n");
    HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, "failed to recreate all R1s\n");

out_err:
    return err;
}

/** handles the user-message sent by fw when a new anchor has to be set
 * up at the peer host
 *
 * @param msg   the user-message sent by the firewall
 * @return      0 if ok, != 0 else
 */
int esp_prot_handle_trigger_update_msg(const struct hip_common *msg)
{
    const struct hip_tlv_common *param           = NULL;
    const hip_hit_t             *local_hit       = NULL, *peer_hit = NULL;
    uint8_t                      esp_prot_tfm    = 0;
    int                          hash_length     = 0;
    const unsigned char         *esp_prot_anchor = NULL;
    int                          soft_update     = 0;
    int                          anchor_offset[MAX_NUM_PARALLEL_HCHAINS];
    int                          secret_length[MAX_NUM_PARALLEL_HCHAINS];
    int                          branch_length[MAX_NUM_PARALLEL_HCHAINS];
    int                          root_length = 0;
    const unsigned char         *secret[MAX_NUM_PARALLEL_HCHAINS];
    const unsigned char         *branch_nodes[MAX_NUM_PARALLEL_HCHAINS];
    const unsigned char         *root[MAX_NUM_PARALLEL_HCHAINS];
    struct hip_hadb_state       *entry                    = NULL;
    int                          hash_item_length         = 0;
    unsigned char                cmp_val[MAX_HASH_LENGTH] = { 0 };
    int                          err                      = 0;
    long                         i, num_parallel_hchains  = 0;

    param     = hip_get_param(msg, HIP_PARAM_HIT);
    local_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("src_hit", local_hit);

    param    = hip_get_next_param(msg, param);
    peer_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("dst_hit", peer_hit);

    // get matching entry from hadb for HITs provided above
    HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
             "failed to retrieve requested HA entry\n");

    param        = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
    esp_prot_tfm = *((const uint8_t *)
                     hip_get_param_contents_direct(param));
    HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

    // check if transforms are matching and add anchor as new local_anchor
    HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
             "esp prot transform changed without new BEX\n");
    HIP_DEBUG("esp prot transforms match\n");

    param            = hip_get_param(msg, HIP_PARAM_INT);
    hash_item_length = *((const int *)
                         hip_get_param_contents_direct(param));
    HIP_DEBUG("hash_item_length: %i\n", hash_item_length);

    // set the hash_item_length of the item used for this update
    entry->hash_item_length = hash_item_length;

    // we need to know the hash_length for this transform
    hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

    param                = hip_get_next_param(msg, param);
    num_parallel_hchains = *((const long *)
                             hip_get_param_contents_direct(param));
    HIP_DEBUG("num_parallel_hchains: %i\n", num_parallel_hchains);

    // process all update anchors now
    param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
    for (i = 0; i < num_parallel_hchains; i++) {
        esp_prot_anchor = hip_get_param_contents_direct(param);
        HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);

        // make sure that the update-anchor is not set yet
        HIP_IFEL(memcmp(&entry->esp_local_update_anchors[i][0],
                        &cmp_val[0], MAX_HASH_LENGTH),
                 -1,
                 "next hchain changed in fw, but we still have the last update-anchor set!");

        // set the update anchor
        memcpy(&entry->esp_local_update_anchors[i][0], esp_prot_anchor, hash_length);

        param = hip_get_next_param(msg, param);
    }

    root_length = *((const int *)
                    hip_get_param_contents_direct(param));
    HIP_DEBUG("root_length: %i\n", root_length);
    entry->esp_root_length = root_length;

    // process all update roots now
    if (root_length > 0) {
        param = hip_get_param(msg, HIP_PARAM_ROOT);
        for (i = 0; i < num_parallel_hchains; i++) {
            root[i] = hip_get_param_contents_direct(param);
            memcpy(&entry->esp_root[i][0], root[i], root_length);

            HIP_HEXDUMP("root: ", &entry->esp_root[i][0], root_length);

            param = hip_get_next_param(msg, param);
        }
    }

    soft_update = *((const int *) hip_get_param_contents_direct(param));
    HIP_DEBUG("soft_update: %i\n", soft_update);

    if (soft_update) {
        for (i = 0; i < num_parallel_hchains; i++) {
            param            = hip_get_next_param(msg, param);
            anchor_offset[i] = *((const int *)
                                 hip_get_param_contents_direct(param));
            HIP_DEBUG("anchor_offset: %i\n", anchor_offset[i]);

            param            = hip_get_next_param(msg, param);
            secret_length[i] = *((const int *)
                                 hip_get_param_contents_direct(param));
            HIP_DEBUG("secret_length: %i\n", secret_length[i]);

            param            = hip_get_next_param(msg, param);
            branch_length[i] = *((const int *)
                                 hip_get_param_contents_direct(param));
            HIP_DEBUG("branch_length: %i\n", branch_length[i]);

            param     = hip_get_next_param(msg, param);
            secret[i] = hip_get_param_contents_direct(param);
            HIP_HEXDUMP("secret: ", secret[i], secret_length[i]);

            param           = hip_get_next_param(msg, param);
            branch_nodes[i] = hip_get_param_contents_direct(param);
            HIP_HEXDUMP("branch_nodes: ", branch_nodes[i], branch_length[i]);
        }
    }

    if (soft_update) {
        HIP_IFEL(esp_prot_send_light_update(entry, anchor_offset, secret, secret_length,
                                            branch_nodes, branch_length), -1,
                 "failed to send anchor update\n");
    } else {
        /* this should send an update only containing the mandatory params
         * HMAC and HIP_SIGNATURE as well as the ESP_PROT_ANCHOR and the
         * SEQ param (to guaranty freshness of the ANCHOR) in the signed part
         * of the message */
        /* TODO implement own update trigger
         * HIP_IFEL(hip_send_update_to_one_peer(NULL, entry,
         *                                   &entry->our_addr,
         *                                   &entry->peer_addr,
         *                                   NULL,
         *                                   HIP_UPDATE_ESP_ANCHOR),
         *       -1, "failed to send anchor update\n");
         */
    }

out_err:
    return err;
}

/** handles the user-message sent by fw when the anchors have changed in
 * the sadb from next to active
 *
 * @param msg   the user-message sent by the firewall
 * @return      0 if ok, != 0 else
 */
int esp_prot_handle_anchor_change_msg(const struct hip_common *msg)
{
    const struct hip_tlv_common *param                = NULL;
    const hip_hit_t             *local_hit            = NULL, *peer_hit = NULL;
    uint8_t                      esp_prot_tfm         = 0;
    int                          hash_length          = 0;
    const unsigned char         *esp_prot_anchor      = NULL;
    struct hip_hadb_state       *entry                = NULL;
    int                          direction            = 0;
    long                         num_parallel_hchains = 0, i;
    int                          err                  = 0;

    param     = hip_get_param(msg, HIP_PARAM_HIT);
    local_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("src_hit", local_hit);

    param    = hip_get_next_param(msg, param);
    peer_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("dst_hit", peer_hit);

    param     = hip_get_param(msg, HIP_PARAM_INT);
    direction = *((const int *)
                  hip_get_param_contents_direct(param));
    HIP_DEBUG("direction: %i\n", direction);

    param        = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
    esp_prot_tfm = *((const uint8_t *)
                     hip_get_param_contents_direct(param));
    HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

    param                = hip_get_param(msg, HIP_PARAM_INT);
    num_parallel_hchains = *((const long *)
                             hip_get_param_contents_direct(param));
    HIP_DEBUG("num_parallel_hchains: %u\n", num_parallel_hchains);

    param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);


    // get matching entry from hadb for HITs provided above
    HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
             "failed to retrieve requested HA entry\n");

    // check if transforms are matching and add anchor as new local_anchor
    HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
             "esp prot transform changed without new BEX\n");
    HIP_DEBUG("esp prot transforms match\n");

    // we need to know the hash_length for this transform
    hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

    // only handle outbound direction here
    if (direction == HIP_SPI_DIRECTION_OUT) {
        for (i = 0; i < num_parallel_hchains; i++) {
            esp_prot_anchor = hip_get_param_contents_direct(param);
            HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);

            // make sure that the update-anchor is set
            HIP_IFEL(memcmp(&entry->esp_local_update_anchors[i][0], esp_prot_anchor, hash_length),
                     -1, "hchain-anchors used for outbound connections NOT in sync\n");

            // set update anchor as new active local anchor
            memcpy(&entry->esp_local_anchors[i][0], &entry->esp_local_update_anchors[i][0], hash_length);
            memset(&entry->esp_local_update_anchors[i][0], 0, MAX_HASH_LENGTH);

            HIP_DEBUG("changed update_anchor to local_anchor\n");

            param = hip_get_next_param(msg, param);
        }

        goto out_err;
    }

    HIP_ERROR("failure when changing update_anchor to local_anchor\n");
    err = -1;

out_err:
    return err;
}

/** sets the ESP protection extension transform and anchor in user-messages
 * sent to the firewall in order to add a new SA
 *
 * @param entry         the host association entry for this connection
 * @param msg           the user-message sent by the firewall
 * @param direction     direction of the entry to be created
 * @param update        this was triggered by an update
 * @return              0 if ok, != 0 else
 */
int esp_prot_sa_add(struct hip_hadb_state *entry, struct hip_common *msg,
                    const int direction, const int update)
{
    unsigned char (*hchain_anchors)[MAX_HASH_LENGTH] = NULL;
    int      hash_length      = 0;
    uint32_t hash_item_length = 0;
    int      err              = 0, i;

    HIP_DEBUG("direction: %i\n", direction);

    // we always tell the negotiated transform to the firewall
    HIP_DEBUG("esp protection transform is %u \n", entry->esp_prot_transform);
    HIP_IFEL(hip_build_param_contents(msg, &entry->esp_prot_transform,
                                      HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
             "build param contents failed\n");

    // but we only transmit the anchor to the firewall, if the esp extension is used
    if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

        // choose the anchor depending on the direction and update or add
        if (update) {
            if (direction == HIP_SPI_DIRECTION_OUT) {
                HIP_IFEL(!(hchain_anchors = entry->esp_local_update_anchors), -1,
                         "hchain anchor expected, but not present\n");

                hash_item_length = entry->esp_local_update_length;
            } else {
                HIP_IFEL(!(hchain_anchors = entry->esp_peer_update_anchors), -1,
                         "hchain anchor expected, but not present\n");

                hash_item_length = entry->esp_peer_update_length;
            }
        } else {
            if (direction == HIP_SPI_DIRECTION_OUT) {
                HIP_IFEL(!(hchain_anchors = entry->esp_local_anchors), -1,
                         "hchain anchor expected, but not present\n");

                hash_item_length = entry->esp_local_active_length;
            } else {
                HIP_IFEL(!(hchain_anchors = entry->esp_peer_anchors), -1,
                         "hchain anchor expected, but not present\n");

                hash_item_length = entry->esp_peer_active_length;
            }
        }

        // add parameters to hipfw message
        HIP_IFEL(hip_build_param_contents(msg, &hash_item_length,
                                          HIP_PARAM_ITEM_LENGTH, sizeof(uint32_t)), -1,
                 "build param contents failed\n");

        // add parameters to hipfw message
        HIP_IFEL(hip_build_param_contents(msg, &esp_prot_num_parallel_hchains,
                                          HIP_PARAM_UINT, sizeof(uint16_t)), -1,
                 "build param contents failed\n");

        for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
            HIP_HEXDUMP("esp protection anchor is ", &hchain_anchors[i][0], hash_length);

            HIP_IFEL(hip_build_param_contents(msg, &hchain_anchors[i][0],
                                              HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
                     "build param contents failed\n");
        }
    } else {
        HIP_DEBUG("no anchor added, transform UNUSED\n");
    }

out_err:
    return err;
}

/********************* BEX parameters *********************/

/**
 * Adds the supported esp protection transform to an R1 message
 *
 * @param msg   the hip message to be sent
 * @return      0 on success, -1 in case of an error
 */
int esp_prot_r1_add_transforms(struct hip_common *msg)
{
    int err = 0;

    /* only supported in usermode and optional there
     *
     * add the transform only when usermode is active */
    if (hip_use_userspace_ipsec) {
        HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

        /* send the stored transforms */
        HIP_IFEL(hip_build_param_esp_prot_transform(msg, esp_prot_num_transforms,
                                                    esp_prot_transforms), -1,
                 "Building of ESP protection mode failed\n");

        HIP_DEBUG("ESP prot transforms param built\n");
    } else {
        HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skip\n");
    }

out_err:
    return err;
}

/**
 * Handles the esp protection transforms included in an R1 message.
 *
 * @param packet_type Unused.
 * @param ha_state    Unused:
 * @param ctx         Packet context for the received R1 message.
 * @return            Always 0.
 */
int esp_prot_r1_handle_transforms(UNUSED const uint8_t packet_type,
                                  UNUSED const enum hip_state ha_state,
                                  struct hip_packet_context *ctx)
{
    const struct esp_prot_preferred_tfms *prot_transforms = NULL;
    int                                   err             = 0;

    /* this is only handled if we are using userspace ipsec,
     * otherwise we just ignore it */
    if (hip_use_userspace_ipsec) {
        HIP_DEBUG("userspace IPsec hint: ESP extension might be in use\n");

        prot_transforms = hip_get_param(ctx->input_msg,
                                        HIP_PARAM_ESP_PROT_TRANSFORMS);

        // check if the transform parameter was sent
        if (prot_transforms) {
            HIP_DEBUG("received preferred transforms from peer\n");

            // store that we received the param for further processing
            ctx->hadb_entry->esp_prot_param = 1;

            // select transform and store it for this connection
            ctx->hadb_entry->esp_prot_transform = esp_prot_select_transform(prot_transforms->num_transforms,
                                                                            prot_transforms->transforms);
        } else {
            HIP_DEBUG("R1 does not contain preferred ESP protection "
                      "transforms, locally setting UNUSED\n");

            // store that we didn't received the param
            ctx->hadb_entry->esp_prot_param = 0;

            // if the other end-host does not want to use the extension, we don't either
            ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
        }
    } else {
        HIP_DEBUG("no userspace IPsec hint for ESP extension, locally setting UNUSED\n");

        // make sure we don't add the anchor now and don't add any transform or anchor
        ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
    }

    return err;
}

/**
 * Adds an anchor element with the negotiated transform to an I2 message
 *
 * @param ctx       packet context for the I2 message
 * @return          0 on success, -1 in case of an error
 */
int esp_prot_i2_add_anchor(struct hip_packet_context *ctx)
{
    unsigned char *anchor           = NULL;
    int            hash_length      = 0;
    int            hash_item_length = 0;
    int            err              = 0, i;

    /* only add, if extension in use and we agreed on a transform
     *
     * @note the transform was selected in handle R1 */
    if (ctx->hadb_entry->esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        // check for sufficient elements
        if (anchor_db_get_num_anchors(ctx->hadb_entry->esp_prot_transform) >=
            esp_prot_num_parallel_hchains) {
            hash_length = anchor_db_get_anchor_length(ctx->hadb_entry->esp_prot_transform);
            HIP_DEBUG("hash_length: %i\n", hash_length);
            hash_item_length = anchor_db_get_hash_item_length(ctx->hadb_entry->esp_prot_transform);

            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                // add all anchors now
                HIP_IFEL(!(anchor = anchor_db_get_anchor(ctx->hadb_entry->esp_prot_transform)), -1,
                         "no anchor elements available, threading?\n");
                HIP_IFEL(hip_build_param_esp_prot_anchor(ctx->output_msg, ctx->hadb_entry->esp_prot_transform,
                                                         anchor, NULL, hash_length, hash_item_length), -1,
                         "Building of ESP protection anchor failed\n");

                // store local_anchor
                memcpy(&ctx->hadb_entry->esp_local_anchors[i][0], anchor, hash_length);
                HIP_HEXDUMP("stored local anchor: ", &ctx->hadb_entry->esp_local_anchors[i][0], hash_length);

                ctx->hadb_entry->esp_local_active_length = hash_item_length;
                HIP_DEBUG("ctx->hadb_entry->esp_local_active_length: %u\n",
                          ctx->hadb_entry->esp_local_active_length);
            }
        } else {
            // fall back
            HIP_ERROR("agreed on using esp hchain protection, but not sufficient elements");

            ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

            // inform our peer
            HIP_IFEL(hip_build_param_esp_prot_anchor(ctx->output_msg, ctx->hadb_entry->esp_prot_transform,
                                                     NULL, NULL, 0, 0), -1,
                     "Building of ESP protection anchor failed\n");
        }
    } else {
        // only reply, if transforms param in R1; send UNUSED param
        if (ctx->hadb_entry->esp_prot_param) {
            HIP_DEBUG("R1 contained transforms, but agreed not to use the extension\n");

            ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

            HIP_IFEL(hip_build_param_esp_prot_anchor(ctx->output_msg, ctx->hadb_entry->esp_prot_transform,
                                                     NULL, NULL, 0, 0), -1,
                     "Building of ESP protection anchor failed\n");
        } else {
            HIP_DEBUG("peer didn't send transforms in R1, locally setting UNUSED\n");

            ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
        }
    }

out_err:
    free(anchor);
    return err;
}

/**
 * Handles the received anchor element of an I2 message
 *
 * @param ctx       packet context for the I2 message
 * @return          0 on success, -1 in case of an error
 */
int esp_prot_i2_handle_anchor(struct hip_packet_context *ctx)
{
    const struct hip_tlv_common  *param       = NULL;
    const struct esp_prot_anchor *prot_anchor = NULL;
    int                           hash_length = 0;
    int                           err         = 0, i;

    /* only supported in user-mode ipsec and optional there */
    if (hip_use_userspace_ipsec && esp_prot_num_transforms > 1) {
        HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

        if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_ESP_PROT_ANCHOR))) {
            prot_anchor = (const struct esp_prot_anchor *) param;

            // check if the anchor has a supported transform
            if (esp_prot_check_transform(esp_prot_num_transforms, esp_prot_transforms,
                                         prot_anchor->transform) >= 0) {
                // we know this transform
                ctx->hadb_entry->esp_prot_transform = prot_anchor->transform;
                hash_length                         = anchor_db_get_anchor_length(ctx->hadb_entry->esp_prot_transform);

                if (ctx->hadb_entry->esp_prot_transform == ESP_PROT_TFM_UNUSED) {
                    HIP_DEBUG("agreed NOT to use esp protection extension\n");

                    // there should be no other anchors in this case
                    goto out_err;
                }

                // store number of elements per hash structure
                ctx->hadb_entry->esp_peer_active_length = ntohl(prot_anchor->hash_item_length);
                HIP_DEBUG("ctx->hadb_entry->esp_peer_active_length: %u\n",
                          ctx->hadb_entry->esp_peer_active_length);

                // store all contained anchors
                for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                    if (!prot_anchor || prot_anchor->transform != ctx->hadb_entry->esp_prot_transform) {
                        // we expect an anchor and all anchors should have the same transform
                        err = -1;
                        goto out_err;
                    } else {
                        // store peer_anchor
                        memcpy(&ctx->hadb_entry->esp_peer_anchors[i][0], &prot_anchor->anchors[0],
                               hash_length);
                        HIP_HEXDUMP("received anchor: ", &ctx->hadb_entry->esp_peer_anchors[i][0],
                                    hash_length);
                    }

                    // get next anchor
                    param       = hip_get_next_param(ctx->input_msg, param);
                    prot_anchor = (const struct esp_prot_anchor *) param;
                }
            } else {
                HIP_ERROR("received anchor with unknown transform, falling back\n");

                ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
            }
        } else {
            HIP_DEBUG("NO esp anchor sent, locally setting UNUSED\n");

            ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
        }
    } else {
        HIP_DEBUG("userspace IPsec hint: esp protection extension NOT in use\n");

        ctx->hadb_entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
    }

out_err:
    return err;
}

/**
 * Adds an anchor element with the negotiated transform to an R2 message
 *
 * @param r2        the hip message to be sent
 * @param entry     hip association for the connection
 * @return          0 on success, -1 in case of an error
 */
int esp_prot_r2_add_anchor(struct hip_common *r2, struct hip_hadb_state *entry)
{
    unsigned char *anchor           = NULL;
    int            hash_length      = 0;
    int            hash_item_length = 0;
    int            err              = 0, i;

    // only add, if extension in use, we agreed on a transform and no error until now
    if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        // check for sufficient elements
        if (anchor_db_get_num_anchors(entry->esp_prot_transform) >= esp_prot_num_parallel_hchains) {
            hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);
            HIP_DEBUG("hash_length: %i\n", hash_length);

            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                // add all anchors now
                HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)), -1,
                         "no anchor elements available, threading?\n");
                hash_item_length = anchor_db_get_hash_item_length(entry->esp_prot_transform);
                HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
                                                         anchor, NULL, hash_length, hash_item_length), -1,
                         "Building of ESP protection anchor failed\n");

                // store local_anchor
                memcpy(&entry->esp_local_anchors[i][0], anchor, hash_length);
                HIP_HEXDUMP("stored local anchor: ", &entry->esp_local_anchors[i][0], hash_length);

                entry->esp_local_active_length = anchor_db_get_hash_item_length(entry->esp_prot_transform);
                HIP_DEBUG("entry->esp_local_active_length: %u\n",
                          entry->esp_local_active_length);
            }
        } else {
            // fall back
            HIP_ERROR("agreed on using esp hchain protection, but no elements");

            entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

            // inform our peer about fallback
            HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
                                                     NULL, NULL, 0, 0), -1,
                     "Building of ESP protection anchor failed\n");
        }
    } else {
        HIP_DEBUG("esp protection extension NOT in use for this connection\n");

        entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
    }

out_err:
    free(anchor);
    return err;
}

/**
 * Handles the received anchor element of an R2 message
 *
 * @param entry     hip association for the connection
 * @param input_msg the input message
 * @return          0 on success, -1 in case of an error
 */
int esp_prot_r2_handle_anchor(struct hip_hadb_state *entry,
                              const struct hip_common *input_msg)
{
    const struct hip_tlv_common  *param       = NULL;
    const struct esp_prot_anchor *prot_anchor = NULL;
    int                           hash_length = 0;
    int                           err         = 0, i;

    // only process anchor, if we agreed on using it before
    if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        if ((param = hip_get_param(input_msg, HIP_PARAM_ESP_PROT_ANCHOR))) {
            prot_anchor = (const struct esp_prot_anchor *) param;

            // check if the anchor has got the negotiated transform
            if (prot_anchor->transform == entry->esp_prot_transform) {
                hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

                // store number of elements per hash structure
                entry->esp_peer_active_length = ntohl(prot_anchor->hash_item_length);
                HIP_DEBUG("entry->esp_peer_active_length: %u\n",
                          entry->esp_peer_active_length);

                // store all contained anchors
                for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                    if (prot_anchor->transform != entry->esp_prot_transform || !prot_anchor) {
                        // we expect an anchor and all anchors should have the same transform
                        err = -1;
                        goto out_err;
                    } else {
                        // store peer_anchor
                        memcpy(&entry->esp_peer_anchors[i][0], &prot_anchor->anchors[0],
                               hash_length);
                        HIP_HEXDUMP("received anchor: ", &entry->esp_peer_anchors[i][0],
                                    hash_length);
                    }

                    // get next anchor
                    param       = hip_get_next_param(input_msg, param);
                    prot_anchor = (const struct esp_prot_anchor *) param;
                }
            } else if (prot_anchor->transform == ESP_PROT_TFM_UNUSED) {
                HIP_DEBUG("peer encountered problems and did fallback\n");

                // also fallback
                entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
            } else {
                HIP_ERROR("received anchor does NOT use negotiated transform, falling back\n");

                // fallback
                entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
            }
        } else {
            HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");

            // fall back option
            entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
        }
    } else {
        HIP_DEBUG("NOT using esp protection extension\n");

        entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
    }

out_err:
    return err;
}

/******************** UPDATE parameters *******************/

/** Classifies update packets belonging to the esp protection extension
 *
 * @param   recv_update the received hip update
 * @return              packet type qualifiers
 */
int esp_prot_update_type(const struct hip_common *recv_update)
{
    const struct hip_seq      *seq      = NULL;
    const struct hip_ack      *ack      = NULL;
    const struct hip_esp_info *esp_info = NULL;

    HIP_ASSERT(recv_update != NULL);

    seq      = hip_get_param(recv_update, HIP_PARAM_SEQ);
    ack      = hip_get_param(recv_update, HIP_PARAM_ACK);
    esp_info = hip_get_param(recv_update, HIP_PARAM_ESP_INFO);

    if (seq && !ack && !esp_info) {
        return ESP_PROT_FIRST_UPDATE_PACKET;
    } else if (!seq && ack && esp_info) {
        return ESP_PROT_SECOND_UPDATE_PACKET;
    } else {
        HIP_DEBUG("NOT a pure ANCHOR-UPDATE, unhandled\n");

        return ESP_PROT_UNKNOWN_UPDATE_PACKET;
    }
}

/**
 * Processes the first packet of a pure ANCHOR-UPDATE
 *
 * @param recv_update   the received hip update
 * @param entry         hip association for the connection
 * @param src_ip        src ip address
 * @param dst_ip        dst ip address
 * @return              0 on success, -1 in case of an error
 **/
int esp_prot_handle_first_update_packet(const struct hip_common *recv_update,
                                        struct hip_hadb_state *entry,
                                        const struct in6_addr *src_ip,
                                        const struct in6_addr *dst_ip)
{
    uint32_t spi = 0;
    int      err = 0;

    HIP_ASSERT(entry != NULL);

    /* this is the first ANCHOR-UPDATE msg
     *
     * @note contains anchors -> update inbound SA
     * @note response has to contain corresponding ACK and ESP_INFO */
    HIP_IFEL(esp_prot_update_handle_anchor(recv_update, entry, &spi),
             -1, "failed to handle anchor in UPDATE msg\n");
    HIP_DEBUG("successfully processed anchors in ANCHOR-UPDATE\n");

    // send ANCHOR_UPDATE response, when the anchor was verified above
    HIP_IFEL(esp_prot_send_update_response(recv_update, entry, dst_ip,
                                           src_ip, spi),
             -1, "failed to send UPDATE replay");

out_err:
    return err;
}

/**
 * Processes the second packet of a pure ANCHOR-UPDATE
 *
 * @param entry     hip association for the connection
 * @param src_ip    src ip address
 * @param dst_ip    dst ip address
 * @return          0 on success, -1 in case of an error
 **/
int esp_prot_handle_second_update_packet(struct hip_hadb_state *entry,
                                         const struct in6_addr *src_ip,
                                         const struct in6_addr *dst_ip)
{
    int err = 0;

    HIP_ASSERT(entry != NULL);

    /* this is the second ANCHOR-UPDATE msg
     *
     * @note contains ACK for previously sent anchors -> update outbound SA */
    HIP_DEBUG("received ACK for previously sent ANCHOR-UPDATE\n");

    // notify sadb about next anchor
    HIP_IFEL(hip_add_sa(dst_ip, src_ip,
                        &entry->hit_our,
                        &entry->hit_peer,
                        entry->spi_outbound_new,
                        entry->esp_transform,
                        &entry->esp_out,
                        &entry->auth_out,
                        HIP_SPI_DIRECTION_OUT,
                        entry),
             -1, "failed to notify sadb about next anchor\n");

out_err:
    return err;
}

/**
 * Adds anchor elements to a HIP update message
 *
 * @param update    the received hip update
 * @param entry     hip association for the connection
 * @return          0 on success, -1 in case of an error
 */
int esp_prot_update_add_anchor(struct hip_common *update,
                               struct hip_hadb_state *entry)
{
    const struct hip_seq *seq         = NULL;
    int                   hash_length = 0;
    int                   err         = 0, i;

    // only do further processing when extension is in use
    if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        /* we only want to send anchors in 1. and 2. UPDATE message
         *
         * @note we can distinguish the 1. and 2. UPDATE message by
         *       looking at the presence of SEQ param in the packet
         *       to be sent */
        seq = hip_get_param(update, HIP_PARAM_SEQ);

        if (seq) {
            // we need to know the hash_length for this transform
            hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

            /* @note update-anchor will be set, if there was a anchor UPDATE before
             *       or if this is an anchor UPDATE; otherwise update-anchor will
             *       be NULL
             *
             * XX TODO we need to choose the correct SA with the anchor we want to
             *         update, when supporting multihoming and when this is a
             *         pure anchor-update */
            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                HIP_IFEL(hip_build_param_esp_prot_anchor(update,
                                                         entry->esp_prot_transform,
                                                         &entry->esp_local_anchors[i][0],
                                                         &entry->esp_local_update_anchors[i][0],
                                                         hash_length, entry->hash_item_length),
                         -1,
                         "building of ESP protection ANCHOR failed\n");
            }

            // only add the root if it is specified
            if (entry->esp_root_length > 0) {
                for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                    HIP_IFEL(hip_build_param_esp_prot_root(update,
                                                           entry->esp_root_length,
                                                           &entry->esp_root[i][0]),
                             -1,
                             "building of ESP ROOT failed\n");
                }
            }

            entry->esp_local_update_length = anchor_db_get_hash_item_length(entry->esp_prot_transform);
            HIP_DEBUG("entry->esp_local_update_length: %u\n",
                      entry->esp_local_update_length);
        }
    }

out_err:
    return err;
}

/**
 * Handles anchor elements in a HIP update message
 *
 * @param recv_update   the received hip update
 * @param entry         hip association for the connection
 * @param spi           the ipsec spi number
 * @return              0 on success, -1 in case of an error
 */
int esp_prot_update_handle_anchor(const struct hip_common *recv_update,
                                  struct hip_hadb_state *entry,
                                  uint32_t *spi)
{
    const struct esp_prot_anchor *prot_anchor                = NULL;
    const struct hip_tlv_common  *param                      = NULL;
    int                           hash_length                = 0;
    unsigned char                 cmp_value[MAX_HASH_LENGTH] = { 0 };
    int                           i, err                     = 0;

    HIP_ASSERT(spi != NULL);

    *spi = 0;

    param       = hip_get_param(recv_update, HIP_PARAM_ESP_PROT_ANCHOR);
    prot_anchor = (const struct esp_prot_anchor *) param;

    if (prot_anchor) {
        /* XX TODO find matching SA entry in host association for active_anchor
         *         and _inbound_ direction */

        // we need to know the hash_length for this transform
        hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

        /* treat the very first hchain update after the BEX differently
         * -> assume properties of first parallal chain same as for others */
        if (!memcmp(&entry->esp_peer_update_anchors[0][0], &cmp_value[0], MAX_HASH_LENGTH)) {
            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                // check that we are receiving an anchor matching the negotiated transform
                HIP_IFEL(entry->esp_prot_transform != prot_anchor->transform, -1,
                         "esp prot transform changed without new BEX\n");
                HIP_DEBUG("esp prot transforms match\n");

                // check that we are receiving an anchor matching the active one
                HIP_IFEL(memcmp(&prot_anchor->anchors[0], &entry->esp_peer_anchors[i][0],
                                hash_length), -1, "esp prot active peer anchors do NOT match\n");
                HIP_DEBUG("esp prot active peer anchors match\n");

                // set the update anchor as the peer's update anchor
                memcpy(&entry->esp_peer_update_anchors[i][0], &prot_anchor->anchors[hash_length],
                       hash_length);
                HIP_DEBUG("peer_update_anchor set\n");

                entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
                HIP_DEBUG("entry->esp_peer_update_length: %u\n",
                          entry->esp_peer_update_length);

                param       = hip_get_next_param(recv_update, param);
                prot_anchor = (const struct esp_prot_anchor *) param;
            }
        } else if (!memcmp(&entry->esp_peer_update_anchors[0][0], &prot_anchor->anchors[0],
                           hash_length)) {
            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                // check that we are receiving an anchor matching the active one
                HIP_IFEL(memcmp(&prot_anchor->anchors[0], &entry->esp_peer_update_anchors[i][0],
                                hash_length), -1, "esp prot active peer anchors do NOT match\n");
                HIP_DEBUG("last received esp prot update peer anchor and sent one match\n");

                // track the anchor updates by moving one anchor forward
                memcpy(&entry->esp_peer_anchors[i][0],
                       &entry->esp_peer_update_anchors[i][0],
                       hash_length);

                // set the update anchor as the peer's update anchor
                memcpy(&entry->esp_peer_update_anchors[i][0], &prot_anchor->anchors[hash_length],
                       hash_length);
                HIP_DEBUG("peer_update_anchor set\n");

                entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
                HIP_DEBUG("entry->esp_peer_update_length: %u\n",
                          entry->esp_peer_update_length);

                param       = hip_get_next_param(recv_update, param);
                prot_anchor = (const struct esp_prot_anchor *) param;
            }
        } else {
            for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
                prot_anchor = (const struct esp_prot_anchor *) param;

                HIP_IFEL(memcmp(&prot_anchor->anchors[0], &entry->esp_peer_anchors[i][0],
                                hash_length), -1, "received unverifiable anchor\n");

                /**** received newer update for active anchor ****/

                // set the update anchor as the peer's update anchor
                memcpy(&entry->esp_peer_update_anchors[i][0],
                       &prot_anchor->anchors[hash_length],
                       hash_length);

                HIP_DEBUG("peer_update_anchor set\n");

                entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
                HIP_DEBUG("entry->esp_peer_update_length: %u\n",
                          entry->esp_peer_update_length);
            }
        }

        /* @note spi is also needed in ACK packet
         * @note like this we do NOT support multihoming
         *
         * XX TODO instead use the SA of the SPI looked up in TODO above
         * when merging with UPDATE re-implementation */
        *spi = entry->spi_inbound_current;

        /* as we don't verify the hashes in the end-host, we don't have to
         * update the outbound SA now
         */
    }

out_err:
    return err;
}
