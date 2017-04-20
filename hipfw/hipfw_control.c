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
 * Firewall communication interface with hipd. Firewall can send messages
 * asynchronously (recommended) or synchronously (not recommended because
 * other messages may intervene).
 *
 * @brief Firewall communication interface with hipd
 */

#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/ife.h"
#include "libcore/message.h"
#include "libcore/prefix.h"
#include "libcore/protodefs.h"
#include "cache.h"
#include "conntrack.h"
#include "hipfw.h"
#include "user_ipsec_fw_msg.h"
#include "user_ipsec_sadb.h"
#include "hipfw_control.h"

/**
 * Change the state of hadb state cache in the firewall
 *
 * @param msg the message containing hadb cache information
 *
 * @return zero on success, non-zero on error
 */
static int handle_bex_state_update(struct hip_common *msg)
{
    const struct in6_addr       *src_hit = NULL, *dst_hit = NULL;
    const struct hip_tlv_common *param   = NULL;
    int                          err     = 0, msg_type = 0;

    msg_type = hip_get_msg_type(msg);

    /* src_hit */
    param   = hip_get_param(msg, HIP_PARAM_HIT);
    src_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Source HIT: ", src_hit);

    /* dst_hit */
    param   = hip_get_next_param(msg, param);
    dst_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

    /* update bex_state in firewalldb */
    switch (msg_type) {
    case HIP_MSG_FW_BEX_DONE:
        err = hipfw_cache_set_bex_state(src_hit, dst_hit,
                                        HIP_STATE_ESTABLISHED);
        break;
    case HIP_MSG_FW_UPDATE_DB:
        err = hipfw_cache_set_bex_state(src_hit, dst_hit,
                                        HIP_STATE_NONE);
        break;
    default:
        break;
    }
    return err;
}

/**
 * distribute a user message to the respective extension handler
 *
 * @param   msg  pointer to the received user message
 * @param   addr destination address for a reply
 * @return  0 on success, else -1
 */
int hip_handle_msg(struct hip_common *msg, struct sockaddr *addr)
{
    int                type, err = 0;
    struct hip_common *msg_out = NULL;

    HIP_DEBUG("Handling message from hipd\n");

    type = hip_get_msg_type(msg);

    HIP_DEBUG("of type %d\n", type);

    switch (type) {
    case HIP_MSG_FW_BEX_DONE:
    case HIP_MSG_FW_UPDATE_DB:
        if (hip_lsi_support) {
            handle_bex_state_update(msg);
        }
        break;
    case HIP_MSG_IPSEC_ADD_SA:
        HIP_DEBUG("Received add sa request from hipd\n");
        HIP_IFEL(handle_sa_add_request(msg), -1,
                 "hip userspace sadb add did NOT succeed\n");
        break;
    case HIP_MSG_IPSEC_DELETE_SA:
        HIP_DEBUG("Received delete sa request from hipd\n");
        HIP_IFEL(handle_sa_delete_request(msg), -1,
                 "hip userspace sadb delete did NOT succeed\n");
        break;
    case HIP_MSG_IPSEC_FLUSH_ALL_SA:
        HIP_DEBUG("Received flush all sa request from hipd\n");
        hip_sadb_flush();
        break;
    case HIP_MSG_RESET_FIREWALL_DB:
        hipfw_cache_delete_hldb(0);
        break;
    case HIP_MSG_OFFER_FULLRELAY:
        if (!esp_relay) {
            HIP_ERROR("Enable ESP relay with option -r for hipfw!\n");
            hip_fw_init_esp_relay();
        }
        break;
    case HIP_MSG_CANCEL_FULLRELAY:
        HIP_DEBUG("To disable ESP relay, restart hipfw without -r option\n");
        hip_fw_uninit_esp_relay();
        break;
    case HIP_MSG_GET_HA_INFO:
        HIP_IFEL(hip_fw_handle_get_ha_info(msg), -1,
                 "Could not handle GET_HA message.\n");
        HIP_IFEL(hip_fw_send_message(msg, addr), -1,
                 "Could not send HA reply.\n");
        break;
    default:
        HIP_ERROR("Unhandled message type %d\n", type);
        err = -1;
        break;
    }

out_err:
    if (hip_get_msg_response(msg)) {
        HIP_DEBUG("Send response\n");
        if (err) {
            hip_hdr msg_type = hip_get_msg_type(msg);
            hip_msg_init(msg);
            hip_build_user_hdr(msg, msg_type, 0);
            hip_set_msg_err(msg, 1);
        }
        HIP_DEBUG("Sending message (type=%d) response\n",
                  hip_get_msg_type(msg));
        if (hip_fw_send_message(msg, addr) == -1) {
            err = -1;
        } else {
            HIP_DEBUG("Response sent ok\n");
        }
    }

    free(msg_out);
    return err;
}
