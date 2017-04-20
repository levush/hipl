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
 * @brief Functionality for dynamic packet handling.
 */

#include <stdint.h>

#include "libcore/builder.h"
#include "libcore/ife.h"
#include "libcore/linkedlist.h"
#include "libcore/protodefs.h"
#include "libcore/state.h"
#include "libcore/modularization.h"
#include "pkt_handling.h"


struct handle_function {
    uint16_t priority;
    int      (*func_ptr)(const uint8_t packet_type,
                         const enum hip_state ha_state,
                         struct hip_packet_context *ctx);
};

/**
 * This three-dimension array stores lists of packet handling functions
 * categorized by HIP version numbers, HIP packet types and HIP host
 * association states. Each list contains corresponding handle functions
 * sorted by priority.
 */
static struct hip_ll *hip_handle_functions[HIP_MAX_VERSION][HIP_MAX_PACKET_TYPE][HIP_MAX_HA_STATE];

/**
 * Register a function for handling packets with specified combination from HIP
 * version, packet type and host association state.
 *
 * @param hip_version     HIP version. If HIP_ALL is given, the handle function
                          is registered to all HIP versions which are supported
                          by HIPL.
 * @param packet_type     The packet type of the control message
 *                        (RFC 5201, 5.3.)
 * @param ha_state        The host association state (RFC 5201, 4.4.1.)
 * @param handle_function Pointer to the function which should be called
 *                        when the combination of packet type and host
 *                        association state is reached.
 * @param priority        Execution priority for the handle function.
 *
 * @return                0 on success, -1 on error.
 */
int hip_register_handle_function(const uint8_t hip_version,
                                 const uint8_t packet_type,
                                 const enum hip_state ha_state,
                                 int (*handle_function)(const uint8_t packet_type,
                                                        const enum hip_state ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint16_t priority)
{
    int                     err       = 0;
    struct handle_function *new_entry = NULL;

    if (hip_version == HIP_ALL) {
        for (int i = HIP_V1; i < HIP_MAX_VERSION; i++) {
            err = hip_register_handle_function(i, packet_type, ha_state,
                                               handle_function, priority);
            if (err) {
                return -1;
            }
        }
        return 0;
    }

    if (hip_version <= 0 || hip_version >= HIP_MAX_VERSION) {
        HIP_ERROR("Invalid HIP version: %d\n", hip_version);
        return -1;
    }

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    HIP_IFEL(!(new_entry = malloc(sizeof(struct handle_function))),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->priority = priority;
    new_entry->func_ptr = handle_function;

    hip_handle_functions[hip_version][packet_type][ha_state] =
        lmod_register_function(hip_handle_functions[hip_version][packet_type][ha_state],
                               new_entry,
                               priority);
    if (!hip_handle_functions[hip_version][packet_type][ha_state]) {
        HIP_ERROR("Error on registering a handle function.\n");
        err = -1;
    }
out_err:
    return err;
}

/**
 * Run all handle functions for specified combination from packet type and host
 * association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx The packet context containing the received message, source and
 *            destination address, the ports and the corresponding entry from
 *            the host association database.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_run_handle_functions(const uint8_t packet_type,
                             const enum hip_state ha_state,
                             struct hip_packet_context *ctx)
{
    int                       err = 0;
    int                       hip_version;
    const struct hip_ll_node *iter = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    hip_version = hip_get_msg_version(ctx->input_msg);

    HIP_IFEL(!hip_handle_functions[hip_version][packet_type][ha_state],
             -1,
             "Error on running handle functions.\nPacket type: %d, HA state: %d\n",
             packet_type,
             ha_state);

    while ((iter = hip_ll_iterate(hip_handle_functions[hip_version][packet_type][ha_state],
                                  iter))
           && !ctx->error) {
        err = ((struct handle_function *) iter->ptr)->func_ptr(packet_type,
                                                               ha_state,
                                                               ctx);
        if (err) {
            HIP_ERROR("Error after running registered handle function, dropping packet...\n");
            return err;
        }
    }

out_err:
    return err;
}

/**
 * Free the memory used for storage of handle functions.
 *
 */
void hip_uninit_handle_functions(void)
{
    int i, j, k;

    for (i = 0; i < HIP_MAX_VERSION; i++) {
        for (j = 0; j < HIP_MAX_PACKET_TYPE; j++) {
            for (k = 0; k < HIP_MAX_HA_STATE; k++) {
                if (hip_handle_functions[i][j][k]) {
                    hip_ll_uninit(hip_handle_functions[i][j][k], free);
                    free(hip_handle_functions[i][j][k]);
                }
            }
        }
    }
}
