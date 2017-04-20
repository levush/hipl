/*
 * Copyright (c) 2010, 2012 Aalto University and RWTH Aachen University.
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
 * This is the main source file of the module HEARTBEAT-UPDATE. Its core
 * functionality is UPDATE triggering if HEARTBEATS fail. You can adjust the
 * threshold which has to be reached before an UPDATE is triggered.
 *
 * During module initialization an maintenance function is registered. This
 * checks if the threshold value is reached and triggers the UPDATE if needed.
 *
 * The heartbeat counter is set to 0, if an UPDATE was triggered.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "libcore/builder.h"
#include "libcore/common.h"
#include "libcore/debug.h"
#include "libcore/protodefs.h"
#include "libhipl/hadb.h"
#include "libhipl/maintenance.h"
#include "modules/update/hipd/update.h"
#include "modules/update/hipd/update_locator.h"
#include "hb_update.h"

static const int hip_heartbeat_trigger_update_threshold = 5;

static int hb_update_trigger(struct hip_hadb_state *const hadb_entry,
                             UNUSED void *opaque)
{
    uint8_t *heartbeat_failures = NULL;

    if (hadb_entry->state == HIP_STATE_ESTABLISHED) {
        heartbeat_failures = lmod_get_state_item(hadb_entry->hip_modular_state,
                                                "heartbeat_update");

        if (*heartbeat_failures > 0 &&
            *heartbeat_failures % hip_heartbeat_trigger_update_threshold == 0) {
            HIP_DEBUG("HEARTBEAT counter reached threshold, trigger UPDATE\n");

            if (hip_trigger_update(hadb_entry)) {
                HIP_DEBUG("failed to trigger update\n");
                return -1;
            }
        }
    }

    return 0;
}

static int hb_update_maintenance(void)
{
    hip_for_each_ha(hb_update_trigger, NULL);

    return 0;
}

int hip_hb_update_init(void)
{
    HIP_INFO("Initializing tunnel updates for heartbeat extension\n");

    if (hip_register_maint_function(&hb_update_maintenance, 50000)) {
        HIP_DEBUG("Error on registration of hip_hb_update_maintenance()\n");
        return -1;
    }

    return 0;
}
