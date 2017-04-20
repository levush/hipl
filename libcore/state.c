/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University
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

#include "debug.h"
#include "state.h"

/**
 * Gets the name of a state.
 *
 * @param  state a state state value
 * @return a state name as a string.
 */
const char *hip_state_str(enum hip_state state)
{
    switch (state) {
    case HIP_STATE_NONE:
        return "NONE";
    case HIP_STATE_UNASSOCIATED:
        return "UNASSOCIATED";
    case HIP_STATE_I1_SENT:
        return "I1-SENT";
    case HIP_STATE_I2_SENT:
        return "I2-SENT";
    case HIP_STATE_R2_SENT:
        return "R2-SENT";
    case HIP_STATE_ESTABLISHED:
        return "ESTABLISHED";
    case HIP_STATE_FAILED:
        return "FAILED";
    case HIP_STATE_CLOSING:
        return "CLOSING";
    case HIP_STATE_CLOSED:
        return "CLOSED";
    case HIP_STATE_R1_SENT:
        return "R1-SENT";
    case HIP_STATE_U1_SENT:
        return "U1-SENT";
    case HIP_STATE_U2_SENT:
        return "U2-SENT";
    default:
        HIP_ERROR("invalid state %u\n", state);
        return "UNKNOWN";
    }
}
