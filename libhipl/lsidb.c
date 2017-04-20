/*
 * Copyright (c) 2012 Aalto University and RWTH Aachen University.
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
 * Implementation of the local scope identifier (LSI) database.
 * The LSIDB manages which LSIs are assigned to network interfaces on the local
 * host and which LSIs are still available.
 */

#include <netinet/in.h>
#include <stdbool.h>

#include "libcore/common.h"
#include "libcore/debug.h"
#include "libcore/protodefs.h"
#include "lsidb.h"

static unsigned lsi_index = 1;

/**
 * Allocate an unused LSI that is still available to be used on the local host.
 * This function merely keeps track of LSIs allocated through this interface.
 * It does no check the actual network interfaces or other data structures in
 * the HIP daemon to determine whether LSIs are in use or not.
 *
 * @param lsi   Points to an LSI object that receives the LSI if this function
 *              returns successfully.
 *              The result of calling this function with @a lsi == @c NULL or
 *              @a lsi not pointing to a valid LSI object is undefined.
 * @return      This function returns true if an available LSI was successfully
 *              allocated and stored in @a lsi.
 *              This function returns false if no more LSIs are available on
 *              the local host.
 *
 * @internal
 * The current implementation is extremely primitive and returns successively
 * incremented LSIs.
 * Freeing an LSI has no effect.
 * This is currently acceptable because LSIs are allocated together with host
 * identities when HIPD starts up and LSIs are only freed when HIPD exits.
 * This interface is intended to hide potentially more complex allocation
 * schemes, too.
 */
bool lsidb_allocate_lsi(hip_lsi_t *const lsi)
{
    HIP_ASSERT(lsi);
    /* the index may not be 0 because that does not lead to a valid network
     * address */
    HIP_ASSERT(lsi_index != 0);

    /* does the index still fit into the allowed address prefix length of
     * LSIs (-1 because the highest address is the broadcast address) */
    if (lsi_index < HIP_LSI_TYPE_MASK_CLEAR) {
        *lsi = (hip_lsi_t) { htonl(HIP_LSI_PREFIX | lsi_index) };
        lsi_index++;
        return true;
    }

    return false;
}

/**
 * Free a previously allocated LSI so it is available to allocation again.
 * This function should be called only after the LSI has been de-registered
 * from the system is no longer in active use.
 *
 * @param lsi   The LSI object to free.
 * @return      This function returns true if @a lsi is an LSI that was
 *              previously allocated via lsidb_allocate_lsi() and if it was
 *              freed successfully.
 *              This function returns false if @a lsi could not be freed and
 *              made available through allocation again.
 */
bool lsidb_free_lsi(const hip_lsi_t lsi)
{
    /* is this a valid LSI? */
    if ((ntohl(lsi.s_addr) & ~HIP_LSI_TYPE_MASK_CLEAR) == HIP_LSI_PREFIX) {
        /* we currently do not support freeing the LSI */
        return true;
    }

    return false;
}
