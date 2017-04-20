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
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with
 * base exchange code. See bugzilla ids 592195 and 592196.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/lhash.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/ife.h"
#include "libcore/protodefs.h"
#include "libhipl/maintenance.h"
#include "update_builder.h"
#include "update.h"
#include "update_locator.h"

/**
 * Retrieve the locator type from type 0 and type 1 locators.
 *
 * @param  item the locator item for which to determine the type
 *
 * @return the locator type
 */
static uint8_t get_locator_type(const void *item)
{
    /* The locator_type field is at the same position for
     * type 0 and type 1 locators (c.f. RFC 5206) */
    return ((const struct hip_locator_type_0 *) item)->header.locator_type;
}

/**
 * Retrieve a locator address item from a list.
 *
 * @param item_list a pointer to the first item in the list
 * @param idx       the index of the item in the list
 * @return          the locator address item, NULL on unrecognized locator types
 */
const union hip_locator_info_addr *hip_get_locator_item(const void *item_list,
                                                        const int idx)
{
    int         i;
    uint8_t     locator_type;
    const char *result = item_list;

    for (i = 0; i <= idx - 1; i++) {
        locator_type = get_locator_type(result);
        if (locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            result += sizeof(struct hip_locator_type_0);
        } else if (locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
            result += sizeof(struct hip_locator_type_1);
        } else {
            HIP_ERROR("Bad locator type: %i \n", locator_type);
            return NULL;
        }
    }
    return (const union hip_locator_info_addr *) result;
}

/**
 * retrieve a IP address from a locator item structure
 *
 * @param item      a pointer to the item
 * @return a pointer to the IP address, NULL on unrecognized locator types
 */
const struct in6_addr *hip_get_locator_item_address(const void *const item)
{
    uint8_t locator_type;

    locator_type = get_locator_type(item);
    if (locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
        return &((const struct hip_locator_type_1 *) item)->address;
    } else if (locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
        return &((const struct hip_locator_type_0 *) item)->address;
    } else {
        HIP_ERROR("Bad locator type: %i \n", locator_type);
        return NULL;
    }
}

/**
 * Retrieve the number of locators inside a LOCATOR parameter.
 * Type 0 and 1 parameters are supported.
 *
 * @param locator a LOCATOR parameter
 * @return the number of locators, -1 on error (unrecognized locator types)
 */
int hip_get_locator_addr_item_count(const struct hip_locator *const locator)
{
    const char *address_pointer = (const char *) (locator + 1);
    int         loc_count       = 0;
    uint8_t     type;

    while (address_pointer <
           ((const char *) locator) + hip_get_param_contents_len(locator)) {
        type = get_locator_type(address_pointer);

        if (type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            address_pointer += sizeof(struct hip_locator_type_0);
        } else if (type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
            address_pointer += sizeof(struct hip_locator_type_1);
        } else {
            HIP_ERROR("Bad locator type: %i \n", type);
            return -1;
        }
        loc_count += 1;
    }
    return loc_count;
}
