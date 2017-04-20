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

#ifndef HIPL_HIPFW_CACHE_H
#define HIPL_HIPFW_CACHE_H

#include <netinet/in.h>

#include "libcore/protodefs.h"
#include "libcore/icomm.h"
#include "libcore/state.h"

enum fw_cache_query_type { FW_CACHE_HIT, FW_CACHE_LSI, FW_CACHE_IP };

struct hip_hadb_user_info_state *hipfw_cache_db_match(const void *local,
                                                      const void *peer,
                                                      enum fw_cache_query_type type,
                                                      int query_daemon);

void hipfw_cache_init_hldb(void);

void hipfw_cache_delete_hldb(int);

int hipfw_cache_set_bex_state(const struct in6_addr *hit_s,
                              const struct in6_addr *hit_r,
                              enum hip_state state);

#endif /* HIPL_HIPFW_CACHE_H */
