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

#ifndef HIPL_LIBHIPL_DH_H
#define HIPL_LIBHIPL_DH_H

#include <stdint.h>

#include "libcore/protodefs.h"


int hip_insert_dh(uint8_t *buffer, int bufsize, int group_id);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(const uint16_t group_id,
                                const uint8_t *const pulic_value,
                                const int len,
                                unsigned char *const buffer,
                                const int bufsize);
int hip_init_cipher(void);

int hip_insert_dh_v2(uint8_t *buffer, int bufsize, int group_id);
int hip_insert_ecdh(uint8_t *buffer, int bufsize, int group_id);
int hip_match_dh_group_list(const struct hip_tlv_common *const dh_group_list,
                            const uint8_t *our_dh_group, const int our_group_size);

#endif /* HIPL_LIBHIPL_DH_H */
