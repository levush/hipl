/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE O
 */

#ifndef HIPL_LIBHIPL_CONFIGFILEREADER_H
#define HIPL_LIBHIPL_CONFIGFILEREADER_H

#include <stdio.h>

/** Maximum number of characters in a HIP relay config file parameter. */
#define HIP_RELAY_MAX_PAR_LEN  32
/** Maximum number of characters in a HIP relay config file value. */
#define HIP_RELAY_MAX_VAL_LEN  64

/** Linked list node. */
struct hip_configfile_value {
    char                         data[HIP_RELAY_MAX_VAL_LEN + 1]; /**< Node data. */
    struct hip_configfile_value *next;     /**< A pointer to next item. */
};

/** Linked list. */
struct hip_config_value_list {
    struct hip_configfile_value *head;     /**< A pointer to the first item of the list. */
};

int hip_cf_get_line_data(FILE *fp, char *parameter,
                         struct hip_config_value_list *values,
                         int *parseerr);
void hip_cvl_init(struct hip_config_value_list *linkedlist);
void hip_cvl_uninit(struct hip_config_value_list *linkedlist);
struct hip_configfile_value *hip_cvl_get_next(struct hip_config_value_list *linkedlist,
                                              struct hip_configfile_value *current);
void print_node(struct hip_configfile_value *node);

#endif /* HIPL_LIBHIPL_CONFIGFILEREADER_H */
