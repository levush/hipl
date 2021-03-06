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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIPL_LIBCORE_PERFORMANCE_H
#define HIPL_LIBCORE_PERFORMANCE_H

/**
 * @file
 * Primitive performance measurement
 */

#include <stdio.h>

/** This performace set holds all measurements */
struct perf_set {
    /** A pointer to names of output files */
    FILE **files;
    /** A list of names of the perf sets. */
    char **names;
    /** A list timeval time structs. */
    struct timeval *times;
    /** A list of measured results. */
    double *result;
    /** The number of perf sets. */
    int num_files;
    /** A linecount */
    int *linecount;
    /** Are the necessary files opened? 1 = TRUE, 0 = FALSE. */
    int files_open;
    /** Are measurements running? This is an integer field of the length num_files. */
    int *running;
    /** Are the measurements writable (completed)? This is an integer field of the length num_files. */
    int *writable;
};

struct perf_set *hip_perf_create(int num);
int hip_perf_set_name(struct perf_set *perf_set, int slot, const char *name);
int hip_perf_open(struct perf_set *perf_set);
void hip_perf_start_benchmark(struct perf_set *perf_set, int slot);
void hip_perf_stop_benchmark(struct perf_set *perf_set, int slot);
int hip_perf_write_benchmark(struct perf_set *perf_set, int slot);
void hip_perf_destroy(struct perf_set *perf_set);

enum perf_sensor {
    PERF_I1,
    PERF_R1,
    PERF_I2,
    PERF_R2,
    PERF_UPDATE,
    PERF_VERIFY,
    PERF_BASE,
    PERF_CLOSE_SEND,
    PERF_HANDLE_CLOSE,
    PERF_HANDLE_CLOSE_ACK,
    PERF_CLOSE_COMPLETE,
    PERF_DSA_VERIFY_IMPL,
    PERF_RSA_VERIFY_IMPL,
    /* The firewall only uses the sensors given above, hence it
     * has a separate PERF_MAX. */
    PERF_MAX_FIREWALL,
    PERF_DH_CREATE,
    PERF_SIGN,
    PERF_DSA_SIGN_IMPL,
    PERF_I1_SEND,
    PERF_RSA_SIGN_IMPL,
    PERF_STARTUP,
    /* Number of sensors for the HIP daemon. */
    PERF_MAX
};

struct perf_set *perf_set;

#endif /* HIPL_LIBCORE_PERFORMANCE_H */
