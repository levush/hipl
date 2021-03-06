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
 * This file defines helper function for statistical computations
 */

#define _BSD_SOURCE

#include <math.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>

#include "debug.h"
#include "ife.h"
#include "statistics.h"


/**
 * Convert a timeval struct to milliseconds
 *
 *
 * @param timeval   time value
 * @return          time value in milliseconds
 */
static uint64_t timeval_to_uint64(const struct timeval *timeval)
{
    HIP_ASSERT(timeval != NULL);

    /* convert values to microseconds and add */
    return (timeval->tv_sec * STATS_IN_USECS) + timeval->tv_usec;
}

/**
 * Compute mean value for a given data set
 *
 * @param statistics_data   data set
 * @param scaling_factor    scale samples by this constant factor
 * @return                  mean value
 */
static double calc_avg(const struct statistics_data *statistics_data,
                       const double scaling_factor)
{
    double avg = 0.0;

    HIP_ASSERT(statistics_data != NULL);
    HIP_ASSERT(scaling_factor > 0);

    if (statistics_data->num_items >= 1) {
        avg = (statistics_data->added_values / scaling_factor)
              / statistics_data->num_items;
    }

    return avg;
}

/**
 * Compute standard deviation for a given data set
 *
 * @param statistics_data   data set
 * @param scaling_factor    scale samples by this constant factor
 * @return                  standard deviation
 */
static double calc_std_dev(const struct statistics_data *statistics_data,
                           const double scaling_factor)
{
    double std_dev = 0.0;
    double sum1    = 0.0, sum2 = 0.0;

    HIP_ASSERT(statistics_data != NULL);

    if (statistics_data->num_items >= 1) {
        sum1 = (double) statistics_data->added_values / statistics_data->num_items;
        sum2 = (double) statistics_data->added_squared_values
               / statistics_data->num_items;

        std_dev = sqrt(sum2 - (sum1 * sum1));
    }

    return std_dev / scaling_factor;
}

/**
 * Compute the difference between two timevals, i.e. timeval_end - timeval_start.
 *
 * @param timeval_start first time value
 * @param timeval_end   second time value
 * @return              difference in microseconds
 *                      0 if result would be negative
 */
uint64_t calc_timeval_diff(const struct timeval *const timeval_start,
                           const struct timeval *const timeval_end)
{
    struct timeval rel_timeval;

    HIP_ASSERT(timeval_start != NULL);
    HIP_ASSERT(timeval_end != NULL);

    /* check that timeval_high really is higher */
    if (timeval_end->tv_sec > timeval_start->tv_sec ||
        (timeval_end->tv_sec == timeval_start->tv_sec &&
         timeval_end->tv_usec > timeval_start->tv_usec)) {
        timersub(timeval_end, timeval_start, &rel_timeval);
    } else {
        rel_timeval.tv_sec  = 0;
        rel_timeval.tv_usec = 0;
    }

    return timeval_to_uint64(&rel_timeval);
}

/**
 * Adds a sample to a given data set
 *
 * @note Memory for statistics_data must be allocated
 *       and managed outside this function.
 *
 * @param statistics_data   data set
 * @param item_value        sample
 * @return                  0 on success, -1 otherwise
 */
int add_statistics_item(struct statistics_data *statistics_data,
                        const uint64_t item_value)
{
    int err = 0;

    HIP_ASSERT(statistics_data != NULL);

    HIP_IFEL(!(statistics_data->num_items < statistics_data->num_items + 1), -1,
             "value exceeds data type range\n");
    statistics_data->num_items++;

    HIP_IFEL(!(statistics_data->added_values < statistics_data->added_values + item_value),
             -1,
             "value exceeds data type range\n")
    statistics_data->added_values += item_value;


    HIP_IFEL(!(statistics_data->added_squared_values < statistics_data->added_squared_values + item_value * item_value),
             -1,
             "value exceeds data type range\n");
    statistics_data->added_squared_values += item_value * item_value;

    if (item_value > statistics_data->max_value) {
        statistics_data->max_value = item_value;
    }

    if (item_value < statistics_data->min_value ||
        statistics_data->min_value == 0.0) {
        statistics_data->min_value = item_value;
    }

out_err:
    if (err) {
        HIP_DEBUG("resetting statistics\n");

        statistics_data->num_items            = 0;
        statistics_data->added_values         = 0;
        statistics_data->added_squared_values = 0;
    }

    return err;
}

/**
 * Fills a set of pointers with the results present in a given
 * data structure
 *
 * @param statistics_data   data set
 * @param num_items    number of samples in the data set
 * @param min          minimal value in the data set
 * @param max          maximal value in the data set
 * @param avg          mean value of the data set
 * @param std_dev      standard deviation from the mean value
 * @param scaling_factor    scale values by this constant factor
 */
void calc_statistics(const struct statistics_data *statistics_data,
                     uint32_t *num_items,
                     double *min,
                     double *max,
                     double *avg,
                     double *std_dev,
                     double scaling_factor)
{
    HIP_ASSERT(statistics_data != NULL);

    if (num_items) {
        *num_items = statistics_data->num_items;
    }
    if (min) {
        *min = statistics_data->min_value / scaling_factor;
    }
    if (max) {
        *max = statistics_data->max_value / scaling_factor;
    }
    if (avg) {
        *avg = calc_avg(statistics_data, scaling_factor);
    }
    if (std_dev) {
        *std_dev = calc_std_dev(statistics_data, scaling_factor);
    }
}
