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

#include <check.h>
#include <stdlib.h>

#include "libhipl/lsidb.c"
#include "test_suites.h"

START_TEST(test_lsidb_allocate_lsi_valid)
{
    hip_lsi_t lsi;

    /* exhaust all available LSIs */
    for (unsigned i = 1; i < HIP_LSI_TYPE_MASK_CLEAR; i++) {
        fail_unless(lsidb_allocate_lsi(&lsi) == true, NULL);
        /* does the returned LSI have the correct LSI head? */
        fail_unless((lsi.s_addr & ntohl(HIP_LSI_TYPE_MASK_1)) != 0, NULL);
        /* does the returned LSI have the correct prefix? */
        fail_unless((lsi.s_addr & ntohl(~HIP_LSI_TYPE_MASK_CLEAR)) == ntohl(HIP_LSI_TYPE_MASK_1), NULL);
    }

    /* now the allocator should return an error because there should be no
     * LSIs left. */
    fail_unless(lsidb_allocate_lsi(&lsi) == false, NULL);
}
END_TEST

START_TEST(test_lsidb_free_lsi_valid)
{
    hip_lsi_t lsi;

    fail_unless(lsidb_allocate_lsi(&lsi) == true, NULL);
    fail_unless(lsidb_free_lsi(lsi) == true, NULL);
}
END_TEST

START_TEST(test_lsidb_free_lsi_invalid)
{
    hip_lsi_t lsi = { 0xFFFFFFFF };

    fail_unless(lsidb_free_lsi(lsi) == false, NULL);
}
END_TEST

START_TEST(test_lsidb_allocate_lsi_null)
{
    lsidb_allocate_lsi(NULL);
}
END_TEST

Suite *hipd_lsidb(void)
{
    Suite *s = suite_create("hipd/lsidb");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_lsidb_allocate_lsi_valid);
    tcase_add_test(tc_core, test_lsidb_free_lsi_valid);
    tcase_add_test(tc_core, test_lsidb_free_lsi_invalid);
    tcase_add_exit_test(tc_core, test_lsidb_allocate_lsi_null, 1);
    suite_add_tcase(s, tc_core);

    return s;
}
