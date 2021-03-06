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

/**
 * @file
 * @brief Unit tests of libcore (see doc/HACKING on unit tests).
 */

#include <stdlib.h>
#include <check.h>

#include "test/libcore/test_suites.h"

int main(void)
{
    int number_failed;

    SRunner *sr = srunner_create(NULL);
    srunner_add_suite(sr, libcore_cert());
    srunner_add_suite(sr, libcore_hit());
    srunner_add_suite(sr, libcore_hostid());
    srunner_add_suite(sr, libcore_solve());
    srunner_add_suite(sr, libcore_straddr());

    srunner_add_suite(sr, libcore_gpl_checksum());

    srunner_add_suite(sr, libcore_modules_midauth_builder());

#ifdef HAVE_EC_CRYPTO
    srunner_add_suite(sr, libcore_crypto());

    srunner_add_suite(sr, libcore_gpl_pk());
#endif /* HAVE_EC_CRYPTO */

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
