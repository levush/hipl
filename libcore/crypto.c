/*
 * Copyright (c) 2010-2013 Aalto University and RWTH Aachen University.
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
 * HIP crypto management functions using OpenSSL.  Includes
 * Diffie-Hellman groups and shared key generation, DSA/RSA key
 * creation and disk storage, signing, verifying and HMAC creation.
 *
 * @brief HIP crypto management functions using OpenSSL
 *
 * @todo Intergrate ERR_print_errors_fp somehow into HIP_INFO().
 * @todo No printfs! Daemon has no stderr.
 * @todo Return values should be from <errno.h>.
 * @todo Clean up the code!
 * @todo Use goto err_out, not return 1.
 * @todo Check that DH key is created exactly as stated in Jokela draft
 *       RFC2412?
 * @todo Create a function for calculating HIT from DER encoded DSA pubkey
 * @todo can alloc_and_extract_bin_XX_pubkey() be merged into one function
 * @todo more consistency in return values: all functions should always return
 *       _negative_, _symbolic_ values (with the exception of zero)
 * @todo "Bad signature r or s size" occurs randomly. This should not happen.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "libcore/gpl/pk.h"
#include "config.h"
#include "common.h"
#include "debug.h"
#include "ife.h"
#include "keylen.h"
#include "performance.h"
#include "crypto.h"


const uint8_t HIP_DH_GROUP_LIST[HIP_DH_GROUP_LIST_SIZE] = {
    HIP_DH_NIST_P_384,
    HIP_DH_OAKLEY_15,
    HIP_DH_OAKLEY_5
};

/*
 * Diffie-Hellman primes
 */

/* 384-bit Group */
static unsigned char dhprime_384[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0xB2, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 2412 Oakley Group 1 768-bit, 96 bytes */
static unsigned char dhprime_oakley_1[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x3A, 0x36, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 3526 MODP 1536-bit = RFC 2412 Oakley Group 5 */
static unsigned char dhprime_modp_1536[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 3526 MODP 3072-bit, 384 bytes */
static unsigned char dhprime_modp_3072[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 3526 MODP 6144-bit, 768 bytes */
static unsigned char dhprime_modp_6144[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
    0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
    0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
    0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
    0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
    0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
    0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2,
    0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
    0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
    0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
    0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB,
    0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
    0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51,
    0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
    0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15,
    0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
    0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31,
    0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
    0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
    0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
    0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2,
    0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
    0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D,
    0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
    0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7,
    0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
    0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E,
    0x6D, 0xCC, 0x40, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 3526 MODP 8192-bit, 1024 bytes */
static unsigned char dhprime_modp_8192[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
    0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
    0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
    0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
    0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
    0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
    0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2,
    0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
    0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
    0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
    0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB,
    0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
    0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51,
    0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
    0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15,
    0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
    0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31,
    0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
    0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
    0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
    0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2,
    0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
    0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D,
    0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
    0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7,
    0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
    0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E,
    0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
    0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0,
    0x73, 0xB9, 0x31, 0xBA, 0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00,
    0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED, 0x25, 0x76, 0xF6, 0x93,
    0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
    0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB,
    0xE3, 0x9D, 0x65, 0x2D, 0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
    0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 0x13, 0xEB, 0x57, 0xA8,
    0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
    0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F,
    0xA2, 0xC0, 0x87, 0xE8, 0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A,
    0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 0x6D, 0x2A, 0x13, 0xF8,
    0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
    0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5,
    0x08, 0x46, 0x85, 0x1D, 0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1,
    0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 0xFA, 0xF3, 0x6B, 0xC3,
    0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
    0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E,
    0xD5, 0xEE, 0x38, 0x2B, 0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47,
    0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA, 0x9E, 0x30, 0x50, 0xE2,
    0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
    0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

/* load DH arrays for easy access */
static const unsigned char *dhprime[HIP_MAX_DH_GROUP_ID] = {
    0,
    dhprime_384,
    dhprime_oakley_1,
    dhprime_modp_1536,
    dhprime_modp_3072,
    dhprime_modp_6144,
    dhprime_modp_8192,
};

static int dhprime_len[HIP_MAX_DH_GROUP_ID] = {
    -1,
    sizeof(dhprime_384),
    sizeof(dhprime_oakley_1),
    sizeof(dhprime_modp_1536),
    sizeof(dhprime_modp_3072),
    sizeof(dhprime_modp_6144),
    sizeof(dhprime_modp_8192),
    64,                       /* NIST P-256 */
    96,                       /* NIST P-384 */
    132,                      /* NIST P-512 */
    0,                        /* SECP 160R1, unsupported */
};

static unsigned char dhgen[HIP_MAX_DH_GROUP_ID] = { 0,
                                                    0x02,
                                                    0x02,
                                                    0x02,
                                                    0x02,
                                                    0x02,
                                                    0x02 };

/**
 * Calculates a hmac.
 *
 * @param type   type (digest algorithm) of hmac.
 * @param key    a pointer to the key used for hmac.
 * @param in     a pointer to the input buffer.
 * @param in_len the length of the input buffer @c in.
 * @param out    a pointer to the output buffer. For SHA1-HMAC this is 160bits.
 * @return       1 if ok, zero otherwise.
 * @warning      This function returns 1 for success which is against the policy
 *               defined in @c /doc/HACKING.
 */
int hip_write_hmac(int type, const void *key, void *in, int in_len, void *out)
{
    switch (type) {
    case HIP_DIGEST_SHA1_HMAC:
        HMAC(EVP_sha1(),
             key,
             hip_hmac_key_length(HIP_ESP_AES_SHA1),
             in, in_len,
             out, NULL);
        break;

    case HIP_DIGEST_MD5_HMAC:
        HMAC(EVP_md5(),
             key,
             hip_hmac_key_length(HIP_ESP_3DES_MD5),
             in, in_len,
             out, NULL);
        break;
    default:
        HIP_ERROR("Unknown HMAC type 0x%x\n", type);
        return 1;
    }

    HIP_HEXDUMP("HMAC key:", key, hip_hmac_key_length(HIP_ESP_AES_SHA1));
    HIP_HEXDUMP("HMAC in:", in, in_len);
    HIP_HEXDUMP("HMAC out:", out, HIP_AH_SHA_LEN);

    return 0;
}

/**
 * @brief Encrypt or decrypts data.
 *
 * Encrypts/decrypts data in @c data and places the result in the same buffer
 * @c data thus overwriting the original source data.
 *
 * @param data      a pointer to a buffer of data to be encrypted/decrypted.
 *                  This is both a source and a target buffer.
 * @param iv_orig   a pointer to an initialization vector
 * @param alg       encryption algorithm to use
 * @param len       length of @c data
 * @param key       encryption/decryption key to use
 * @param direction flag for selecting encryption/decryption. Either
 *                  HIP_DIRECTION_ENCRYPT or HIP_DIRECTION_DECRYPT
 *
 * @return          Zero if the encryption/decryption was successful, negative
 *                  otherwise.
 */
int hip_crypto_encrypted(void *data, const void *iv_orig, int alg, int len,
                         uint8_t *key, int direction)
{
    void            *result = NULL;
    int              err    = -1;
    AES_KEY          aes_key;
    des_key_schedule ks1, ks2, ks3;
    uint8_t          secret_key1[8], secret_key2[8], secret_key3[8];
    /* OpenSSL modifies the IV it is passed during the encryption/decryption */
    uint8_t iv[20];
    HIP_IFEL(!(result = malloc(len)), -1, "Out of memory\n");

    switch (alg) {
    case HIP_HIP_AES_SHA1:
        /* AES key must be 128, 192, or 256 bits in length */
        memcpy(iv, iv_orig, 16);
        if (direction == HIP_DIRECTION_ENCRYPT) {
            HIP_IFEL((err = AES_set_encrypt_key(key, 8 * hip_transform_key_length(alg), &aes_key)) != 0, err,
                     "Unable to use calculated DH secret for AES key (%d)\n", err);
            AES_cbc_encrypt(data, result, len, &aes_key, (unsigned char *) iv, AES_ENCRYPT);
        } else {
            HIP_IFEL((err = AES_set_decrypt_key(key, 8 * hip_transform_key_length(alg), &aes_key)) != 0, err,
                     "Unable to use calculated DH secret for AES key (%d)\n", err);
            AES_cbc_encrypt(data, result, len, &aes_key, (unsigned char *) iv, AES_DECRYPT);
        }
        memcpy(data, result, len);
        break;

    case HIP_HIP_3DES_SHA1:
        memcpy(iv, iv_orig, 8);
        memcpy(&secret_key1, key, hip_transform_key_length(alg) / 3);
        memcpy(&secret_key2, key + 8, hip_transform_key_length(alg) / 3);
        memcpy(&secret_key3, key + 16, hip_transform_key_length(alg) / 3);

        des_set_odd_parity((des_cblock *) &secret_key1);
        des_set_odd_parity((des_cblock *) &secret_key2);
        des_set_odd_parity((des_cblock *) &secret_key3);

        HIP_IFEL((err = des_set_key_checked(((des_cblock *) &secret_key1), ks1)) != 0 ||
                 (err = des_set_key_checked(((des_cblock *) &secret_key2), ks2)) != 0 ||
                 (err = des_set_key_checked(((des_cblock *) &secret_key3), ks3)) != 0,
                 err, "Unable to use calculated DH secret for 3DES key (%d)\n", err);
        des_ede3_cbc_encrypt(data, result, len,
                             ks1, ks2, ks3, (des_cblock *) iv,
                             direction == HIP_DIRECTION_ENCRYPT ? DES_ENCRYPT : DES_DECRYPT);
        memcpy(data, result, len);
        break;

    case HIP_HIP_NULL_SHA1:
        HIP_DEBUG("Null encryption used.\n");
        break;

    default:
        HIP_OUT_ERR(-EINVAL, "Attempted to use unknown CI (alg = %d)\n", alg);
    }

    err = 0;

out_err:
    free(result);

    return err;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Sign using ECDSA
 *
 * @param digest the sha1-160 digest of the message to sign
 * @param ecdsa the ECDSA key
 * @param signature write the signature here (we will need ECDSA_size(signing_key) of memory);
 *
 * @return 0 on success and negative on error
 */
int impl_ecdsa_sign(const unsigned char *const digest,
                    EC_KEY *const ecdsa,
                    unsigned char *const signature)
{
    ECDSA_SIG *ecdsa_sig = NULL;
    int        err       = 0, sig_size;

    HIP_IFEL(!digest, -1, "NULL digest \n");
    HIP_IFEL(!signature, -1, "NULL signature output destination \n");
    HIP_IFEL(!EC_KEY_check_key(ecdsa),
             -1, "Check of signing key failed. \n");

    sig_size = ECDSA_size(ecdsa);
    memset(signature, 0, sig_size);

    ecdsa_sig = ECDSA_do_sign(digest, HIP_AH_SHA_LEN, ecdsa);
    HIP_IFEL(!ecdsa_sig, -1, "ECDSA_do_sign failed\n");

    /* build signature from ECDSA_SIG struct */
    bn2bin_safe(ecdsa_sig->r, signature, sig_size / 2);
    bn2bin_safe(ecdsa_sig->s, signature + sig_size / 2, sig_size / 2);

out_err:
    ECDSA_SIG_free(ecdsa_sig);
    return err;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * Sign using DSA
 *
 * @param digest the sha1-160 digest of the message to sign
 * @param dsa the DSA key
 * @param signature write the signature here (we need memory of size HIP_DSA_SIGNATURE_LEN)
 *
 * @return 0 on success and non-zero on error
 */
int impl_dsa_sign(const unsigned char *const digest, DSA *const dsa, unsigned char *const signature)
{
    DSA_SIG *dsa_sig = NULL;
    int      err     = 0, t;

    t = (BN_num_bytes(dsa->p) - 64) / 8;
    HIP_IFEL(t > 8 || t < 0, 1, "Illegal DSA key\n");

    memset(signature, 0, HIP_DSA_SIGNATURE_LEN);
    signature[0] = t;

    /* calculate the DSA signature of the message hash */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_DSA_SIGN_IMPL\n");
    hip_perf_start_benchmark(perf_set, PERF_DSA_SIGN_IMPL);
#endif
    dsa_sig = DSA_do_sign(digest, SHA_DIGEST_LENGTH, dsa);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_DSA_SIGN_IMPL\n");
    hip_perf_stop_benchmark(perf_set, PERF_DSA_SIGN_IMPL);
#endif
    HIP_IFEL(!dsa_sig, 1, "DSA_do_sign failed\n");

    /* build signature from DSA_SIG struct */
    bn2bin_safe(dsa_sig->r, &signature[1], DSA_PRIV);
    bn2bin_safe(dsa_sig->s, &signature[1 + DSA_PRIV], DSA_PRIV);

out_err:
    DSA_SIG_free(dsa_sig);
    return err;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Verify an ECDSA signature
 *
 * @param digest a digest which was used to create the signature
 * @param ecdsa the ECDSA key
 * @param signature the signature to verify
 *
 * @return 1 for a valid signature, 0 for an incorrect signature and -1 on
 *         error (see ERR_get_error(3) for the actual error)
 */
int impl_ecdsa_verify(const unsigned char *const digest,
                      EC_KEY *const ecdsa,
                      const unsigned char *const signature)
{
    ECDSA_SIG *ecdsa_sig = NULL;
    int        err       = 0, sig_size;

    HIP_IFEL(!digest, -1, "NULL digest \n");
    HIP_IFEL(!ecdsa, -1, "NULL key \n");
    HIP_IFEL(!signature, -1, "NULL signature \n");

    sig_size = ECDSA_size(ecdsa);

    /* build the signature structure */
    ecdsa_sig = ECDSA_SIG_new();
    HIP_IFEL(!ecdsa_sig, 1, "Failed to allocate ECDSA_SIG\n");
    ecdsa_sig->r = BN_bin2bn(signature, sig_size / 2, NULL);
    ecdsa_sig->s = BN_bin2bn(signature + sig_size / 2, sig_size / 2, NULL);
    err          = ECDSA_do_verify(digest, SHA_DIGEST_LENGTH, ecdsa_sig, ecdsa) == 1 ? 0 : 1;

out_err:
    ECDSA_SIG_free(ecdsa_sig);
    return err;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * Verify a DSA signature
 *
 * @param digest a digest which was used to create the signature
 * @param dsa the DSA key
 * @param signature the signature to verify
 *
 * @return 1 for a valid signature, 0 for an incorrect signature and -1 on
 *         error (see ERR_get_error(3) for the actual error)
 */
int impl_dsa_verify(const unsigned char *const digest, DSA *const dsa, const unsigned char *const signature)
{
    DSA_SIG *dsa_sig;
    int      err = 0;

    /* build the signature structure */
    dsa_sig = DSA_SIG_new();
    HIP_IFEL(!dsa_sig, 1, "Failed to allocate DSA_SIG\n");
    dsa_sig->r = BN_bin2bn(&signature[1], DSA_PRIV, NULL);
    dsa_sig->s = BN_bin2bn(&signature[1 + DSA_PRIV], DSA_PRIV, NULL);

    /* verify the DSA signature */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_DSA_VERIFY_IMPL\n");
    hip_perf_start_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
#endif
    err = DSA_do_verify(digest, SHA_DIGEST_LENGTH, dsa_sig, dsa) == 1 ? 0 : 1;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_DSA_VERIFY_IMPL\n");
    hip_perf_stop_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
#endif

out_err:
    DSA_SIG_free(dsa_sig);
    return err;
}

/**
 * Generate a shared key using Diffie-Hellman.
 *
 * @param dh Diffie-Hellman key
 * @param peer_key peer's public key
 * @param peer_len length of the peer_key
 * @param dh_shared_key shared key to generate
 * @param outlen the length of the shared key
 * @return 1 on success, 0 otherwise
 */
int hip_gen_dh_shared_key(DH *dh,
                          const uint8_t *peer_key,
                          size_t peer_len,
                          uint8_t *dh_shared_key,
                          size_t outlen)
{
    BIGNUM *peer_pub_key = NULL;
    size_t  len;
    int     err;

    HIP_IFEL(!dh, -EINVAL, "No DH context\n");
    HIP_IFEL(!(peer_pub_key = BN_bin2bn(peer_key, peer_len, NULL)),
             -EINVAL, "Unable to read peer_key\n");
    HIP_IFEL((len = DH_size(dh)) > outlen, -EINVAL,
             "Output buffer too small. %d bytes required\n", len);
    err = DH_compute_key(dh_shared_key, peer_pub_key, dh);

out_err:
    BN_free(peer_pub_key);
    return err;
}

/**
 * Encode Diffie-Hellman key into a character array.
 *
 * @param dh Diffie-Hellman key
 * @param out output argument: a character array
 * @param outlen the length of @c out in bytes
 * @return the number of bytes written
 */
int hip_encode_dh_publickey(DH *dh, uint8_t *out, int outlen)
{
    int len, err;
    HIP_IFEL(!dh, -EINVAL, "No Diffie Hellman context for DH tlv.\n");
    HIP_IFEL(outlen < (len = BN_num_bytes(dh->pub_key)), -EINVAL,
             "Output buffer %d too small. %d bytes required\n", outlen, len);

    err = bn2bin_safe(dh->pub_key, out, outlen);

out_err:
    return err;
}

/**
 * Generate a new Diffie-Hellman key.
 *
 * @param group_id the group id of the D-H
 * @return a new Diffie-Hellman key (caller deallocates)
 */
DH *hip_generate_dh_key(const int group_id)
{
    int            err;
    DH            *dh;
    char           rnd_seed[20];
    struct timeval time1;

    gettimeofday(&time1, NULL);
    sprintf(rnd_seed, "%x%x", (unsigned int) time1.tv_usec,
            (unsigned int) time1.tv_sec);
    RAND_seed(rnd_seed, sizeof(rnd_seed));

    dh    = DH_new();
    dh->g = BN_new();
    dh->p = BN_new();
    /* Put prime corresponding to group_id into dh->p */
    BN_bin2bn(dhprime[group_id],
              dhprime_len[group_id], dh->p);
    /* Put generator corresponding to group_id into dh->g */
    BN_set_word(dh->g, dhgen[group_id]);
    /* By not setting dh->priv_key, allow crypto lib to pick at random */
    if ((err = DH_generate_key(dh)) != 1) {
        HIP_ERROR("DH key generation failed (%d).\n", err);
        exit(1);
    }
    return dh;
}

#ifdef HAVE_EC_CRYPTO

/**
 * Test if the current DH group ID belongs to an ECDH group.
 *
 * @param group_id the Diffie-Hellman group ID
 * @return         True if the given group is an ECDH group, False otherwise.
 */
bool hip_is_ecdh_group(const int group_id)
{
    return group_id == HIP_DH_NIST_P_256 ||
           group_id == HIP_DH_NIST_P_384 ||
           group_id == HIP_DH_NIST_P_521;
}

/**
 * Generate a new Elliptic Curve Diffie-Hellman key.
 *
 * @param group_id the group ID of the DH_GROUP defined in HIPv2
 * @return         a new ECDH key (caller deallocates), or NULL on error.
 */
EC_KEY *hip_generate_ecdh_key(const int group_id)
{
    char           rnd_seed[20];
    struct timeval tv;
    EC_KEY        *key;
    int            nid;

    switch (group_id) {
    case HIP_DH_NIST_P_256:
        nid = NID_X9_62_prime256v1;
        break;
    case HIP_DH_NIST_P_384:
        nid = NID_secp384r1;
        break;
    case HIP_DH_NIST_P_521:
        nid = NID_secp521r1;
        break;
    default:
        HIP_ERROR("Unsupported ECDH group: %d\n", group_id);
        return NULL;
    }

    gettimeofday(&tv, NULL);
    sprintf(rnd_seed, "%x%x", (unsigned int) tv.tv_usec,
            (unsigned int) tv.tv_sec);
    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if ((key = EC_KEY_new_by_curve_name(nid)) == NULL) {
        HIP_ERROR("Failed to create a new EC_KEY from nid: %d\n", nid);
        return NULL;
    }

    if (EC_KEY_generate_key(key) == 0) {
        HIP_ERROR("Failed to generate parameters for the new EC_KEY.\n");
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

/**
 * Generate a shared key using Elliptic Curve Diffie-Hellman.
 * This method only supports keys using Prime Curve.
 *
 * @param key           the Elliptic Curve Diffie-Hellman key
 * @param peer_pub_x    the x coordinator of the peer's public key
 * @param peer_pub_y    the y coordinator of the peer's public key
 * @param peer_len      length of the @c peer_pub_x or @c peer_pub_y (these two
 *                      length values are identical)
 * @param shared_key    shared key to generate
 * @param outlen        the length of the @c shared_key
 * @return              the length of the shared key on success, 0 otherwise
 */
int hip_gen_ecdh_shared_key(EC_KEY *const key,
                            const uint8_t *const peer_pub_x,
                            const uint8_t *const peer_pub_y,
                            const size_t peer_len,
                            uint8_t *const shared_key,
                            const size_t outlen)
{
    const EC_GROUP *group;
    BIGNUM         *peer_pubx = NULL;
    BIGNUM         *peer_puby = NULL;
    EC_POINT       *peer_pub  = NULL;
    unsigned int    err       = 1;

    if (EC_KEY_check_key(key) == 0) {
        HIP_ERROR("Invalid input EC_KEY\n");
        return 0;
    }

    group = EC_KEY_get0_group(key);

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        != NID_X9_62_prime_field) {
        HIP_ERROR("Invalid group method, only prime curve is supported.\n");
        return 0;
    }

    peer_pub  = EC_POINT_new(group);
    peer_pubx = BN_bin2bn(peer_pub_x, peer_len, NULL);
    peer_puby = BN_bin2bn(peer_pub_y, peer_len, NULL);

    HIP_IFEL(EC_POINT_set_affine_coordinates_GFp(group, peer_pub, peer_pubx,
                                                 peer_puby, NULL) == 0,
             0, "Failed to create peer's public key.\n");

    err = ECDH_compute_key(shared_key, outlen, peer_pub, key, NULL);
    HIP_IFEL(err == 0 || err != peer_len, 0,
             "Failed to compute the ECDH shared key\n");

out_err:
    BN_free(peer_pubx);
    BN_free(peer_puby);
    EC_POINT_free(peer_pub);
    return err;
}

/**
 * Encode an ECDH public key into a character array.
 *
 * @param key      the ECDH key
 * @param[out] out the character array
 * @param outlen   the length of @c out in bytes
 * @return         the number of bytes written
 */
int hip_encode_ecdh_publickey(EC_KEY *key, uint8_t *out, int outlen)
{
    BIGNUM *pubx = NULL;
    BIGNUM *puby = NULL;
    int     len;
    int     err = 0;

    if (key == NULL || out == NULL || outlen < 0 ||
        EC_KEY_check_key(key) == 0) {
        HIP_ERROR("Invalid input\n");
        return -1;
    }

    pubx = BN_new();
    puby = BN_new();
    HIP_IFEL(pubx == NULL || puby == NULL, -1, "Failed to initialize Big Number\n");

    err = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key),
                                              EC_KEY_get0_public_key(key),
                                              pubx, puby, NULL);
    HIP_IFEL(err == 0, -1,
             "Failed to get x,y coordinates from the ECDH key\n");

    len = BN_num_bytes(pubx);
    HIP_IFEL(outlen < len * 2, -1, "Output buffer too small\n");

    bn2bin_safe(pubx, out, outlen / 2);
    bn2bin_safe(puby, out + outlen / 2, outlen / 2);
    err = outlen;

out_err:
    BN_free(pubx);
    BN_free(puby);
    return err;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * Determine the size for required to store DH shared secret.
 * @param hip_dh_group_type the group type from DIFFIE_HELLMAN parameter
 *
 * @return 0 on failure, or the size for storing DH shared secret in bytes
 */
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type)
{
    uint16_t ret = 0;

    if (hip_dh_group_type == 0) {
        HIP_ERROR("Trying to use reserved DH group type 0\n");
    } else if (hip_dh_group_type > ARRAY_SIZE(dhprime_len)) {
        HIP_ERROR("Unknown/unsupported DH or ECDH group %d\n", hip_dh_group_type);
    } else {
        ret = dhprime_len[hip_dh_group_type];
    }

    return ret;
}

/**
 * Generate DSA parameters and a new key pair.
 * @param bits length of the prime
 *
 * The caller is responsible for freeing the allocated DSA key.
 *
 * @return the created DSA structure, otherwise NULL.
 */
DSA *create_dsa_key(const int bits)
{
    DSA *dsa = NULL;

    dsa = DSA_generate_parameters(bits, NULL, 0, NULL, NULL, NULL, NULL);
    if (!dsa) {
        HIP_ERROR("create_dsa_key failed (DSA_generate_parameters): %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
        goto err_out;
    }

    /* generate private and public keys */
    if (!DSA_generate_key(dsa)) {
        HIP_ERROR("create_dsa_key failed (DSA_generate_key): %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
        goto err_out;
    }

    HIP_DEBUG("*****************Creating DSA of %d bits\n\n\n", bits);
    return dsa;

err_out:
    DSA_free(dsa);
    return NULL;
}

/**
 * generate RSA parameters and a new key pair
 * @param bits length of the prime
 *
 * The caller is responsible for freeing the allocated RSA key.
 *
 * @return the created RSA structure, otherwise NULL.
 */
RSA *create_rsa_key(const int bits)
{
    RSA    *rsa = RSA_new();
    BIGNUM *f4  = BN_new();
    BN_set_word(f4, RSA_F4);

    /* generate private and public keys */
    HIP_DEBUG("*****************Creating RSA of %d bits\n\n\n", bits);
    if (!RSA_generate_key_ex(rsa, bits, f4, NULL)) {
        HIP_ERROR("create_rsa_key failed (RSA_generate_key_ex): %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
        goto err_out;
    }

    return rsa;

err_out:
    RSA_free(rsa);
    return NULL;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Generate ECDSA parameters and a new key pair.
 *
 * The caller is responsible for freeing the allocated ECDSA key.
 *
 * @param nid openssl specific curve id, for the curve to be used with this key
 *
 * @return the created ECDSA structure on success, NULL otherwise
 */
EC_KEY *create_ecdsa_key(const int nid)
{
    EC_KEY   *err       = NULL;
    EC_KEY   *eckey     = NULL;
    EC_GROUP *group     = NULL;
    int       asn1_flag = OPENSSL_EC_NAMED_CURVE;

    HIP_IFEL(!(eckey = EC_KEY_new()),
             NULL, "Could not init new key.\n");

    HIP_IFEL(!(group = EC_GROUP_new_by_curve_name(nid)),
             NULL, "Could not create curve. No curve with NID: %i.\n", nid);

    EC_GROUP_set_asn1_flag(group, asn1_flag);

    HIP_IFEL(!EC_KEY_set_group(eckey, group),
             NULL, "Could not set group.\n");

    HIP_IFEL(!EC_KEY_generate_key(eckey),
             NULL, "Could not generate EC key\n");

    return eckey;

out_err:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    return err;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * Save host DSA keys to disk.
 * @param filenamebase the filename base where DSA key should be saved
 * @param dsa the DSA key structure
 *
 * The DSA keys from dsa are saved in PEM format, public key to file
 * filenamebase.pub, private key to file filenamebase and DSA parameters to
 * file filenamebase.params. If any of the files cannot be saved, all
 * files are deleted.
 *
 * @todo change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return 0 if all files were saved successfully, or non-zero if an error
 * occurred.
 */
int save_dsa_private_key(const char *const filenamebase, DSA *const dsa)
{
    int   err         = 0, files = 0, ret;
    char *pubfilename = NULL;
    int   pubfilename_len;
    FILE *fp = NULL;

    HIP_IFEL(!filenamebase, 1, "NULL filenamebase\n");

    pubfilename_len =
        strlen(filenamebase) + sizeof(DEFAULT_PUB_FILE_SUFFIX);
    pubfilename = malloc(pubfilename_len);
    HIP_IFEL(!pubfilename, 1, "malloc for pubfilename failed\n");

    ret = snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
                   DEFAULT_PUB_FILE_SUFFIX);
    HIP_IFEL(ret <= 0, 1, "Failed to create pubfilename\n");

    HIP_INFO("Saving DSA keys to: pub='%s' priv='%s'\n", pubfilename,
             filenamebase);
    HIP_INFO("Saving host DSA pubkey=%s\n", BN_bn2hex(dsa->pub_key));
    HIP_INFO("Saving host DSA privkey=%s\n", BN_bn2hex(dsa->priv_key));
    HIP_INFO("Saving host DSA p=%s\n", BN_bn2hex(dsa->p));
    HIP_INFO("Saving host DSA q=%s\n", BN_bn2hex(dsa->q));
    HIP_INFO("Saving host DSA g=%s\n", BN_bn2hex(dsa->g));

    /* rewrite using PEM_write_PKCS8PrivateKey */

    fp = fopen(pubfilename, "wb" /* mode */);
    HIP_IFEL(!fp, 1,
             "Couldn't open public key file %s for writing\n", pubfilename);
    files++;

    err = PEM_write_DSA_PUBKEY(fp, dsa) == 0 ? 1 : 0;

    if (err) {
        HIP_ERROR("Write failed for %s\n", pubfilename);
        goto out_err;
    }
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

    fp = fopen(filenamebase, "wb" /* mode */);
    HIP_IFEL(!fp, 1,
             "Couldn't open private key file %s for writing\n", filenamebase);
    files++;

    HIP_IFEL(!PEM_write_DSAPrivateKey(fp, dsa, NULL, NULL, 0, NULL, NULL),
             1, "Write failed for %s\n", filenamebase);

out_err:
    if (err && fp) {
        if (fclose(fp)) {
            HIP_ERROR("Error closing file\n");
        }
    } else if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
    }

    if (err) {
        switch (files) {
        case 2:
            if (unlink(filenamebase)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", filenamebase);
            }
        case 1:
            if (unlink(pubfilename)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", pubfilename);
            }
        default:
            break;
        }
    }

    free(pubfilename);

    return err;
}

/**
 * Save host RSA keys to disk.
 * @param filenamebase the filename base where RSA key should be saved
 * @param rsa the RSA key structure
 *
 * The RSA keys from rsa are saved in PEM format, public key to file
 * filenamebase.pub, private key to file filenamebase and RSA
 * parameters to file filenamebase.params. If any of the files cannot
 * be saved, all files are deleted.
 *
 * @todo change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return 0 if all files were saved successfully, or non-zero if an
 * error occurred.
 */
int save_rsa_private_key(const char *const filenamebase, RSA *const rsa)
{
    int   err         = 0, files = 0, ret;
    char *pubfilename = NULL;
    int   pubfilename_len;
    FILE *fp = NULL;

    HIP_IFEL(!filenamebase, 1, "NULL filenamebase\n");

    pubfilename_len =
        strlen(filenamebase) + sizeof(DEFAULT_PUB_FILE_SUFFIX);
    pubfilename = malloc(pubfilename_len);
    HIP_IFEL(!pubfilename, 1, "malloc for pubfilename failed\n");

    ret = snprintf(pubfilename, pubfilename_len, "%s%s",
                   filenamebase,
                   DEFAULT_PUB_FILE_SUFFIX);
    HIP_IFEL(ret <= 0, 1, "Failed to create pubfilename\n");

    HIP_INFO("Saving RSA keys to: pub='%s' priv='%s'\n", pubfilename,
             filenamebase);
    HIP_INFO("Saving host RSA n=%s\n", BN_bn2hex(rsa->n));
    HIP_INFO("Saving host RSA e=%s\n", BN_bn2hex(rsa->e));
    HIP_INFO("Saving host RSA d=%s\n", BN_bn2hex(rsa->d));
    HIP_INFO("Saving host RSA p=%s\n", BN_bn2hex(rsa->p));
    HIP_INFO("Saving host RSA q=%s\n", BN_bn2hex(rsa->q));

    /* rewrite using PEM_write_PKCS8PrivateKey */

    fp = fopen(pubfilename, "wb");
    HIP_IFEL(!fp, 1,
             "Couldn't open public key file %s for writing\n", pubfilename);
    files++;

    err = PEM_write_RSA_PUBKEY(fp, rsa) == 0 ? 1 : 0;

    if (err) {
        HIP_ERROR("Write failed for %s\n", pubfilename);
        goto out_err;
    }
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

    fp = fopen(filenamebase, "wb" /* mode */);
    HIP_IFEL(!fp, 1,
             "Couldn't open private key file %s for writing\n", filenamebase);
    files++;

    HIP_IFEL(!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL),
             1, "Write failed for %s\n", filenamebase);

out_err:

    if (err && fp) {
        if (fclose(fp)) {
            HIP_ERROR("Error closing file\n");
        }
    } else if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
    }

    if (err) {
        switch (files) {
        case 2:
            if (unlink(filenamebase)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", filenamebase);
            }
        case 1:
            if (unlink(pubfilename)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", pubfilename);
            }
        default:
            break;
        }
    }

    free(pubfilename);

    return err;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Save the host's ECDSA keys to disk.
 *
 * The ECDSA key at *ecdsa is saved in PEM format: the public key is saved to file
 * filename.pub, the private key to file filename. If any of the files cannot
 * be written, all files are deleted.
 *
 * @param filename  the filename base where the ECDSA key should be saved
 * @param ecdsa     the ECDSA key structure to be saved
 *
 * @return  0 if all files were saved successfully, or negative if an
 *          error occurred.
 */
int save_ecdsa_private_key(const char *const filename, EC_KEY *const ecdsa)
{
    int   err         = 0, files = 0, ret, pubfilename_len;
    char *pubfilename = NULL;
    FILE *fp          = NULL;

    if (!filename) {
        HIP_ERROR("NULL filename\n");
        return -1;
    }
    if (!ecdsa) {
        HIP_ERROR("NULL key\n");
        return -1;
    }
    // Test necessary to catch keys that have only been initialized with EC_KEY_new()
    // but not properly generated. Such keys cause segmentation faults when
    // being passed into EC_KEY_get0_group()
    if (!EC_KEY_check_key(ecdsa)) {
        HIP_ERROR("Invalid key. \n");
        return -1;
    }

    pubfilename_len = strlen(filename) + sizeof(DEFAULT_PUB_FILE_SUFFIX);
    pubfilename     = malloc(pubfilename_len);
    if (!pubfilename) {
        HIP_ERROR("malloc for pubfilename failed\n");
        return -1;
    }
    ret = snprintf(pubfilename, pubfilename_len, "%s%s",
                   filename,
                   DEFAULT_PUB_FILE_SUFFIX);
    HIP_IFEL(ret <= 0, -1, "Failed to create pubfilename\n");

    HIP_INFO("Saving ECDSA keys to: pub='%s' priv='%s'\n", pubfilename,
             filename);

    fp = fopen(pubfilename, "wb" /* mode */);
    HIP_IFEL(!fp, -1,
             "Couldn't open public key file %s for writing\n", pubfilename);
    files++;

    HIP_IFEL(!PEM_write_ECPKParameters(fp, EC_KEY_get0_group(ecdsa)),
             -1, "Could not save parameters of public key\n");

    HIP_IFEL(!PEM_write_EC_PUBKEY(fp, ecdsa),
             -1, "Could not write public EC Key to %s \n", filename);

    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

    fp = fopen(filename, "wb" /* mode */);
    HIP_IFEL(!fp, -1,
             "Couldn't open private key file %s for writing\n", filename);
    files++;

    HIP_IFEL(!PEM_write_ECPKParameters(fp, EC_KEY_get0_group(ecdsa)),
             -1, "Could not save parameters of private key\n");

    HIP_IFEL(!PEM_write_ECPrivateKey(fp, ecdsa, NULL, NULL, 0, NULL, NULL),
             -1, "Could not write private EC Key to %s \n", filename);

out_err:

    if (err && fp) {
        if (fclose(fp)) {
            HIP_ERROR("Error closing file\n");
        }
    } else if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file %s\n", filename);
    }

    if (err) {
        switch (files) {
        case 2:
            if (unlink(filename)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", filename);
            }
        case 1:
            if (unlink(pubfilename)) { /* add error check */
                HIP_ERROR("Could not delete file %s\n", pubfilename);
            }
        default:
            break;
        }
    }

    free(pubfilename);

    return err;
}

/**
 * Load the host's private EC keys from disk.
 *
 * @param filename  the filename of the host EC key
 * @param ecdsa     the openssl key structure is allocated at *ecdsa
 *
 * Loads EC private key from file filename. EC struct
 * will be allocated dynamically and it is the responsibility
 * of the caller to free it with EC_free.
 *
 * @return  On success *ecdsa contains the EC structure.
 *          On failure *ecdsa contains NULL if the key could not be loaded
 *          (not in PEM format or file not found, etc).
 */
int load_ecdsa_private_key(const char *const filename, EC_KEY **const ecdsa)
{
    FILE *fp = NULL;

    if (!filename) {
        HIP_ERROR("NULL filename\n");
        return -ENOENT;
    }
    if (!ecdsa) {
        HIP_ERROR("NULL destination key\n");
        return -1;
    }

    *ecdsa = NULL;

    fp = fopen(filename, "rb");
    if (!fp) {
        HIP_ERROR("Could not open private key file %s for reading\n", filename);
        return -ENOMEM;
    }

    *ecdsa = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    if (fclose(fp)) {
        HIP_ERROR("Error closing file\n");
        return -1;
    }

    if (!EC_KEY_check_key(*ecdsa)) {
        HIP_ERROR("Error during loading of ecdsa key.\n");
        return -1;
    }

    return 0;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * Load host DSA private keys from disk.
 * @param filename the file name base of the host DSA key
 * @param dsa Pointer to the DSA key structure.
 *
 * Loads DSA private key from file filename. DSA struct
 * will be allocated dynamically and it is the responsibility
 * of the caller to free it with DSA_free.
 *
 * @return On success *dsa contains the DSA structure. On failure
 * *dsa contins NULL if the key could not be loaded (not in PEM format
 * or file not found, etc).
 */
int load_dsa_private_key(const char *const filename, DSA **const dsa)
{
    FILE *fp  = NULL;
    int   err = 0;

    *dsa = NULL;

    HIP_IFEL(!filename, -ENOENT, "NULL filename\n");

    fp = fopen(filename, "rb");
    HIP_IFEL(!fp, -ENOMEM,
             "Could not open private key file %s for reading\n", filename);

    *dsa = PEM_read_DSAPrivateKey(fp, NULL, NULL, NULL);
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

    HIP_IFEL(!*dsa, -EINVAL, "Read failed for %s\n", filename);

out_err:

    return err;
}

/**
 * Load host RSA private keys from disk.
 * @param filename the file name base of the host RSA key
 * @param rsa Pointer to the RSA key structure.
 *
 * Loads RSA private key from file filename. RSA struct
 * will be allocated dynamically and it is the responsibility
 * of the caller to free it with RSA_free.
 *
 * @return On success *rsa contains the RSA structure. On failure
 * *rsa contains NULL if the key could not be loaded (not in PEM
 * format or file not found, etc).
 */
int load_rsa_private_key(const char *const filename, RSA **const rsa)
{
    FILE *fp  = NULL;
    int   err = 0;

    *rsa = NULL;

    HIP_IFEL(!filename, -ENOENT, "NULL filename\n");

    fp = fopen(filename, "rb");
    HIP_IFEL(!fp, -ENOMEM,
             "Couldn't open private key file %s for reading\n", filename);

    *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }
    HIP_IFEL(!*rsa, -EINVAL, "Read failed for %s\n", filename);

out_err:

    return err;
}

/**
 * Get random bytes.
 *
 * @param buf a buffer where to write random bytes
 * @param n write n bytes to @c buf
 */
void get_random_bytes(void *buf, int n)
{
    RAND_bytes(buf, n);
}
