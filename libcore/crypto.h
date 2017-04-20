/*
 * Copyright (c) 2010-2012 Aalto University and RWTH Aachen University.
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

#ifndef HIPL_LIBCORE_CRYPTO_H
#define HIPL_LIBCORE_CRYPTO_H

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#ifdef HAVE_EC_CRYPTO
#include <openssl/ec.h>
#endif /* HAVE_EC_CRYPTO */
#include <openssl/dh.h>
#include <openssl/pem.h>


#include "debug.h"
#include "ife.h"
#include "transform.h"
#include "builder.h"

#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */



/* These should be consistent with the table length in crypto.c and
 * crypto/dh.c */
/* 384-bit group, DEPRECATED from HIPv2 */
#define HIP_DH_384                    1
/* 768-bit OAKLEY well known group 1, DEPRECATED from HIPv2 */
#define HIP_DH_OAKLEY_1               2
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
/* 6144-bit MODP group, DEPRECATED from HIPv2 */
#define HIP_DH_OAKLEY_17              5
/* 8192-bit MODP group, DEPRECATED from HIPv2 */
#define HIP_DH_OAKLEY_18              6
/* Group 7 to 10 are new groups defined in HIPv2, among which group 7,8 and 9
 * are Ellipse Curve groups. */
#define HIP_DH_NIST_P_256             7
#define HIP_DH_NIST_P_384             8
#define HIP_DH_NIST_P_521             9
#define HIP_DH_SECP_160_R1            10
#define HIP_FIRST_DH_GROUP_ID         HIP_DH_OAKLEY_5
#define HIP_SECOND_DH_GROUP_ID        HIP_DH_384
#define HIP_MAX_DH_GROUP_ID           11

#define DSA_KEY_DEFAULT_BITS       1024
#define RSA_KEY_DEFAULT_BITS       1024
#define ECDSA_DEFAULT_CURVE        NID_X9_62_prime256v1


#define DEFAULT_HOST_DSA_KEY_FILE_BASE      HIPL_SYSCONFDIR "/hip_host_dsa_key"
#define DEFAULT_HOST_RSA_KEY_FILE_BASE      HIPL_SYSCONFDIR "/hip_host_rsa_key"
#define DEFAULT_HOST_ECDSA_KEY_FILE_BASE    HIPL_SYSCONFDIR "/hip_host_ecdsa_key"
#define DEFAULT_PUB_FILE_SUFFIX             ".pub"

#define DEFAULT_PUB_HI_FILE_NAME_SUFFIX  "_pub"
#define DEFAULT_ANON_HI_FILE_NAME_SUFFIX "_anon"

#ifdef OPENSSL_NO_SHA0
#define HIP_SHA(buffer, total_len, hash)   SHA1((buffer), (total_len), (hash))
#else
#define HIP_SHA(buffer, total_len, hash)   SHA((buffer), (total_len), (hash))
#endif

#ifdef OPENSSL_NO_SHA0
#define HIP_SHA(buffer, total_len, hash)   SHA1((buffer), (total_len), (hash))
#else
#define HIP_SHA(buffer, total_len, hash)   SHA((buffer), (total_len), (hash))
#endif

/* HIPv2: default value for DH_GROUP_LIST parameter */
#define HIP_DH_GROUP_LIST_SIZE        3
const uint8_t HIP_DH_GROUP_LIST[HIP_DH_GROUP_LIST_SIZE];

/* HIPv2: max acceptable size of DH group list, longer part will be ignored */
#define HIP_DH_GROUP_MAX_RECV_SIZE    6

int ssl_rsa_verify(uint8_t *digest, uint8_t *public_key, uint8_t *signature, int pub_klen);
int ssl_dsa_verify(uint8_t *digest, uint8_t *public_key, uint8_t *signature);
/* In kernel these come from crypto/dh.h, included above */
int hip_gen_dh_shared_key(DH *dh, const uint8_t *peer_key, size_t peer_len, uint8_t *out,
                          size_t outlen);
int hip_encode_dh_publickey(DH *dh, uint8_t *out, int outlen);
DH *hip_generate_dh_key(const int group_id);
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
DSA *create_dsa_key(const int bits);
RSA *create_rsa_key(const int bits);
int save_dsa_private_key(const char *const filenamebase, DSA *const dsa);
int save_rsa_private_key(const char *const filenamebase, RSA *const rsa);
int load_dsa_private_key(const char *const filenamebase, DSA **const dsa);
int load_rsa_private_key(const char *const filename, RSA **const rsa);
int impl_dsa_sign(const unsigned char *const digest,
                  DSA *const dsa,
                  unsigned char *const signature);
int impl_dsa_verify(const unsigned char *const digest,
                    DSA *const dsa,
                    const unsigned char *const signature);
int hip_write_hmac(int type, const void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
                         uint8_t *enc_key, int direction);
void get_random_bytes(void *buf, int n);

#ifdef HAVE_EC_CRYPTO
EC_KEY *create_ecdsa_key(const int nid);
int save_ecdsa_private_key(const char *const filenamebase, EC_KEY *const ecdsa);
int load_ecdsa_private_key(const char *const filename, EC_KEY **const ec);
int impl_ecdsa_sign(const unsigned char *const digest,
                    EC_KEY *const ecdsa,
                    unsigned char *const signature);
int impl_ecdsa_verify(const unsigned char *const digest,
                      EC_KEY *const ecdsa,
                      const unsigned char *const signature);
bool hip_is_ecdh_group(const int group_id);
EC_KEY *hip_generate_ecdh_key(const int group_id);
int hip_encode_ecdh_publickey(EC_KEY *key, uint8_t *out, int outlen);
int hip_gen_ecdh_shared_key(EC_KEY *const key,
                            const uint8_t *const peer_pub_x,
                            const uint8_t *const peer_pub_y,
                            const size_t peer_len,
                            uint8_t *const shared_key,
                            const size_t outlen);
#endif /* HAVE_EC_CRYPTO */

#endif /* HIPL_LIBCORE_CRYPTO_H */
