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
 * @brief Diffie-Hellman wrappers for HIP
 */

#include <stdint.h>
#include <sys/types.h>
#include <openssl/ossl_typ.h>

#include "libcore/crypto.h"
#include "libcore/debug.h"
#include "dh.h"

/**
 * This table holds Diffie-Hellman values used during HIP BEXs.
 * These values are generated when the HIP daemon starts and valid for its
 * lifetime.
 * Each array element corresponds to a DH value of a specific DH group.
 * The valid groups are defined in RFC 5201, section 5.2.6.
 * This array is indexed by the Group ID value defined in the RFC.
 * Note that this means that the array element at index 0 is thus unused.
 */
static DH *dh_table[HIP_MAX_DH_GROUP_ID] = { 0 };

#ifdef HAVE_EC_CRYPTO
static EC_KEY *ecdh_table[HIP_MAX_DH_GROUP_ID] = { 0 };
#endif /* HAVE_EC_CRYPTO */

/**
 * insert the current DH-key into the buffer
 *
 * If a DH-key does not exist, we will create one.
 * @return the number of bytes written
 */
int hip_insert_dh(uint8_t *buffer, int bufsize, int group_id)
{
    int res;
    DH *tmp;

    if (group_id <= 0 || group_id >= HIP_MAX_DH_GROUP_ID) {
        HIP_ERROR("The Group ID %d is invalid\n", group_id);
        res = -1;
        goto err_free;
    }

    /*
     * First check that we have the key available.
     * Then encode it into the buffer
     */

    if (dh_table[group_id] == NULL) {
        tmp = hip_generate_dh_key(group_id);

        dh_table[group_id] = tmp;

        if (dh_table[group_id] == NULL) {
            HIP_ERROR("DH key %d not found and could not create it\n",
                      group_id);
            return -1;
        }
    }

    tmp = dh_table[group_id];

    res = hip_encode_dh_publickey(tmp, buffer, bufsize);
    if (res < 0) {
        HIP_ERROR("Encoding error\n");
        res = -1;
        goto err_free;
    }

err_free:
    return res;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Store the bytes of the current ECDH public key in the given buffer.
 *
 * A new ECDH key will be created if it doesn't exist,
 *
 * @param buffer   buffer to store the public part of the ECDH key
 * @param bufsize  size of the @c buffer
 * @param group_id group ID of the ECDH key
 * @return         the number of bytes written to the buffer, -1 on error.
 */
int hip_insert_ecdh(uint8_t *buffer, int bufsize, int group_id)
{
    EC_KEY *key;
    int     ret;

    if (!hip_is_ecdh_group(group_id)) {
        HIP_ERROR("Invalid group id for ECDH: %d\n", group_id);
        return -1;
    }

    if (ecdh_table[group_id] == NULL) {
        key = hip_generate_ecdh_key(group_id);
        if (key == NULL) {
            HIP_ERROR("Failed to generate an ECDH key for group: %d\n",
                      group_id);
            return -1;
        }
        ecdh_table[group_id] = key;
    }

    key = ecdh_table[group_id];
    if ((ret = hip_encode_ecdh_publickey(key, buffer, bufsize)) < 0) {
        HIP_ERROR("Failed to encode the ECDH public key\n");
        return -1;
    }

    return ret;
}
#endif /* HAVE_EC_CRYPTO */

/**
 * HIPv2: Store the bytes of the current ECDH/DH public key to the given buffer.
 *
 * An ECDH/DH key will be created if it does not exist.
 *
 * @param buffer   the buffer to store the ECDH/DH public key
 * @param bufsize  the size of the @c buffer
 * @param group_id the group ID of the ECDH/DH key
 * @return         the number of bytes written to the buffer
 */
int hip_insert_dh_v2(uint8_t *buffer, int bufsize, int group_id)
{
    if (group_id <= 0 || group_id >= HIP_MAX_DH_GROUP_ID) {
        HIP_ERROR("Invalid DH_GROUP_ID: %d\n", group_id);
        return -1;
    }

#ifdef HAVE_EC_CRYPTO
    if (hip_is_ecdh_group(group_id)) {
        return hip_insert_ecdh(buffer, bufsize, group_id);
    } else {
        return hip_insert_dh(buffer, bufsize, group_id);
    }
#else
    return hip_insert_dh(buffer, bufsize, group_id);
#endif /* HAVE_EC_CRYPTO */
}

/**
 * Match the first identical DH group ID in local and peer's list.
 *
 * @param dh_group_list  the DH_GROUP_LIST parameter sent from the peer
 * @param our_dh_group   the local DH list
 * @param our_group_size the size of the @c our_dh_group
 * @return               ID of the matched group on success, -1 otherwise.
 */
int hip_match_dh_group_list(const struct hip_tlv_common *const dh_group_list,
                            const uint8_t *const our_dh_group,
                            const int our_group_size)
{
    int     list_size = HIP_DH_GROUP_MAX_RECV_SIZE;
    uint8_t list[list_size];
    int     i, j;

    list_size = hip_get_list_from_param(dh_group_list, list, list_size,
                                        sizeof(uint8_t));
    for (i = 0; i < list_size; i++) {
        for (j = 0; j < our_group_size; j++) {
            if (our_dh_group[j] == list[i]) {
                return our_dh_group[j];
            }
        }
    }

    return -1;
}

/**
 * Calculate a Diffie-Hellman shared secret based on the public key of the peer
 * (passed as an argument) and own DH private key (created beforehand).
 *
 * @param group_id     the Diffie-Hellman group ID
 * @param public_value the Diffie-Hellman public key of the peer
 * @param len          the length of the @c public_value
 * @param buffer       the buffer that holds enough space for the shared secret
 * @param bufsize      the size of the @c buffer
 *
 * @return             the length of the shared secret in octets if successful,
 *                     or -1 if an error occurred.
 */
static int hip_calculate_dh_shared_secret(const uint16_t group_id,
                                          const uint8_t *const public_value,
                                          const int len,
                                          unsigned char *const buffer,
                                          const int bufsize)
{
    DH *key;
    int secret_len;

    if (group_id <= 0 || group_id >= HIP_MAX_DH_GROUP_ID) {
        HIP_ERROR("Invalid Group ID: %d.\n", group_id);
        return -1;
    }

    if (dh_table[group_id] == NULL) {
        if (NULL == (key = hip_generate_dh_key(group_id))) {
            HIP_ERROR("Failed to generate a DH key for group: %d\n", group_id);
            return -1;
        }
        dh_table[group_id] = key;
    }
    key = dh_table[group_id];

    secret_len = hip_gen_dh_shared_key(dh_table[group_id], public_value, len,
                                       buffer, bufsize);
    if (secret_len < 0) {
        HIP_ERROR("failed to create a DH shared secret\n");
        return -1;
    }

    return secret_len;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Calculate an Elliptic Curve Diffie-Hellman shared secret.
 *
 * The length of the public value should match the corresponding ECDH group; The
 * buffer to hold the shared secret should be at least larger than the length of
 * the public value divided by 2.
 *
 * @param group_id     the ECDH group ID
 * @param public_value Peer's ECDH public key
 * @param pubkey_len   the length of the @c public_value
 * @param buffer       Buffer that holds enough space for the shared secret
 * @param bufsize      size of the @c buffer
 *
 * @return             the length of the shared secret in octets if successful,
 *                     or -1 if an error occurred.
 */
static int hip_calculate_ecdh_shared_secret(const uint16_t group_id,
                                            const uint8_t *const public_value,
                                            const int pubkey_len,
                                            unsigned char *const buffer,
                                            const int bufsize)
{
    EC_KEY *key;
    int     key_len;

    if (ecdh_table[group_id] == NULL) {
        if (NULL == (key = hip_generate_ecdh_key(group_id))) {
            HIP_ERROR("Failed to generate an ECDH key for group: %d\n",
                      group_id);
            return -1;
        }
        ecdh_table[group_id] = key;
    }
    key = ecdh_table[group_id];

    key_len = hip_get_dh_size(group_id);
    if (key_len != pubkey_len || key_len / 2 > bufsize) {
        HIP_ERROR("Invalid public key length (%d) or buffer size (%d)\n",
                  pubkey_len, bufsize);
        return -1;
    }
    int out = hip_gen_ecdh_shared_key(key, public_value,
                                      public_value + key_len / 2,
                                      key_len / 2,
                                      buffer,
                                      bufsize);
    if (out <= 0) {
        HIP_ERROR("Failed to generate a shared secret\n");
        return -1;
    }

    return out;
}
#endif /* HAVE_EC_CRYPTO */

/**
 * Calculate a shared secret for Diffie-Hellman exchange.
 *
 * This function supports both normal DH and ECDH groups. The DH private key
 * is created beforehand.
 *
 * @param group_id     the Diffie-Hellman group ID
 * @param public_value the Diffie-Hellman public key of the peer
 * @param len          the length of the @c public_value
 * @param buffer       Buffer that holds the shared secret
 * @param bufsize      size of the @c buffer
 *
 * @return             the length of the shared secret in octets if successful,
 *                     or -1 if an error occurred.
 */
int hip_calculate_shared_secret(const uint16_t group_id,
                                const uint8_t *const public_value,
                                const int len,
                                unsigned char *const buffer,
                                const int bufsize)
{
    if (group_id <= 0 || group_id >= HIP_MAX_DH_GROUP_ID) {
        HIP_ERROR("Invalid Diffie-Hellman group ID: %d\n", group_id);
        return -1;
    }

#ifdef HAVE_EC_CRYPTO
    if (hip_is_ecdh_group(group_id)) {
        return hip_calculate_ecdh_shared_secret(group_id, public_value, len,
                                                buffer, bufsize);
    } else {
        return hip_calculate_dh_shared_secret(group_id, public_value, len,
                                              buffer, bufsize);
    }
#else
        return hip_calculate_dh_shared_secret(group_id, public_value, len,
                                              buffer, bufsize);
#endif /* HAVE_EC_CRYPTO */
}

/**
 * Re-generate a DH key for a given group ID.
 *
 * @param group_id the Diffie-Hellman group ID
 * @return         0 on success, -1 otherwise
 */
static int regen_dh_key(const int group_id)
{
    DH *tmp, *okey;

    tmp = hip_generate_dh_key(group_id);
    if (!tmp) {
        HIP_INFO("Failed to generate a DH key for group: %d\n", group_id);
        return -1;
    }

    okey               = dh_table[group_id];
    dh_table[group_id] = tmp;

    DH_free(okey);
    return 0;
}

#ifdef HAVE_EC_CRYPTO
/**
 * Re-generate DH key for a given ECDH group ID.
 *
 * @param group_id the ECDH group ID
 * @return         0 on success, -1 otherwise
 */
static int regen_ecdh_key(const int group_id)
{
    EC_KEY *tmp, *okey;

    tmp = hip_generate_ecdh_key(group_id);
    if (!tmp) {
        HIP_INFO("Failed to generate an ECDH key for group: %d\n", group_id);
        return -1;
    }

    okey                 = ecdh_table[group_id];
    ecdh_table[group_id] = tmp;

    EC_KEY_free(okey);
    return 0;
}

#endif /* HAVE_EC_CRYPTO */

/**
 * HIPv2: regenerate Diffie-Hellman keys.
 *
 * @param bitmask the mask of groups to generate
 */
static void regen_dh_keys_v2(uint32_t bitmask)
{
    int maxmask, i;
    int cnt = 0;

    /* if MAX_DH_GROUP_ID = 4 --> maxmask = 0...01111 */
    maxmask  = (1 << (HIP_MAX_DH_GROUP_ID + 1)) - 1;
    bitmask &= maxmask;

    for (i = 1; i < HIP_MAX_DH_GROUP_ID; i++) {
        if (bitmask & (1 << i)) {
#ifdef HAVE_EC_CRYPTO
            if (hip_is_ecdh_group(i)) {
                regen_ecdh_key(i);
            } else {
                regen_dh_key(i);
            }
#else
            regen_dh_key(i);
#endif /* HAVE_EC_CRYPTO */

            cnt++;
            HIP_DEBUG("DH key for group %d generated\n", i);
        }
    }
    HIP_DEBUG("%d keys generated\n", cnt);
}

/**
 * uninitialize precreated DH structures
 */
void hip_dh_uninit(void)
{
    int i;
    for (i = 1; i < HIP_MAX_DH_GROUP_ID; i++) {
        DH_free(dh_table[i]);
        dh_table[i] = NULL;
    }

#ifdef HAVE_EC_CRYPTO
    for (i = 1; i < HIP_MAX_DH_GROUP_ID; i++) {
        EC_KEY_free(ecdh_table[i]);
        ecdh_table[i] = NULL;
    }
#endif /* HAVE_EC_CRYPTO */

    CRYPTO_cleanup_all_ex_data();
}

/**
 * initialize D-H cipher structures
 */
int hip_init_cipher(void)
{
    uint32_t supported_groups;

    supported_groups = (1 << HIP_DH_OAKLEY_1   |
                        1 << HIP_DH_OAKLEY_5   |
                        1 << HIP_DH_384        |
                        1 << HIP_DH_NIST_P_256 |
                        1 << HIP_DH_NIST_P_384 |
                        1 << HIP_DH_NIST_P_521);

    HIP_DEBUG("Generating DH keys\n");
    regen_dh_keys_v2(supported_groups);

    return 1;
}
