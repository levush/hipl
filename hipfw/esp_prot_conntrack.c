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

/**
 * @file
 * This implements the connection tracking for the ESP
 * protection extension.
 *
 * @brief Connection tracking extension needed for the ESP protection extension
 */

#define _BSD_SOURCE

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "libcore/builder.h"
#include "libcore/debug.h"
#include "libcore/hashtree.h"
#include "libcore/ife.h"
#include "libcore/linkedlist.h"
#include "libcore/protodefs.h"
#include "common_types.h"
#include "conntrack.h"
#include "esp_prot_api.h"
#include "esp_prot_config.h"
#include "esp_prot_defines.h"
#include "hipfw.h"
#include "hipfw_defines.h"
#include "hslist.h"
#include "esp_prot_conntrack.h"


struct esp_prot_conntrack_tfm {
    hash_function hash_function;       /* pointer to the hash function */
    int           hash_length;   /* hash length for this transform */
    int           is_used;   /* needed as complete transform array is initialized */
};

/* cached anchor element updates */
struct esp_anchor_item {
    uint32_t       seq; /* current sequence of the IPsec SA */
    uint8_t        transform; /* negotiated TPA transform */
    uint32_t       hash_item_length; /* length of the update hash structure */
    unsigned char *active_anchors[MAX_NUM_PARALLEL_HCHAINS]; /* the active hash anchor element */
    unsigned char *next_anchors[MAX_NUM_PARALLEL_HCHAINS]; /* the update hash anchor element */
    uint8_t        root_length; /* length of the eventual root element (HHL) */
    unsigned char *roots[MAX_NUM_PARALLEL_HCHAINS]; /* the root element (HHL) */
};


/* defines the default tolerance when verifying hash-chain elements
 * NOTE set to the preferred anti-replay window size of ESP */
int window_size;

static struct esp_prot_conntrack_tfm esp_prot_conntrack_tfms[MAX_NUM_TRANSFORMS];


/**
 * Resolves a transform to the specified hash function and hash length
 *
 * @param transform     TPA transform
 * @return              resolved transform, NULL for UNUSED transform
 */
static struct esp_prot_conntrack_tfm *esp_prot_conntrack_resolve_transform(const uint8_t transform)
{
    HIP_DEBUG("resolving transform: %u\n", transform);

    if (transform > ESP_PROT_TFM_UNUSED) {
        return &esp_prot_conntrack_tfms[transform];
    } else {
        return NULL;
    }
}

/**
 * Frees cached anchor elements
 *
 * @param cache_item  the cache item to be freed
 */
static void esp_prot_conntrack_free_cached_item(void *cache_item)
{
    struct esp_anchor_item *anchor_item = NULL;
    long                    i;

    if (cache_item) {
        anchor_item = cache_item;

        for (i = 0; i < num_parallel_hchains; i++) {
            free(anchor_item->active_anchors[i]);
            free(anchor_item->next_anchors[i]);
            free(anchor_item->roots[i]);
        }

        free(anchor_item);
    }
}

/**
 * Finds the matching esp state in the connection state
 *
 * @param   tuple state maintained for this connection
 * @param   active_anchor the active anchor element of the TPA tokens
 * @param   hash_length length of the anchor element
 * @return  esp state of the connection
 */
static struct esp_tuple *esp_prot_conntrack_find_esp_tuple(const struct tuple *tuple,
                                                           const unsigned char *active_anchor,
                                                           const int hash_length)
{
    struct esp_tuple *esp_tuple = NULL;
    struct slist     *list      = NULL;
    int               err       = 0;

    HIP_DEBUG("\n");

    HIP_ASSERT(tuple != NULL);

    HIP_HEXDUMP("received active anchor: ", active_anchor, hash_length);

    list = tuple->esp_tuples;

    while (list) {
        esp_tuple = list->data;

        // check if last installed anchor equals the one in the packet
        if (!memcmp(&esp_tuple->first_active_anchors[0][0], active_anchor,
                    hash_length)) {
            HIP_DEBUG("found matching active anchor in esp_tuples\n");

            HIP_HEXDUMP("stored active anchor: ",
                        &esp_tuple->first_active_anchors[0][0],
                        hash_length);

            goto out_err;
        }

        list = list->next;
    }

    HIP_DEBUG("no esp_tuple with matching anchor found\n");
    err = -1;

out_err:
    if (err) {
        esp_tuple = NULL;
    }

    return esp_tuple;
}

/**
 * Caches an anchor element found in a update messages
 *
 * @param   tuple state maintained for this connection
 * @param   seq the sequence number parameter of the HIP message
 * @param   esp_anchors the anchor element parameters of the HIP message
 * @param   esp_roots the root element parameters of the HIP message
 * @return  0 on success, -1 in case of an error
 */
static int esp_prot_conntrack_cache_anchor(const struct tuple *tuple,
                                           const struct hip_seq *seq,
                                           const struct esp_prot_anchor **esp_anchors,
                                           const struct esp_prot_root **esp_roots)
{
    struct esp_anchor_item        *anchor_item   = NULL;
    struct esp_tuple              *esp_tuple     = NULL;
    struct esp_prot_conntrack_tfm *conntrack_tfm = NULL;
    unsigned char                 *cmp_value     = NULL;
    int                            hash_length   = 0, err = 0;
    long                           i;

    HIP_DEBUG("\n");

    HIP_ASSERT(tuple != NULL);
    HIP_ASSERT(seq != NULL);
    HIP_ASSERT(esp_anchors[0] != NULL);

    HIP_DEBUG("caching update anchor(s)...\n");

    // needed for allocating and copying the anchors
    conntrack_tfm = esp_prot_conntrack_resolve_transform(esp_anchors[0]->transform);
    hash_length   = conntrack_tfm->hash_length;

    HIP_IFEL(!(esp_tuple = esp_prot_conntrack_find_esp_tuple(tuple,
                                                             &esp_anchors[0]->anchors[0],
                                                             hash_length)),
             -1, "failed to look up matching esp_tuple\n");

    HIP_IFEL(!(anchor_item = calloc(1, sizeof(struct esp_anchor_item))), -1,
             "failed to allocate memory\n");

    HIP_DEBUG("setting active_anchor\n");
    anchor_item->seq              = seq->update_id;
    anchor_item->transform        = esp_anchors[0]->transform;
    anchor_item->hash_item_length = esp_anchors[0]->hash_item_length;

    // malloc and set cmp_value to be 0
    HIP_IFEL(!(cmp_value = calloc(1, hash_length)), -1,
             "failed to allocate memory\n");

    // set all received anchor elements
    for (i = 0; i < esp_tuple->num_hchains; i++) {
        // active_anchors have to be present at least
        HIP_IFEL(!(anchor_item->active_anchors[i] = malloc(hash_length)), -1,
                 "failed to allocate memory\n");

        memcpy(anchor_item->active_anchors[i], &esp_anchors[i]->anchors[0],
               hash_length);

        // check if next_anchor is set
        if (memcmp(&esp_anchors[i]->anchors[hash_length], cmp_value,
                   hash_length)) {
            HIP_HEXDUMP("setting cache->next_anchors[i]: ",
                        &esp_anchors[i]->anchors[hash_length],
                        hash_length);

            // also copy this anchor as it is set
            HIP_IFEL(!(anchor_item->next_anchors[i] = malloc(hash_length)), -1,
                     "failed to allocate memory\n");

            memcpy(anchor_item->next_anchors[i],
                   &esp_anchors[i]->anchors[hash_length],
                   hash_length);
        } else {
            HIP_DEBUG("setting next_anchor to NULL\n");

            anchor_item->next_anchors[i] = NULL;
        }

        // also set the roots for the link_tree of the next hchain, if provided
        if (esp_roots[i]) {
            HIP_HEXDUMP("setting cache->roots[i]: ", esp_roots[i]->root,
                        esp_roots[i]->root_length);

            HIP_IFEL(!(anchor_item->roots[i] = malloc(esp_roots[i]->root_length)), -1,
                     "failed to allocate memory\n");

            anchor_item->root_length = esp_roots[i]->root_length;
            memcpy(anchor_item->roots[i], &esp_roots[i]->root[0],
                   esp_roots[i]->root_length);
        }
    }

    // add this anchor to the list for this direction's tuple
    HIP_DEBUG("adding anchor_item to cache for matching tuple\n");

    HIP_IFEL(hip_ll_add_first(&esp_tuple->anchor_cache, anchor_item), -1,
             "failed to add anchor_item to anchor_cache\n");

out_err:
    free(cmp_value);
    return err;
}

/**
 * Stores and enables update anchor element, if an acknowledgement for the
 * update is received
 *
 * @param   tuple state maintained for this connection
 * @param   ack the acknowledgement parameter of the HIP message
 * @param   esp_info the esp info parameter of the HIP message
 * @return  -1 on error, 1 if cached update not found, 0 if ok
 */
static int esp_prot_conntrack_update_anchor(const struct tuple *tuple,
                                            const struct hip_ack *ack,
                                            const struct hip_esp_info *esp_info)
{
    struct esp_anchor_item        *anchor_item     = NULL;
    struct tuple                  *other_dir_tuple = NULL;
    struct esp_tuple              *esp_tuple       = NULL;
    struct esp_prot_conntrack_tfm *conntrack_tfm   = NULL;
    int                            hash_length     = 0;
    // assume not found
    int      err           = 0;
    unsigned element_index = 0;
    int      found         = 0;
    long     i;

    HIP_DEBUG("\n");

    HIP_ASSERT(tuple != NULL);
    HIP_ASSERT(ack != NULL);
    HIP_ASSERT(esp_info != NULL);

    HIP_DEBUG("checking anchor cache for other direction...\n");

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir_tuple = &tuple->connection->reply;
    } else {
        other_dir_tuple = &tuple->connection->original;
    }

    // get corresponding esp_tuple by spi
    HIP_IFEL(!(esp_tuple = find_esp_tuple(other_dir_tuple->esp_tuples,
                                          ntohl(esp_info->old_spi))), -1,
             "failed to look up esp_tuple\n");
    HIP_DEBUG("found esp_tuple for received ESP_INFO\n");

    HIP_DEBUG("received ack: %u\n", ntohl(ack->peer_update_id));

    for (element_index = 0;
         element_index < hip_ll_get_size(&esp_tuple->anchor_cache);
         element_index++) {
        HIP_IFEL(!(anchor_item = hip_ll_get(&esp_tuple->anchor_cache,
                                            element_index)),
                 -1, "failed to look up anchor_item\n");

        HIP_DEBUG("cached seq: %u\n", ntohl(anchor_item->seq));

        if (anchor_item->seq == ack->peer_update_id) {
            HIP_DEBUG("found match in the cache\n");

            found = 1;
            break;
        }
    }

    if (found) {
        // needed for allocating and copying the anchors
        conntrack_tfm               = esp_prot_conntrack_resolve_transform(esp_tuple->esp_prot_tfm);
        hash_length                 = conntrack_tfm->hash_length;
        esp_tuple->hash_item_length = anchor_item->hash_item_length;

        for (i = 0; i < esp_tuple->num_hchains; i++) {
            HIP_HEXDUMP("esp_tuple->active_anchors[i]: ",
                        &esp_tuple->first_active_anchors[i][0], hash_length);
            HIP_HEXDUMP("anchor_item->active_anchors[i]: ",
                        anchor_item->active_anchors[i],
                        hash_length);

            // check that active anchors match
            if (!memcmp(&esp_tuple->first_active_anchors[i][0],
                        anchor_item->active_anchors[i],
                        hash_length)) {
                // update the esp_tuple
                memcpy(&esp_tuple->next_anchors[i][0],
                       anchor_item->next_anchors[i],
                       hash_length);
                HIP_HEXDUMP("anchor_item->next_anchor: ",
                            anchor_item->next_anchors[i],
                            hash_length);

                if (anchor_item->roots[i]) {
                    esp_tuple->next_root_length[i] = anchor_item->root_length;
                    esp_tuple->next_roots[i]       = anchor_item->roots[i];
                    HIP_HEXDUMP("anchor_item->roots[i]: ",
                                anchor_item->roots[i],
                                anchor_item->root_length);
                }

                // free anchors and but NOT root as in use now
                free(anchor_item->active_anchors[i]);
                free(anchor_item->next_anchors[i]);
            }
        }

        // delete cached item from the list
        HIP_IFEL(!(anchor_item = hip_ll_del(&esp_tuple->anchor_cache,
                                            element_index, NULL)), -1,
                 "failed to remove anchor_item from list\n");
        free(anchor_item);

        HIP_DEBUG("next_anchor of esp_tuple updated\n");
    } else {
        HIP_DEBUG("no matching ANCHOR UPDATE cached\n");
        err = -1;
    }

out_err:
    return err;
}

/**
 * Verifies the anchor element of a HHL-based update
 *
 * @param   tuple state maintained for this connection
 * @param   esp_anchors the anchor element parameters of the HIP message
 * @param   esp_branches the verification branch parameters
 * @param   esp_secrets the secret parameters
 * @return  0 on success, -1 on error
 */
static int esp_prot_conntrack_verify_branch(const struct tuple *tuple,
                                            const struct esp_prot_anchor *esp_anchors[MAX_NUM_PARALLEL_HCHAINS],
                                            const struct esp_prot_branch *esp_branches[MAX_NUM_PARALLEL_HCHAINS],
                                            const struct esp_prot_secret *esp_secrets[MAX_NUM_PARALLEL_HCHAINS])
{
    struct esp_prot_conntrack_tfm *conntrack_tfm = NULL;
    struct esp_tuple              *esp_tuple     = NULL;
    int                            hash_length   = 0;
    int                            err           = 0;
    int                            i             = 0;
    uint32_t                       branch_length = 0;
    uint32_t                       anchor_offset = 0;

    HIP_DEBUG("\n");

    HIP_ASSERT(tuple != NULL);
    HIP_ASSERT(esp_anchors[0] != NULL);
    HIP_ASSERT(esp_branches[0] != NULL);
    HIP_ASSERT(esp_secrets[0] != NULL);

    // needed for allocating and copying the anchors
    conntrack_tfm = esp_prot_conntrack_resolve_transform(esp_anchors[0]->transform);
    hash_length   = conntrack_tfm->hash_length;

    HIP_IFEL(!(esp_tuple = esp_prot_conntrack_find_esp_tuple(tuple,
                                                             &esp_anchors[0]->anchors[0],
                                                             hash_length)),
             -1, "failed to look up matching esp_tuple\n");

    for (i = 0; i < esp_tuple->num_hchains; i++) {
        branch_length = ntohl(esp_branches[i]->branch_length);
        anchor_offset = ntohl(esp_branches[i]->anchor_offset);

        // verify the branch
        if (!htree_verify_branch(esp_tuple->active_roots[i],
                                 esp_tuple->active_root_length,
                                 esp_branches[i]->branch_nodes,
                                 branch_length,
                                 &esp_anchors[i]->anchors[hash_length],
                                 hash_length,
                                 anchor_offset,
                                 esp_secrets[i]->secret,
                                 esp_secrets[i]->secret_length,
                                 htree_leaf_generator,
                                 htree_node_generator,
                                 NULL)) {
            HIP_DEBUG("anchor verified\n");
        } else {
            HIP_DEBUG("failed to verify branch!\n");

            err = -1;
        }
    }

out_err:
    return err;
}

/**
 * Initializes the connection tracking as required for the handling of TPA and HHL
 *
 * @return always 0
 */
int esp_prot_conntrack_init(void)
{
    config_t *config = NULL;
    int       err    = 0, i, j;

    HIP_DEBUG("Initializing conntracking of esp protection extension...\n");

    // read settings from config-file
    config = esp_prot_read_config();
    HIP_IFEL(esp_prot_token_config(config), -1,
             "failed to process config-file\n");
    HIP_IFEL(esp_prot_verifier_config(config), -1,
             "failed to process config-file\n");
    HIP_IFEL(esp_prot_release_config(config), -1,
             "failed to release config-file\n");

    /* setting config-files values for internal usage
     * NOTE internal structure partially more flexible than interface provided by
     *      config-file */
    hash_lengths[NUM_HASH_FUNCTIONS - 1][NUM_HASH_LENGTHS - 1] = hash_length_g;

    // set available transforms to used
    esp_prot_conntrack_tfms[token_transform].is_used = 1;

    /* set up mapping of esp protection transforms to hash functions and lengths */
    for (i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        for (j = 0; j < NUM_HASH_LENGTHS; j++) {
            if (hash_lengths[i][j] > 0) {
                // store these IDs in the transforms array
                HIP_DEBUG("adding transform: %i\n", token_transform);

                if (esp_prot_conntrack_tfms[token_transform].is_used) {
                    esp_prot_conntrack_tfms[token_transform].hash_function =
                        hash_functions[i];
                    esp_prot_conntrack_tfms[token_transform].hash_length =
                        hash_lengths[i][j];
                }
            }
        }
    }

out_err:
    return err;
}

/**
 * Un-initializes the TPA-specific parts of the connection tracking
 *
 * @return always 0
 */
int esp_prot_conntrack_uninit(void)
{
    int err = 0;

    // uninit all possible transforms
    memset(esp_prot_conntrack_tfms, 0,
           MAX_NUM_TRANSFORMS * sizeof(struct esp_prot_conntrack_tfm));

    return err;
}

/**
 * Processes the transform list enclosed in the R1
 *
 * @param   common the HIP message
 * @param   tuple connection state of the connection tracking mechanism
 * @return  always 0
 */
int esp_prot_conntrack_R1_tfms(const struct hip_common *common,
                               const struct tuple *tuple)
{
    const struct esp_prot_preferred_tfms *prot_transforms = NULL;
    int                                   err             = 0, i;

    if (hip_esp_protection) {
        // initialize the ESP protection params in the connection
        tuple->connection->num_esp_prot_tfms = 0;
        memset(tuple->connection->esp_prot_tfms, 0, NUM_TRANSFORMS + 1);

        // check if message contains optional ESP protection transforms
        if ((prot_transforms = hip_get_param(common,
                                             HIP_PARAM_ESP_PROT_TRANSFORMS))) {
            HIP_DEBUG("ESP protection extension transforms found\n");

            // make sure we only process as many transforms as we can handle
            if (prot_transforms->num_transforms > NUM_TRANSFORMS + 1) {
                HIP_DEBUG("received more transforms than we can handle, "
                          "processing max\n");

                // transforms + UNUSED
                tuple->connection->num_esp_prot_tfms = NUM_TRANSFORMS + 1;
            } else {
                tuple->connection->num_esp_prot_tfms = prot_transforms->num_transforms;
            }

            HIP_DEBUG("adding %i transforms...\n", tuple->connection->num_esp_prot_tfms);

            // store the transforms
            for (i = 0; i < tuple->connection->num_esp_prot_tfms; i++) {
                // only store transforms we support
                if (esp_prot_conntrack_tfms[prot_transforms->transforms[i]].is_used) {
                    tuple->connection->esp_prot_tfms[i] = prot_transforms->transforms[i];

                    HIP_DEBUG("added transform %i: %u\n", i + 1,
                              tuple->connection->esp_prot_tfms[i]);
                } else {
                    tuple->connection->esp_prot_tfms[i] = ESP_PROT_TFM_UNUSED;

                    HIP_DEBUG("unknown transform, set to UNUSED\n");
                }
            }
        }
    }

    return err;
}

/**
 * Processes the anchor element of the I2
 *
 * @param   common the HIP message
 * @param   tuple connection state of the connection tracking mechanism
 * @return  0 on success, 1 if non-matching anchor element properties, -1 in case
 *          of an error
 */
int esp_prot_conntrack_I2_anchor(const struct hip_common *common,
                                 struct tuple *tuple)
{
    const struct hip_tlv_common   *param         = NULL;
    const struct esp_prot_anchor  *prot_anchor   = NULL;
    struct esp_tuple              *esp_tuple     = NULL;
    struct esp_prot_conntrack_tfm *conntrack_tfm = NULL;
    long                           i             = 0;
    int                            hash_length   = 0;
    int                            err           = 0;

    if (hip_esp_protection) {
        HIP_ASSERT(common != NULL);
        HIP_ASSERT(tuple != NULL);

        // check if message contains optional ESP protection anchors
        if ((param = hip_get_param(common, HIP_PARAM_ESP_PROT_ANCHOR))) {
            prot_anchor = (const struct esp_prot_anchor *) param;

            /* create esp_tuple for direction of this message only storing
             * the sent anchor, no SPI known yet -> will be sent in R2
             *
             * @note this needs to be done as SPIs are signaled in one direction
             *       but used in the other while anchors are signaled and used
             *       in the same direction
             */

            /* check esp_tuple count for this direction, should be 0 */
            HIP_IFEL(tuple->esp_tuples, -1,
                     "expecting empty esp_tuple list, but it is NOT\n");

            HIP_IFEL(!(esp_tuple = calloc(1, sizeof(struct esp_tuple))), 0,
                     "failed to allocate memory\n");

            // check if the anchor has a supported transform
            if (esp_prot_check_transform(tuple->connection->num_esp_prot_tfms,
                                         tuple->connection->esp_prot_tfms,
                                         prot_anchor->transform) >= 0) {
                // it's one of the supported and advertised transforms
                esp_tuple->esp_prot_tfm = prot_anchor->transform;
                HIP_DEBUG("using esp prot transform: %u\n", esp_tuple->esp_prot_tfm);

                if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED) {
                    conntrack_tfm               = esp_prot_conntrack_resolve_transform(esp_tuple->esp_prot_tfm);
                    hash_length                 = conntrack_tfm->hash_length;
                    esp_tuple->hash_item_length = ntohl(prot_anchor->hash_item_length);

                    if (esp_tuple->esp_prot_tfm == ESP_PROT_TFM_TREE) {
                        esp_tuple->hash_tree_depth = ceil(log_x(2, esp_tuple->hash_item_length));
                        HIP_DEBUG("esp_tuple->hash_tree_depth: %i\n", esp_tuple->hash_tree_depth);

                        // compute full leaf set size
                        esp_tuple->hash_item_length = pow(2, ceil(esp_tuple->hash_tree_depth));
                        HIP_DEBUG("esp_tuple->hash_item_length: %i\n", esp_tuple->hash_item_length);
                    }

                    // store all contained anchors
                    for (i = 0; i < num_parallel_hchains; i++) {
                        if (!prot_anchor || prot_anchor->transform != esp_tuple->esp_prot_tfm) {
                            // we expect an anchor and all anchors should have the same transform
                            err = -1;
                            goto out_err;
                        } else {
                            // store peer_anchor
                            memcpy(&esp_tuple->active_anchors[i][0], &prot_anchor->anchors[0],
                                   hash_length);
                            HIP_HEXDUMP("received anchor: ", &esp_tuple->active_anchors[i][0],
                                        hash_length);

                            // ...and make a backup of it for later verification of UPDATEs
                            memcpy(&esp_tuple->first_active_anchors[i][0], &prot_anchor->anchors[0],
                                   hash_length);
                        }

                        // get next anchor
                        param       = hip_get_next_param(common, param);
                        prot_anchor = (const struct esp_prot_anchor *) param;
                    }

                    // store number of parallel hchains
                    esp_tuple->num_hchains = num_parallel_hchains;

                    // add the tuple to this direction's esp_tuple list
                    HIP_IFEL(!(tuple->esp_tuples = append_to_slist(tuple->esp_tuples,
                                                                   esp_tuple)), -1, "failed to insert esp_tuple\n");
                } else {
                    HIP_DEBUG("received anchor with non-matching transform, DROPPING\n");

                    err = 1;
                    goto out_err;
                }
            } else {
                HIP_ERROR("received anchor with unknown transform, DROPPING\n");

                err = 1;
                goto out_err;
            }

            // finally init the anchor cache needed for tracking UPDATEs
            hip_ll_init(&esp_tuple->anchor_cache);
        }
    }

out_err:
    if (err) {
        free(esp_tuple);
        esp_tuple = NULL;
    }

    return err;
}

/**
 * Gets the corresponding state for the R2
 *
 * @param   other_dir_esps maintained connection tracking state for this connection
 * @return  corresponding state
 */
struct esp_tuple *esp_prot_conntrack_R2_esp_tuple(const struct slist *other_dir_esps)
{
    struct esp_tuple *esp_tuple = NULL;
    int               err       = 0;

    if (hip_esp_protection) {
        /* normally there should NOT be any esp_tuple for the other direction yet,
         * but when tracking anchor elements, the other one was already set up
         * when handling the I2 */
        if (other_dir_esps) {
            /* there should only be one esp_tuple in the other direction's esp_tuple
             * list */
            HIP_IFEL(other_dir_esps->next, -1,
                     "expecting 1 esp_tuple in the list, but there are several\n");

            // get the esp_tuple for the other direction
            HIP_IFEL(!(esp_tuple = other_dir_esps->data), -1,
                     "expecting 1 esp_tuple in the list, but there is NONE\n");
        }
    }

out_err:
    if (err) {
        esp_tuple = NULL;
    }

    return esp_tuple;
}

/**
 * Processes the anchor element of the R2
 *
 * @param   common the HIP message
 * @param   tuple connection state of the connection tracking mechanism
 * @return  0 on success, 1 if non-matching anchor element properties, -1 in case
 *          of an error
 */
int esp_prot_conntrack_R2_anchor(const struct hip_common *common,
                                 const struct tuple *tuple)
{
    const struct hip_tlv_common   *param         = NULL;
    const struct esp_prot_anchor  *prot_anchor   = NULL;
    struct esp_tuple              *esp_tuple     = NULL;
    struct esp_prot_conntrack_tfm *conntrack_tfm = NULL;
    long                           i             = 0;
    int                            hash_length   = 0;
    int                            err           = 0;

    if (hip_esp_protection) {
        HIP_ASSERT(common != NULL);
        HIP_ASSERT(tuple != NULL);

        // check if message contains optional ESP protection anchor
        if ((param = hip_get_param(common, HIP_PARAM_ESP_PROT_ANCHOR))) {
            prot_anchor = (const struct esp_prot_anchor *) param;

            // check if the anchor has a supported transform
            if (esp_prot_check_transform(tuple->connection->num_esp_prot_tfms,
                                         tuple->connection->esp_prot_tfms,
                                         prot_anchor->transform) >= 0) {
                // for BEX there should be only one ESP tuple for this direction
                HIP_IFEL(tuple->esp_tuples->next, -1,
                         "expecting 1 esp_tuple in the list, but there are several\n");

                HIP_IFEL(!(esp_tuple = (struct esp_tuple *) tuple->esp_tuples->data), -1,
                         "expecting 1 esp_tuple in the list, but there is NONE\n");

                esp_tuple->esp_prot_tfm = prot_anchor->transform;
                HIP_DEBUG("using esp prot transform: %u\n", esp_tuple->esp_prot_tfm);

                if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED) {
                    conntrack_tfm = esp_prot_conntrack_resolve_transform(esp_tuple->esp_prot_tfm);
                    hash_length   = conntrack_tfm->hash_length;

                    esp_tuple->hash_item_length = ntohl(prot_anchor->hash_item_length);

                    if (esp_tuple->esp_prot_tfm == ESP_PROT_TFM_TREE) {
                        esp_tuple->hash_tree_depth = ceil(log_x(2, esp_tuple->hash_item_length));
                        HIP_DEBUG("esp_tuple->hash_tree_depth: %i\n", esp_tuple->hash_tree_depth);

                        // compute full leaf set size
                        esp_tuple->hash_item_length = pow(2, esp_tuple->hash_tree_depth);
                        HIP_DEBUG("esp_tuple->hash_item_length: %i\n", esp_tuple->hash_item_length);
                    }

                    // store all contained anchors
                    for (i = 0; i < num_parallel_hchains; i++) {
                        if (!prot_anchor || prot_anchor->transform != esp_tuple->esp_prot_tfm) {
                            // we expect an anchor and all anchors should have the same transform
                            err = -1;
                            goto out_err;
                        } else {
                            // store peer_anchor
                            memcpy(&esp_tuple->active_anchors[i][0], &prot_anchor->anchors[0],
                                   hash_length);
                            HIP_HEXDUMP("received anchor: ", &esp_tuple->active_anchors[i][0],
                                        hash_length);

                            // ...and make a backup of it for later verification of UPDATEs
                            memcpy(&esp_tuple->first_active_anchors[i][0], &prot_anchor->anchors[0],
                                   hash_length);
                        }

                        // get next anchor
                        param       = hip_get_next_param(common, param);
                        prot_anchor = (const struct esp_prot_anchor *) param;
                    }

                    // store number of parallel hchains
                    esp_tuple->num_hchains = num_parallel_hchains;
                } else {
                    HIP_DEBUG("received anchor with non-matching transform, DROPPING\n");

                    err = 1;
                    goto out_err;
                }
            } else {
                HIP_ERROR("received anchor with unknown transform, DROPPING\n");

                err = 1;
                goto out_err;
            }

            // finally init the anchor cache needed for tracking UPDATEs
            hip_ll_init(&esp_tuple->anchor_cache);
        }
    }

out_err:
    return err;
}

/**
 * Processes an update message
 *
 * @param   update the HIP message
 * @param   tuple connection state of the connection tracking mechanism
 * @return  0 on success, -1 in case of an error or unsupported update
 */
int esp_prot_conntrack_update(const struct hip_common *update,
                              const struct tuple *tuple)
{
    const struct hip_tlv_common  *param    = NULL;
    const struct hip_seq         *seq      = NULL;
    const struct hip_ack         *ack      = NULL;
    const struct hip_esp_info    *esp_info = NULL;
    const struct esp_prot_anchor *esp_anchors[MAX_NUM_PARALLEL_HCHAINS];
    const struct esp_prot_root   *esp_roots[MAX_NUM_PARALLEL_HCHAINS];
    int                           err = 0;
    long                          i   = 0;

    if (hip_esp_protection) {
        HIP_ASSERT(update != NULL);
        HIP_ASSERT(tuple != NULL);

        seq      = hip_get_param(update, HIP_PARAM_SEQ);
        esp_info = hip_get_param(update, HIP_PARAM_ESP_INFO);
        ack      = hip_get_param(update, HIP_PARAM_ACK);
        // there might be several anchor elements
        param = hip_get_param(update, HIP_PARAM_ESP_PROT_ANCHOR);

        // distinguish packet types and process accordingly
        if (seq && !ack && !esp_info && param) {
            HIP_DEBUG("received 1. UPDATE packet of ANCHOR UPDATE\n");

            // get all anchors
            for (i = 0; i < num_parallel_hchains; i++) {
                esp_anchors[i] = (const struct esp_prot_anchor *) param;

                param = hip_get_next_param(update, param);
            }

            param = hip_get_param(update, HIP_PARAM_ESP_PROT_ROOT);
            if (param) {
                // get all roots
                for (i = 0; i < num_parallel_hchains; i++) {
                    esp_roots[i] = (const struct esp_prot_root *) param;

                    param = hip_get_next_param(update, param);
                }
            }

            // cache ANCHOR
            HIP_IFEL(esp_prot_conntrack_cache_anchor(tuple, seq, esp_anchors, esp_roots), -1,
                     "failed to cache ANCHOR parameter\n");
        } else if (seq && ack && esp_info && param) {
            /* either 2. UPDATE packet of mutual ANCHOR UPDATE or LOCATION UPDATE */
            // TODO implement

            HIP_ERROR("not implemented yet\n");
            err = -1;
        } else if (!seq && ack && esp_info && !param) {
            HIP_DEBUG("either received 2. UPDATE packet of ANCHOR UPDATE or 3. of mutual one\n");

            // lookup cached ANCHOR and update corresponding esp_tuple
            HIP_IFEL(esp_prot_conntrack_update_anchor(tuple, ack, esp_info), -1,
                     "failed to update anchor\n");
        } else if (!seq && ack && esp_info && param) {
            /* 3. UPDATE packet of LOCATION UPDATE */
            // TODO implement

            HIP_ERROR("not implemented yet\n");
            err = -1;
        } else {
            HIP_DEBUG("unknown HIP-parameter combination, unhandled\n");
        }
    }

out_err:
    return err;
}

/**
 * Frees (cached) anchor elements of an ESP tuple
 *
 * @param esp_tuple     the tuple to be freed
 * @return              always 0
 */
int esp_prot_conntrack_remove_state(struct esp_tuple *esp_tuple)
{
    int err = 0, i;

    if (hip_esp_protection) {
        hip_ll_uninit(&esp_tuple->anchor_cache, esp_prot_conntrack_free_cached_item);

        for (i = 0; i < esp_tuple->num_hchains; i++) {
            free(esp_tuple->active_roots[i]);
            free(esp_tuple->next_roots[i]);
        }
    }

    return err;
}

/**
 * Tracks an HHL-based update message
 *
 * @param   common the HIP message
 * @param   tuple state maintained for this connection
 * @param   ctx packet context
 * @return  0 on success, -1 in case of an error
 */
int esp_prot_conntrack_lupdate(const struct hip_common *common,
                               struct tuple *tuple,
                               const struct hip_fw_context *ctx)
{
    const struct hip_seq         *seq   = NULL;
    const struct hip_tlv_common  *param = NULL;
    const struct esp_prot_anchor *esp_anchors[MAX_NUM_PARALLEL_HCHAINS];
    const struct esp_prot_branch *esp_branches[MAX_NUM_PARALLEL_HCHAINS];
    const struct esp_prot_secret *esp_secrets[MAX_NUM_PARALLEL_HCHAINS];
    const struct esp_prot_root   *esp_roots[MAX_NUM_PARALLEL_HCHAINS] = { 0 };
    const struct hip_ack         *ack                                 = NULL;
    const struct hip_esp_info    *esp_info                            = NULL;
    const struct in6_addr        *ip6_src                             = &ctx->src;
    const struct in6_addr        *ip6_dst                             = &ctx->dst;
    int                           err                                 = 0;
    long                          i;

    if (hip_esp_protection) {
        HIP_ASSERT(ip6_src != NULL);
        HIP_ASSERT(ip6_dst != NULL);
        HIP_ASSERT(common != NULL);
        HIP_ASSERT(tuple != NULL);

        HIP_DEBUG("handling light update...\n");

        // get params from UPDATE message
        seq = hip_get_param(common, HIP_PARAM_SEQ);
        ack = hip_get_param(common, HIP_PARAM_ACK);

        if (seq) {
            HIP_DEBUG("received ANCHOR packet of LIGHT UPDATE\n");

            param = hip_get_param(common, HIP_PARAM_ESP_PROT_ANCHOR);
            for (i = 0; i < num_parallel_hchains; i++) {
                esp_anchors[i] = (const struct esp_prot_anchor *) param;

                param = hip_get_next_param(common, param);
            }

            param = hip_get_param(common, HIP_PARAM_ESP_PROT_BRANCH);
            for (i = 0; i < num_parallel_hchains; i++) {
                esp_branches[i] = (const struct esp_prot_branch *) param;

                param = hip_get_next_param(common, param);
            }

            param = hip_get_param(common, HIP_PARAM_ESP_PROT_SECRET);
            for (i = 0; i < num_parallel_hchains; i++) {
                esp_secrets[i] = (const struct esp_prot_secret *) param;

                param = hip_get_next_param(common, param);
            }

            param = hip_get_param(common, HIP_PARAM_ESP_PROT_ROOT);
            if (param) {
                for (i = 0; i < num_parallel_hchains; i++) {
                    esp_roots[i] = (const struct esp_prot_root *) param;

                    param = hip_get_next_param(common, param);
                }
            }

            HIP_DEBUG("seq->update_id: %u\n", ntohl(seq->update_id));
            HIP_DEBUG("tuple->lupdate_seq: %u\n", tuple->lupdate_seq);

            // track SEQ
            if (ntohl(seq->update_id) < tuple->lupdate_seq) {
                HIP_DEBUG("old light update\n");

                err = -1;
                goto out_err;
            } else {
                HIP_DEBUG("new light update\n");

                tuple->lupdate_seq = ntohl(seq->update_id);
            }

            // verify tree
            HIP_IFEL(esp_prot_conntrack_verify_branch(tuple, esp_anchors, esp_branches,
                                                      esp_secrets), -1,
                     "failed to verify branch\n");

            // cache update_anchor and root
            HIP_IFEL(esp_prot_conntrack_cache_anchor(tuple, seq, esp_anchors, esp_roots), -1,
                     "failed to cache the anchor\n");
        } else if (ack) {
            HIP_DEBUG("received ACK packet of LIGHT UPDATE\n");

            esp_info = hip_get_param(common, HIP_PARAM_ESP_INFO);

            // lookup cached ANCHOR and update corresponding esp_tuple
            HIP_IFEL(esp_prot_conntrack_update_anchor(tuple, ack, esp_info), -1,
                     "failed to update anchor\n");
        } else {
            HIP_DEBUG("unknown HIP-parameter combination, unhandled\n");

            err = -1;
        }
    }

out_err:
    return err;
}

/**
 * Verifies the enclosed TPA tokens
 *
 * @param   ctx context of the currently processed packet
 * @param   esp_tuple corresponding esp state of the connection
 * @return  0 on success, -1 on error
 */
int esp_prot_conntrack_verify(const struct hip_fw_context *ctx,
                              struct esp_tuple *esp_tuple)
{
    struct esp_prot_conntrack_tfm *conntrack_tfm  = NULL;
    struct hip_esp                *esp            = NULL;
    struct esp_cumulative_item    *cached_element = NULL;
    struct esp_cumulative_item    *cumulative_ptr = NULL;
    unsigned char                  packet_hash[MAX_HASH_LENGTH];
    int                            esp_len    = 0, use_hash_trees = 0, active_hchain = 0, err = 0, i;
    uint32_t                       num_verify = 0, current_seq = 0;

    if (hip_esp_protection) {
        if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED) {
            conntrack_tfm = esp_prot_conntrack_resolve_transform(esp_tuple->esp_prot_tfm);

            esp     = ctx->transport_hdr.esp;
            esp_len = ctx->ipq_packet->data_len - ctx->ip_hdr_len;
            if (ctx->udp_encap_hdr) {
                esp_len -= sizeof(struct udphdr);
            }

            // received seq no
            current_seq = ntohl(esp->esp_seq);

            HIP_DEBUG("stored seq no: %u\n", esp_tuple->seq_no);
            HIP_DEBUG("received seq no: %u\n", current_seq);

            HIP_DEBUG("esp_tuple->num_hchains: %i\n", esp_tuple->num_hchains);

            /** NOTE: seq no counting starts with 1 for first packet, but first hchain with
             *        has index 0 */
            active_hchain = (current_seq - 1) % esp_tuple->num_hchains;
            HIP_DEBUG("active_hchain: %i\n", active_hchain);

            if (esp_tuple->esp_prot_tfm == ESP_PROT_TFM_TREE) {
                use_hash_trees = 1;

                /* check ESP protection anchor if extension is in use */
                HIP_IFEL((err = esp_prot_verify_htree_element(conntrack_tfm->hash_function,
                                                              conntrack_tfm->hash_length, esp_tuple->hash_tree_depth,
                                                              &esp_tuple->active_anchors[active_hchain][0],
                                                              &esp_tuple->next_anchors[active_hchain][0],
                                                              esp_tuple->active_roots[active_hchain],
                                                              esp_tuple->active_root_length,
                                                              esp_tuple->next_roots[active_hchain],
                                                              esp_tuple->next_root_length[active_hchain],
                                                              ((unsigned char *) esp) + sizeof(struct hip_esp))) < 0, -1,
                         "failed to verify ESP protection hash\n");
            } else {
                /* calculate difference of SEQ no in order to determine how many hashes
                 * we have to calculate */
                if (ntohl(esp->esp_seq) - esp_tuple->seq_no > 0 &&
                    ntohl(esp->esp_seq) - esp_tuple->seq_no <= (unsigned) window_size) {
                    HIP_DEBUG("seq number within verification window\n");

                    num_verify = ntohl(esp->esp_seq) - esp_tuple->seq_no;

                    /* check ESP protection anchor if extension is in use */
                    HIP_IFEL((err = esp_prot_verify_hchain_element(conntrack_tfm->hash_function,
                                                                   conntrack_tfm->hash_length,
                                                                   &esp_tuple->active_anchors[active_hchain][0],
                                                                   &esp_tuple->next_anchors[active_hchain][0],
                                                                   ((unsigned char *) esp) + sizeof(struct hip_esp),
                                                                   num_verify,
                                                                   esp_tuple->active_roots[active_hchain],
                                                                   esp_tuple->active_root_length,
                                                                   esp_tuple->next_roots[active_hchain],
                                                                   esp_tuple->next_root_length[active_hchain])) < 0, -1,
                             "failed to verify ESP protection hash\n");
                } else if ((esp_tuple->esp_prot_tfm == ESP_PROT_TFM_CUMULATIVE
                            || esp_tuple->esp_prot_tfm == ESP_PROT_TFM_PARA_CUMUL)
                           && esp_tuple->seq_no - ntohl(esp->esp_seq) > 0) {
                    /* check for authed packet in cumulative authentication mode when
                     * we received a previous packet (reordering) */

                    HIP_DEBUG("doing cumulative authentication for received packet...\n");

                    // get hash at corresponding offset in the ring-buffer
                    cached_element = &esp_tuple->hash_buffer[ntohl(esp->esp_seq) % ring_buffer_size];

                    if (cached_element->seq == ntohl(esp->esp_seq)) {
                        conntrack_tfm->hash_function((unsigned char *) esp, esp_len, packet_hash);

                        if (memcmp(cached_element->packet_hash, packet_hash, conntrack_tfm->hash_length)) {
                            HIP_DEBUG("unable to verify packet with cumulative authentication\n");

                            err = -1;
                            goto out_err;
                        } else {
                            HIP_DEBUG("packet verified with cumulative authentication\n");

                            // cache packet hashes of previous packets below
                        }
                    } else {
                        HIP_DEBUG("no authentication state for currently received packet\n");

                        err = -1;
                        goto out_err;
                    }
                } else {
                    /* the difference either is so big that the packet would not be verified
                     * or we received the current anchor element again */
                    HIP_DEBUG("seq no. difference == 0, higher than DEFAULT_VERIFY_WINDOW or further behind than IPsec replay window/no cumulative authentication\n");

                    err = -1;
                    goto out_err;
                }

                if (esp_tuple->esp_prot_tfm == ESP_PROT_TFM_CUMULATIVE || esp_tuple->esp_prot_tfm == ESP_PROT_TFM_PARA_CUMUL) {
                    // track hashes of cumulative authentication mode if packet was authed
                    cumulative_ptr = (struct esp_cumulative_item *) (((unsigned char *) esp) + sizeof(struct hip_esp) + conntrack_tfm->hash_length);

                    for (i = 0; i < num_linear_elements + num_random_elements; i++) {
                        HIP_DEBUG("cumulative_ptr[i].seq: %u\n", cumulative_ptr[i].seq);

                        // keep the buffer filled with fresh elements only
                        if (cumulative_ptr[i].seq > esp_tuple->hash_buffer[cumulative_ptr[i].seq % ring_buffer_size].seq) {
                            memcpy(&esp_tuple->hash_buffer[cumulative_ptr[i].seq % ring_buffer_size],
                                   &cumulative_ptr[i],
                                   sizeof(struct esp_cumulative_item));

                            HIP_DEBUG("cached cumulative token with SEQ: %u\n", cumulative_ptr[i].seq);
                            HIP_HEXDUMP("token: ", cumulative_ptr[i].packet_hash, conntrack_tfm->hash_length);
                        }
                    }
                }
            }

            // this means there was a change in the anchors
            if (err > 0) {
                HIP_DEBUG("anchor change occurred for hchain[%i], handled now\n", active_hchain);

                if (use_hash_trees) {
                    // here we store roots, so we must NOT store hash token of current ESP packet
                    memcpy(&esp_tuple->active_anchors[active_hchain][0], &esp_tuple->next_anchors[active_hchain][0],
                           conntrack_tfm->hash_length);
                    memcpy(&esp_tuple->first_active_anchors[active_hchain][0], &esp_tuple->next_anchors[active_hchain][0],
                           conntrack_tfm->hash_length);
                } else {
                    // don't copy the next anchor, but the already verified hash
                    memcpy(&esp_tuple->active_anchors[active_hchain][0], ((unsigned char *) esp) + sizeof(struct hip_esp),
                           conntrack_tfm->hash_length);
                    memcpy(&esp_tuple->first_active_anchors[active_hchain][0], &esp_tuple->next_anchors[active_hchain][0],
                           conntrack_tfm->hash_length);
                }

                // change roots
                /* the BEX-store does not have hierarchies, so no root is used for
                 * the first hchain */
                free(esp_tuple->active_roots[active_hchain]);
                esp_tuple->active_roots[active_hchain]     = esp_tuple->next_roots[active_hchain];
                esp_tuple->next_roots[active_hchain]       = NULL;
                esp_tuple->active_root_length              = esp_tuple->next_root_length[active_hchain];
                esp_tuple->next_root_length[active_hchain] = 0;

                HIP_DEBUG("esp_tuple->active_root_length: %i\n",
                          esp_tuple->active_root_length);
                HIP_HEXDUMP("esp_tuple->active_root: ", esp_tuple->active_roots[active_hchain],
                            esp_tuple->active_root_length);

                // no error case
                err = 0;
            }
        } else {
            HIP_DEBUG("esp protection extension UNUSED\n");

            // this explicitly is no error condition
            err = 0;
        }
    }

out_err:

    if (err != 0) {
        printf("verification error occurred\n");
    }

    return err;
}
