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
 * This implements reading of the configuration files for the
 * ESP protection extension. It furthermore provides sanity
 * checks on the passed values.
 *
 * @brief Reads the config file for the ESP protection extension
 */

#define _BSD_SOURCE

#include <stdlib.h>

#include "libcore/debug.h"
#include "esp_prot_api.h"
#include "esp_prot_conntrack.h"
#include "esp_prot_config.h"
#include "config.h"

#define ESP_PROT_CONFIG_FILE "esp_prot.conf"

#ifdef HAVE_LIBCONFIG
static const char *config_file = HIPL_SYSCONFDIR "/" ESP_PROT_CONFIG_FILE;

static const char *path_hash_length           = "token_config.hash_length";
static const char *path_hash_structure_length = "token_config.hash_structure_length";
static const char *path_token_transform       = "token_config.token_transform";

static const char *path_num_parallel_hchains = "token_config.token_modes.num_parallel_hchains";
static const char *path_ring_buffer_size     = "token_config.token_modes.ring_buffer_size";
static const char *path_num_linear_elements  = "token_config.token_modes.num_linear_elements";
static const char *path_num_random_elements  = "token_config.token_modes.num_random_elements";

static const char *path_num_hchains_per_item = "sender.hcstore.num_hchains_per_item";
static const char *path_num_hierarchies      = "sender.hcstore.num_hierarchies";
static const char *path_refill_threshold     = "sender.hcstore.refill_threshold";
static const char *path_update_threshold     = "sender.update_threshold";

static const char *path_window_size = "verifier.window_size";

/**
 * Return an int value of the currently opened config file
 * @param cfg configuration setting to look up
 * @param name name of setting
 * @param result here the result will be stored. if the setting can't be read,
 *               it won't be altered. So you can use a default value als initial setting.
 * @return true on success and false on failure
 *
 * @note: This function is necessary for wrapping the libconfig call.
 *        It is needed because of an API change between libconfig 1.3 and 1.4
 */
static int wrap_config_lookup_int(const config_t *cfg,
                                  const char *name, int *result)
{
/* TODO: libconfig API change in 1.4: config_lookup_int has int* as the third
 * parameter, previous version had long*. If we decide to only support
 * libconfig 1.4, remove the ugly workaround below accordingly. See #134. */
#if defined LIBCONFIG_VER_MAJOR && defined LIBCONFIG_VER_MINOR && (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR >= 4)) || (LIBCONFIG_VER_MAJOR > 1))
    /* libconfig version 1.4 and later */
    int value = 0;
#else
    /* libconfig version before 1.4 */
    long value = 0;
#endif

    int success = config_lookup_int(cfg, name, &value);

    if (success == CONFIG_TRUE) {
        *result = value;
    }
    return success;
}

#endif /* HAVE_LIBCONFIG */

/**
 * parses the config-file and stores the parameters in memory
 *
 * @return  configuration parameters
 */
config_t *esp_prot_read_config(void)
{
    config_t *cfg = NULL;

/* WORKAROUND in order to not introduce a new dependency for HIPL
 *
 * FIXME this should be removed once we go tiny */
#ifdef HAVE_LIBCONFIG

    if (!(cfg = malloc(sizeof(config_t)))) {
        HIP_ERROR("Unable to allocate memory!\n");
        return NULL;
    }

    // init context and read file
    config_init(cfg);
    HIP_DEBUG("reading config file: %s\n", config_file);
    if (!config_read_file(cfg, config_file)) {
        HIP_ERROR("unable to read config file " ESP_PROT_CONFIG_FILE ".\n"
                                                                     "Please ensure that it is located in " HIPL_SYSCONFDIR ".\n");
        esp_prot_release_config(cfg);
        return NULL;
    }
#endif

    return cfg;
}

/**
 * releases the configuration file and frees the configuration memory
 *
 * @param cfg   parsed configuration parameters
 * @return      always 0
 */
int esp_prot_release_config(config_t *cfg)
{
    if (cfg) {
#ifdef HAVE_LIBCONFIG
        config_destroy(cfg);
        free(cfg);
#endif
    }

    return 0;
}

/**
 * sets the token-specific parameters such as protection mode and element length
 *
 * @param cfg   parsed configuration parameters
 * @return      0 on success, -1 otherwise
 */
int esp_prot_token_config(const config_t *cfg)
{
    if (cfg) {
#ifdef HAVE_LIBCONFIG
        // process parallel hchains-related settings
        if (!wrap_config_lookup_int(cfg, path_token_transform,
                                    &token_transform)) {
            token_transform = ESP_PROT_TFM_UNUSED;
        }

        // process hash tree-based setting
        if (!wrap_config_lookup_int(cfg, path_hash_length, &hash_length_g)) {
            hash_length_g = 20;
        }

        // process hash tree-based setting
        if (!wrap_config_lookup_int(cfg, path_hash_structure_length,
                                    &hash_structure_length)) {
            hash_structure_length = 16;
        }


        switch (token_transform) {
        case ESP_PROT_TFM_PLAIN:
            num_parallel_hchains = 1;
            ring_buffer_size     = 0;
            num_linear_elements  = 0;
            num_random_elements  = 0;
            break;
        case ESP_PROT_TFM_PARALLEL:
            if (!wrap_config_lookup_int(cfg, path_num_parallel_hchains,
                                        &num_parallel_hchains)) {
                num_parallel_hchains = 2;
            }

            ring_buffer_size    = 0;
            num_linear_elements = 0;
            num_random_elements = 0;

            break;
        case ESP_PROT_TFM_CUMULATIVE:
            num_parallel_hchains = 1;

            if (!wrap_config_lookup_int(cfg, path_ring_buffer_size,
                                        &ring_buffer_size)) {
                ring_buffer_size = 64;
            }

            if (!wrap_config_lookup_int(cfg, path_num_linear_elements,
                                        &num_linear_elements)) {
                num_linear_elements = 1;
            }

            if (!wrap_config_lookup_int(cfg, path_num_random_elements,
                                        &num_random_elements)) {
                num_random_elements = 0;
            }

            break;
        case ESP_PROT_TFM_PARA_CUMUL:
            if (!wrap_config_lookup_int(cfg, path_num_parallel_hchains,
                                        &num_parallel_hchains)) {
                num_parallel_hchains = 1;
            }
            if (!wrap_config_lookup_int(cfg, path_ring_buffer_size,
                                        &ring_buffer_size)) {
                ring_buffer_size = 64;
            }

            if (!wrap_config_lookup_int(cfg, path_num_linear_elements,
                                        &num_linear_elements)) {
                num_linear_elements = 1;
            }

            if (!wrap_config_lookup_int(cfg, path_num_random_elements,
                                        &num_random_elements)) {
                num_random_elements = 0;
            }

            break;
        case ESP_PROT_TFM_TREE:
            num_parallel_hchains = 1;
            ring_buffer_size     = 0;
            num_linear_elements  = 0;
            num_random_elements  = 0;
            break;
        default:
            HIP_ERROR("unknown token transform!\n");
            return -1;
        }
#else
        HIP_ERROR("found config file, but libconfig not linked\n");
        return -1;
#endif /* HAVE_LIBCONFIG */
    } else {
        HIP_ERROR("no configuration file available\n");

        HIP_INFO("using default configuration\n");
        /* use defaults for plain TFM from above in case of no lib/file */
        token_transform       = ESP_PROT_TFM_PLAIN;
        hash_length_g         = 20;
        hash_structure_length = 16;
        num_parallel_hchains  = 1;
        ring_buffer_size      = 0;
        num_linear_elements   = 0;
        num_random_elements   = 0;
    }

    // do some sanity checks here
    if (hash_length_g <= 0) {
        HIP_ERROR("hash length has insufficient length\n");
        return -1;
    }
    if (hash_structure_length <= 0) {
        HIP_ERROR("hash structure length has insufficient length\n");
        return -1;
    }

    HIP_DEBUG("token_transform: %i\n", token_transform);
    HIP_DEBUG("hash_length: %i\n", hash_length_g);
    HIP_DEBUG("hash_structure_length: %i\n", hash_structure_length);
    HIP_DEBUG("num_parallel_hchains: %i\n", num_parallel_hchains);
    HIP_DEBUG("ring_buffer_size: %i\n", ring_buffer_size);
    HIP_DEBUG("num_linear_elements: %i\n", num_linear_elements);
    HIP_DEBUG("num_random_elements: %i\n", num_random_elements);

    return 0;
}

/**
 * sets the sender-specific configuration parameters
 *
 * @param cfg   parsed configuration parameters
 * @return      0 on success, -1 otherwise
 */
int esp_prot_sender_config(const config_t *cfg)
{
    if (cfg) {
#ifdef HAVE_LIBCONFIG
        // process hcstore-related settings
        if (!wrap_config_lookup_int(cfg, path_num_hchains_per_item,
                                    &num_hchains_per_item)) {
            num_hchains_per_item = 8;
        }

        if (!wrap_config_lookup_int(cfg, path_num_hierarchies,
                                    &num_hierarchies)) {
            num_hierarchies = 1;
        }

        if (!config_lookup_float(cfg, path_refill_threshold,
                                 &refill_threshold)) {
            refill_threshold = 0.5;
        }

        // process update-related settings
        if (!config_lookup_float(cfg, path_update_threshold,
                                 &update_threshold)) {
            update_threshold = 0.5;
        }
#else
        HIP_ERROR("found config file, but libconfig not linked\n");
        return -1;
#endif /* HAVE_LIBCONFIG */
    } else {
        HIP_ERROR("no configuration file available\n");

        HIP_INFO("using default configuration\n");
        /* use defaults for plain TFM from above in case of no lib/file */
        num_hchains_per_item = 8;
        num_hierarchies      = 1;
        refill_threshold     = 0.5;
        update_threshold     = 0.5;
    }

    // do some sanity checks here
    if (num_hchains_per_item <= 0) {
        HIP_ERROR("num hchains per item has insufficient length\n");
        return -1;
    }
    if (num_hierarchies <= 0) {
        HIP_ERROR("num_hierarchies has insufficient length\n");
        return -1;
    }
    if (refill_threshold < 0.0 || refill_threshold > 1.0) {
        HIP_ERROR("refill_threshold not within boundaries\n");
        return -1;
    }
    if (update_threshold < 0.0 || update_threshold > 1.0) {
        HIP_ERROR("update_threshold not within boundaries\n");
        return -1;
    }

    HIP_DEBUG("num_hchains_per_item: %i\n", num_hchains_per_item);
    HIP_DEBUG("num_hierarchies: %i\n", num_hierarchies);
    HIP_DEBUG("refill_threshold: %f\n", refill_threshold);
    HIP_DEBUG("update_threshold: %f\n", update_threshold);

    return 0;
}

/**
 * sets the verifier-specific configuration parameters
 *
 * @param cfg   parsed configuration parameters
 * @return      0 on success, -1 otherwise
 */
int esp_prot_verifier_config(const config_t *cfg)
{
    if (cfg) {
#ifdef HAVE_LIBCONFIG
        // process verification-related setting
        if (!wrap_config_lookup_int(cfg, path_window_size, &window_size)) {
            window_size = 64;
        }
#else
        HIP_ERROR("found config file, but libconfig not linked\n");
        return -1;
#endif /* HAVE_LIBCONFIG */
    } else {
        HIP_ERROR("no configuration file available\n");

        HIP_INFO("using default configuration\n");
        /* use defaults for plain TFM from above in case of no lib/file */
        window_size = 64;
    }

    // do some sanity checks here
    if (window_size <= 0) {
        HIP_ERROR("window size has insufficient length\n");
        return -1;
    }
    HIP_DEBUG("window_size: %i\n", window_size);

    return 0;
}
