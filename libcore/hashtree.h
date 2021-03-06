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
 * API for Hash trees
 *
 * @brief API for Hash trees
 */

#ifndef HIPL_LIBCORE_HASHTREE_H
#define HIPL_LIBCORE_HASHTREE_H

#include <stdint.h>

/* arguments for the generator functionms */
struct htree_gen_args {
    int index;
};

/** leaf generator function pointer
 *
 * NOTE: if you need additional arguments here, add them to the gen_args struct
 */
typedef int (*htree_leaf_gen)(const unsigned char *data,
                              const int data_length,
                              const unsigned char *secret,
                              const int secret_length,
                              unsigned char *dst_buffer,
                              const struct htree_gen_args *gen_args);

/** node generator function pointer
 *
 * NOTE: if you need additional arguments here, add them to the gen_args struct
 */
typedef int (*htree_node_gen)(const unsigned char *left_node,
                              const unsigned char *right_node,
                              const int node_length,
                              unsigned char *dst_buffer,
                              const struct htree_gen_args *gen_args);

struct hash_tree {
    // data variables
    int            leaf_set_size;    /* maximum number of data blocks to be stored in the tree */
    int            num_data_blocks;    /* number of data blocks to be verified with the tree */
    int            max_data_length;    /* max length for a single leaf element */
    unsigned char *data;     /* array containing the data to be validated with the tree */
    int            secret_length;    /* length of the secret */
    unsigned char *secrets;     /* individual secrets to be revealed with each data block */

    struct hash_tree *link_tree;
    int               hierarchy_level;

    // tree elements variables
    int            node_length;    /* length of a single node element */
    unsigned char *nodes;     /* array containing the nodes of the tree */
    unsigned char *root;     /* the root of the tree -> points into nodes-array */

    // management variables
    int depth;               /* depth of the tree */
    int data_position;               /* index of the next free leaf */
    int is_open;               /* can one enter new entries?
                                *                 This is only true if the nodes have not been
                                *                 computed yet. */
};

double log_x(const int base, const double value);
struct hash_tree *htree_init(const int num_data_blocks,
                             const int max_data_length,
                             const int node_length,
                             const int secret_length,
                             struct hash_tree *link_tree,
                             const int hierarchy_level);
void htree_free(struct hash_tree *tree);
int htree_add_data(struct hash_tree *tree,
                   const unsigned char *data,
                   const int data_length);
int htree_add_random_data(struct hash_tree *tree, const int num_random_blocks);
int htree_add_random_secrets(struct hash_tree *tree);
int htree_calc_nodes(struct hash_tree *tree,
                     const htree_leaf_gen leaf_gen,
                     const htree_node_gen node_gen,
                     const struct htree_gen_args *gen_args);
int htree_get_num_remaining(const struct hash_tree *tree);
int htree_has_more_data(const struct hash_tree *tree);
int htree_get_next_data_offset(struct hash_tree *tree);
unsigned char *htree_get_branch(const struct hash_tree *tree,
                                const int data_index,
                                unsigned char *nodes,
                                int *branch_length);
const unsigned char *htree_get_data(const struct hash_tree *tree,
                                    const int data_index,
                                    int *data_length);
const unsigned char *htree_get_secret(const struct hash_tree *tree,
                                      const int secret_index,
                                      int *secret_length);
const unsigned char *htree_get_root(const struct hash_tree *tree,
                                    int *root_length);
int htree_verify_branch(const unsigned char *root,
                        const int root_length,
                        const unsigned char *branch_nodes,
                        const uint32_t branch_length,
                        const unsigned char *verify_data,
                        const int data_length,
                        const uint32_t data_index,
                        const unsigned char *secret,
                        const int secret_length,
                        const htree_leaf_gen leaf_gen,
                        const htree_node_gen node_gen,
                        const struct htree_gen_args *gen_args);
int htree_leaf_generator(const unsigned char *data,
                         const int data_length,
                         const unsigned char *secret,
                         const int secret_length,
                         unsigned char *dst_buffer,
                         const struct htree_gen_args *gen_args);
int htree_node_generator(const unsigned char *left_node,
                         const unsigned char *right_node,
                         const int node_length,
                         unsigned char *dst_buffer,
                         const struct htree_gen_args *gen_args);

#endif /* HIPL_LIBCORE_HASHTREE_H */
