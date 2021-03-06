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
 *
 * We are using following notation in this file:
 * <pre>
 * +------------+   head   +---------+   next   +---------+
 * | linkedlist |--------->|   node  |--------->|   node  |--  ...  --> NULL
 * +------------+          +--------+-          +---------+
 *                              |                    |
 *                              | ptr                | ptr
 *                              v                    v
 *                         +---------+          +---------+
 *                         | element |          | element |
 *                         +---------+          +---------+
 * </pre>where element contains the payload data.
 */

#ifndef HIPL_LIBCORE_LINKEDLIST_H
#define HIPL_LIBCORE_LINKEDLIST_H

/** Linked list node. */
struct hip_ll_node {
    void               *ptr; /**< A pointer to node payload data. */
    struct hip_ll_node *next;     /**< A pointer to next node. */
};

/** Linked list. */
struct hip_ll {
    unsigned int        element_count;  /**< Total number of nodes in the list. */
    struct hip_ll_node *head;           /**< A pointer to the first node of the list. */
};

#define HIP_LL_INIT { 0, NULL }

/** Linked list element memory deallocator function pointer. */
typedef void (*free_elem_fn)(void *ptr);

void hip_ll_init(struct hip_ll *const linkedlist);
void hip_ll_uninit(struct hip_ll *linkedlist, free_elem_fn free_element);
unsigned int hip_ll_get_size(const struct hip_ll *const linkedlist);
int hip_ll_add(struct hip_ll *linkedlist, const unsigned int index, void *ptr);
int hip_ll_add_first(struct hip_ll *const linkedlist, void *const ptr);
int hip_ll_add_last(struct hip_ll *const linkedlist, void *const ptr);
void *hip_ll_del(struct hip_ll *linkedlist, const unsigned int index,
                 free_elem_fn free_element);
void *hip_ll_del_first(struct hip_ll *linkedlist, free_elem_fn free_element);
void *hip_ll_get(const struct hip_ll *const linkedlist, const unsigned int index);
const struct hip_ll_node *hip_ll_iterate(const struct hip_ll *const linkedlist,
                                         const struct hip_ll_node *const current);

#endif /* HIPL_LIBCORE_LINKEDLIST_H */
