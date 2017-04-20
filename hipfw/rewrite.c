/*
 * Copyright (c) 2011, 2013, 2016 Aalto University and RWTH Aachen University.
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
 * Support and utility functions for packet rewriting, especially for growing
 * packets.
 *
 * Note that the buffer supplied to ipq_get_packet() in the firewall main loop
 * is not big enough to hold both the ipq_packet header and ::HIP_MAX_PACKET
 * bytes of payload.
 * Furthermore, the actual amount of writable data behind the received payload
 * is not documented by the libipq team. This makes sense if you consider that
 * netlink is able to push multiple packets into our userspace buffer for
 * efficiency reasons. Unfortunately, it is not documented whether libipq
 * actually makes use of this feature either.
 *
 * For this reason, all packet rewriting that needs access beyond the boundaries
 * of the originally received packet should copy it into a big, temporary buffer
 * first. This is managed by the hip_fw_context_enable_write() function; see its
 * documentation for more info.
 *
 * After growing, the data_len field and the length of the innermost frame
 * (currently either HIP oder ESP) must be updated: Checksums and outer length
 * fields are updated only once, right before reinjecting the packet.
 *
 * @note Copying the packet incurs a considerable performance hit. Browsing the
 *       source code of libipq, netfilter_queue and netlink, one can find
 *       assumptions about the original buffer and its usage to save copying in
 *       some cases, but unless the internals of these interfaces are documented
 *       more thoroughly, these optimizations should be considered hacks (and
 *       are thus not used here).
 */

#define _BSD_SOURCE

#include <netinet/in.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "libcore/builder.h"
#include "libcore/checksum.h"
#include "libcore/debug.h"
#include "rewrite.h"

/**
 * Don't copy into a temporary buffer if true. May improve performance a bit,
 * but is not considered safe yet, as explained in this file's top-level
 * documentation.
 * May be useful for debugging or benchmarking the effect of copying, however.
 */
static const bool assume_ipq_buffer_sufficient = false;

static uint8_t scratch_buffer[HIP_MAX_PACKET];

/**
 * Given the address @a field of a struct member of @a old, return
 * the same field's address but offset from @a new.
 *
 * As an example use case, say we have a pointer into @a old:
 * <code>
 * char old[LEN];
 * ptr = &old[BLA];
 * </code>
 * Now after copying @a old to @a new, we need to update the pointer:
 * <code>
 * ptr = rebase(ptr, old, new);
 * </code>
 *
 * @note This is essentially equivalent to
 *       <code>
 *       return &new.field
 *       </code>
 *       But of course, the above can only be used if we actually know
 *       the name of @a field, while this function needs just the
 *       address and base pointer.
 */
static void *rebase(const void *const field,
                    const void *const old,
                    void *const new)
{
    HIP_ASSERT((const char *) field >= (const char *) old);
    return (char *) new + ((const char *) field - (const char *) old);
}

/**
 * Mark packet as modified and indicate that the packet buffer passed by libipq
 * is overwritten with packet content.
 *
 * @param ctx The current packet context.
 *
 * @note Only set this flag when sure that the new packet will not exceed the
 *       buffer length of the packet originally passed by libipq.
 */
static void hip_fw_context_enable_write_inplace(struct hip_fw_context *const ctx)
{
    ctx->modified = 1;
}

/**
 * Mark packet as modified and enable rewritten packet to grow up to
 * ::HIP_MAX_PACKET bytes.
 * The buffer will be available via the ipq_packet->payload member of @a ctx, as
 * usual. That is: To the caller, it should look like nothing happened.
 *
 * @param ctx The current packet context. The ipq header may have been modified
 *            but should be consistent, especially the data_len field.
 *
 * @note It is safe to call this function on the same @a ctx multiple times: the
 *       packet will not needlessly be copied again.
 */
static void hip_fw_context_enable_write(struct hip_fw_context *const ctx)
{
    HIP_ASSERT(ctx);
    HIP_ASSERT(ctx->ipq_packet);

    if (assume_ipq_buffer_sufficient) {
        hip_fw_context_enable_write_inplace(ctx);
        return;
    }

    if (ctx->ipq_packet->payload != scratch_buffer) {
        // copy packet data
        memcpy(scratch_buffer, ctx->ipq_packet->payload,
               ctx->ipq_packet->data_len);

        // rebase pointers in ctx to point into copy
        if (ctx->ip_version == 4) {
            ctx->ip_hdr.ipv4 = rebase(ctx->ip_hdr.ipv4,
                                      ctx->ipq_packet->payload,
                                      scratch_buffer);
        } else {
            HIP_ASSERT(ctx->ip_version == 6);
            ctx->ip_hdr.ipv6 = rebase(ctx->ip_hdr.ipv6,
                                      ctx->ipq_packet->payload,
                                      scratch_buffer);
        }

        switch (ctx->packet_type) {
        case ESP_PACKET:
            ctx->transport_hdr.esp = rebase(ctx->transport_hdr.esp,
                                            ctx->ipq_packet->payload,
                                            scratch_buffer);
            break;
        case HIP_PACKET:
            ctx->transport_hdr.hip = rebase(ctx->transport_hdr.hip,
                                            ctx->ipq_packet->payload,
                                            scratch_buffer);
            break;
        case OTHER_PACKET:
            break;
        default:
            HIP_ASSERT(false);
        }

        if (ctx->udp_encap_hdr) {
            ctx->udp_encap_hdr = rebase(ctx->udp_encap_hdr,
                                        ctx->ipq_packet->payload,
                                        scratch_buffer);
        }

        // set payload pointer to copy
        ctx->ipq_packet->payload = scratch_buffer;
        ctx->modified            = 1;
    } else {
        // second invocation
        HIP_ASSERT(ctx->modified);
    }
}

/**
 * Add a new parameter to the correct position in the packet. Parameters are
 * ordered by type number. Hence, some parameters might need to be moved in
 * order for the new parameter to fit into the right position.
 *
 * @param ctx   The current packet context.
 * @param param The parameter to be added to the packet.
 * @return true on success, false otherwise.
 */
bool hipfw_splice_param(struct hip_fw_context *const ctx,
                        const struct hip_tlv_common *const param)
{
    HIP_ASSERT(ctx);
    HIP_ASSERT(ctx->packet_type == HIP_PACKET);
    HIP_ASSERT(param);

    const size_t  hip_len      = hip_get_msg_total_len(ctx->transport_hdr.hip); // padded
    const size_t  param_len    = hip_get_param_total_len(param); // padded
    const hip_tlv param_type   = hip_get_param_type(param);
    const size_t  contents_len = hip_get_param_contents_len(param); // not padded

    // RFC 5201: Types 0 - 1023 are signed, so they must not be moved
    HIP_ASSERT(param_type >= 1024);

    if (ctx->ipq_packet->data_len + param_len > HIP_MAX_PACKET) {
        HIP_ERROR("New parameter of type %u, effective size %u, "
                  "does not fit into packet", param_type, param_len);
        return false;
    }

    hip_fw_context_enable_write(ctx);

    // note: this works because param_len is padded!  otherwise, resize the hip
    // packet and call hip_get_msg_total_len() instead.
    ctx->ipq_packet->data_len += param_len;

    struct hip_common *const hip     = ctx->transport_hdr.hip;
    uint8_t *const           end     = ((uint8_t *) hip) + hip_len;
    struct hip_tlv_common   *current = NULL;
    uint8_t                 *out     = end; // append by default

    while ((current = hip_get_next_param_readwrite(hip, current))) {
        if (hip_get_param_type(current) >= param_type) {
            uint8_t *const splice = (uint8_t *const) current;

            memmove(splice + param_len, splice, end - splice);
            out = splice;
            break;
        }
    }

    if ((sizeof(struct hip_tlv_common) + contents_len) != param_len) {
        // padding needed: don't send uninitialized data
        memset(out, 0, param_len);
    }

    memcpy(out, param, sizeof(struct hip_tlv_common) + contents_len);
    hip_set_msg_total_len(hip, hip_len + param_len); // IP length etc. will be inferred

    return true;
}

/**
 * Getter for the position of the IP payload in an IPv4 packet. This allows to
 * handle IP options.
 *
 * @param ipv4 The IPv4 packet.
 */
inline static void *get_ipv4_payload(struct ip *const ipv4)
{
    return ((uint8_t *) ipv4) + 4 * ipv4->ip_hl;
}

/**
 * Update the UDP header after modifying the higher layer packet content.
 *
 * @param udp         The UDP packet.
 * @param payload_len The length of the UDP payload.
 * @param             src_ip The source IP address (needed for pseudo-header).
 * @param             dst_ip The destination IP address (needed for pseudo-header).
 */
static void update_udp_header(struct udphdr *const udp,
                              const size_t payload_len,
                              const struct in_addr src_ip,
                              const struct in_addr dst_ip)
{
    const uint16_t tot_len = sizeof(*udp) + payload_len;

    HIP_ASSERT(sizeof(*udp) == 8);

    udp->len   = htons(tot_len);
    udp->check = htons(0);
    udp->check = ipv4_checksum(IPPROTO_UDP, &src_ip, &dst_ip, udp, tot_len);
}

/**
 * Update the IPv4 header after modifying the higher layer packet content.
 *
 * @param ipv4 The IPv4 packet.
 * @param payload_len The length of the IPv4 payload.
 */
static void update_ipv4_header(struct ip *const ipv4,
                               const size_t payload_len)
{
    ipv4->ip_len = htons(ipv4->ip_hl * 4 + payload_len);
    ipv4->ip_sum = htons(0);
    ipv4->ip_sum = checksum_ip(ipv4, ipv4->ip_hl);
}

/**
 * Update the IPv6 header after modifying the higher layer packet content.
 *
 * @param ipv6 The IPv6 packet.
 * @param payload_len The length of the IPv6 payload.
 */
static void update_ipv6_header(struct ip6_hdr *const ipv6,
                               const size_t payload_len)
{
    ipv6->ip6_plen = htons(payload_len);
}

/**
 * Set an accept verdict for a modified packet
 *
 * @param handle netfilter_queue file handle
 * @param ctx    The current packet context.
 */
void allow_modified_packet(struct nfq_q_handle *const handle,
                           struct hip_fw_context *const ctx)
{
    HIP_ASSERT(ctx->modified);

    //
    // TODO: send as separate packets if fragmented?
    //

    if (ctx->packet_type == HIP_PACKET) {
        struct hip_common *const hip     = ctx->transport_hdr.hip;
        const size_t             hip_len = hip_get_msg_total_len(hip);

        if (ctx->ip_version == 4) {
            struct ip *const ipv4 = ctx->ip_hdr.ipv4;

            if (ipv4->ip_p == IPPROTO_UDP) {
                // UDP Payload: "zero SPI" (0x00000000) + HIP
                const size_t udp_len = HIP_UDP_ZERO_BYTES_LEN + hip_len;

                update_udp_header(get_ipv4_payload(ipv4), udp_len,
                                  ipv4->ip_src, ipv4->ip_dst);
                update_ipv4_header(ipv4, sizeof(struct udphdr) + udp_len);
                // HIP checksum unused
            } else {
                const struct sockaddr_in src = { .sin_family = AF_INET,
                                                 .sin_addr   = ipv4->ip_src };
                const struct sockaddr_in dst = { .sin_family = AF_INET,
                                                 .sin_addr   = ipv4->ip_dst };

                HIP_ASSERT(ipv4->ip_p == IPPROTO_HIP);

                hip_zero_msg_checksum(hip);
                hip->checksum = hip_checksum_packet((char *) hip,
                                                    (const struct sockaddr *) &src,
                                                    (const struct sockaddr *) &dst);
                update_ipv4_header(ipv4, hip_len);
            }
        } else {
            HIP_ASSERT(ctx->ip_version == 6);

            struct ip6_hdr *const     ipv6 = ctx->ip_hdr.ipv6;
            const struct sockaddr_in6 src  = { .sin6_family = AF_INET6,
                                               .sin6_addr   = ipv6->ip6_src };
            const struct sockaddr_in6 dst = { .sin6_family = AF_INET6,
                                              .sin6_addr   = ipv6->ip6_dst };

            HIP_ASSERT(ipv6->ip6_nxt == IPPROTO_HIP);

            hip_zero_msg_checksum(hip);
            hip->checksum = hip_checksum_packet((char *) hip,
                                                (const struct sockaddr *) &src,
                                                (const struct sockaddr *) &dst);
            update_ipv6_header(ipv6, hip_len);
        }
    }

    nfq_set_verdict(handle, ctx->ipq_packet->packet_id, NF_ACCEPT,
                    ctx->ipq_packet->data_len, ctx->ipq_packet->payload);
    HIP_DEBUG("Packet accepted with modifications\n\n");
}
