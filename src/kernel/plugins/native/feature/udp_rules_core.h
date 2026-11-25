/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UDP_RULES_CORE_H
#define UDP_RULES_CORE_H
#include "udp_rules_abi.h"
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static inline __u64 ur_width_mask(unsigned int width)
{
    return width == 64 ? ~(__u64)0 : (((__u64)1 << width) - 1);
}
static inline int ur_zero(const void *p, unsigned int n)
{
    const unsigned char *b = p;
    while (n--) if (*b++) return 0;
    return 1;
}
static inline int ur_op_valid(const struct ur_op *o, unsigned int bytes,
                               int editing)
{
    __u64 mask;
    if (!o->width || o->width > 64 || o->order > UR_MSB0 ||
        o->reserved || o->bit_offset > bytes * 8 ||
        o->width > bytes * 8 - o->bit_offset)
        return -EINVAL;
    mask = ur_width_mask(o->width);
    if (!o->mask || (o->mask & ~mask) || (o->value & ~mask))
        return -EINVAL;
    if (o->source > UR_COPY_FIELD || (!editing && o->source))
        return -EOPNOTSUPP;
    if (o->source == UR_PARAMETER) {
        if (o->parameter >= UR_MAX_PARAMS || o->source_bit || o->value)
            return -EINVAL;
    } else if (o->source == UR_COPY_FIELD) {
        if (o->parameter || o->value || o->source_bit > bytes * 8 ||
            o->width > bytes * 8 - o->source_bit)
            return -EINVAL;
    } else if (o->parameter || o->source_bit || (!editing && (o->value & ~o->mask)))
        return -EINVAL;
    return 0;
}
static inline int ur_validate(const struct ur_program *p)
{
    unsigned int i, j, k;
    int rc;
    if (p->direction != UR_RX || p->family != UR_IPV4 || p->codec != UR_RAW)
        return -EOPNOTSUPP;
    if (!p->rule_count || p->rule_count > UR_MAX_RULES || p->reserved)
        return -EINVAL;
    for (i = 0; i < p->rule_count; i++) {
        const struct ur_rule *r = &p->rules[i];
        if (!r->id || r->max_payload > UR_MAX_PAYLOAD ||
            r->min_payload > r->max_payload ||
            r->match_count > UR_MAX_OPS || r->edit_count > UR_MAX_OPS ||
            r->max_commits > 0x7fffffffffffffffULL)
            return -EINVAL;
        for (j = 0; j < i; j++) if (p->rules[j].id == r->id) return -EINVAL;
        for (j = 0; j < UR_MAX_OPS; j++) {
            if (j < r->match_count) {
                rc = ur_op_valid(&r->matches[j], r->min_payload, 0);
                if (rc) return rc;
            } else if (!ur_zero(&r->matches[j], sizeof(struct ur_op))) return -EINVAL;
            if (j < r->edit_count) {
                rc = ur_op_valid(&r->edits[j], r->min_payload, 1);
                if (rc) return rc;
                /* Final values are deterministic even with overlapping edits. */
            } else if (!ur_zero(&r->edits[j], sizeof(struct ur_op))) return -EINVAL;
        }
    }
    for (k = p->rule_count; k < UR_MAX_RULES; k++)
        if (!ur_zero(&p->rules[k], sizeof(struct ur_rule))) return -EINVAL;
    return 0;
}
static inline __u64 ur_load_bits(const unsigned char *data, unsigned int offset,
                                  unsigned int width, unsigned int order)
{
    __u64 value = 0;
    unsigned int i, bit, pos;
    /* Whole-byte fields need one operation per byte, with no unaligned loads
     * or access past the declared field. Non-byte fields keep the bit path. */
    if (!((offset | width) & 7)) {
        data += offset >> 3;
        if (order == UR_LSB0)
            for (i = 0; i < width / 8; i++) value |= (__u64)data[i] << (i * 8);
        else
            for (i = 0; i < width / 8; i++) value = (value << 8) | data[i];
        return value;
    }
    for (i = 0; i < width; i++) {
        pos = offset + i;
        bit = order == UR_LSB0 ? (pos & 7) : 7 - (pos & 7);
        if (order == UR_LSB0) value |= (__u64)((data[pos >> 3] >> bit) & 1) << i;
        else value = (value << 1) | ((data[pos >> 3] >> bit) & 1);
    }
    return value;
}
static inline void ur_store_bits(unsigned char *data, const struct ur_op *o,
                                  __u64 value)
{
    unsigned int i, pos, bit, vbit;
    if (!((o->bit_offset | o->width) & 7)) {
        unsigned int bytes = o->width / 8;
        data += o->bit_offset >> 3;
        for (i = 0; i < bytes; i++) {
            unsigned int shift = (o->order == UR_LSB0 ? i : bytes - 1 - i) * 8;
            unsigned char mask = o->mask >> shift;
            if (mask) data[i] = (data[i] & ~mask) | ((value >> shift) & mask);
        }
        return;
    }
    for (i = 0; i < o->width; i++) {
        pos = o->bit_offset + i;
        bit = o->order == UR_LSB0 ? (pos & 7) : 7 - (pos & 7);
        vbit = o->order == UR_LSB0 ? i : o->width - 1 - i;
        if (!(o->mask & ((__u64)1 << vbit))) continue;
        data[pos >> 3] = (data[pos >> 3] & ~(1U << bit)) |
                         (((value >> vbit) & 1) << bit);
    }
}
static inline int ur_matches(const struct ur_rule *r, const unsigned char *data,
                               unsigned int len)
{
    unsigned int i;
    if (len < r->min_payload || len > r->max_payload) return 0;
    for (i = 0; i < r->match_count; i++) {
        const struct ur_op *o = &r->matches[i];
        if ((ur_load_bits(data, o->bit_offset, o->width, o->order) & o->mask) != o->value)
            return 0;
    }
    return 1;
}
static inline void ur_edit(const struct ur_rule *r, const unsigned char *original,
                            unsigned char *output, const struct ur_params *params)
{
    unsigned int i;
    for (i = 0; i < r->edit_count; i++) {
        const struct ur_op *o = &r->edits[i];
        __u64 value = o->value;
        if (o->source == UR_PARAMETER) value = params->values[o->parameter];
        else if (o->source == UR_COPY_FIELD)
            value = ur_load_bits(original, o->source_bit, o->width, o->order);
        ur_store_bits(output, o, value);
    }
}
#endif
