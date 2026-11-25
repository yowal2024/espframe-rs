/* SPDX-License-Identifier: GPL-2.0 */
#ifndef READ_NATIVE_PLUGIN_SDK_H
#define READ_NATIVE_PLUGIN_SDK_H
#include "readspoof/plugin_abi.h"
#include "plugins/plugin.h"
struct rp_host {
    void *(*alloc)(__u32 bytes); /* zero initialized; at most RP_MAX_CONFIG */
    void (*free)(void *, __u32 bytes); /* wipes before freeing */
};
struct rp_rule {
    __u32 original_bytes, replacement_bytes;
    const __u8 *original, *replacement;
};
/* Trusted native code, same ARM64 ELF format as UDP plugins.
 * All callbacks run synchronously during control, may sleep, and must not retain
 * the caller's configuration or start background work. create owns its context;
 * destroy must clean every partial creation. rule returns 1, 0 at end, or -errno.
 * Returned rule buffers stay valid until destroy; the host owns the rule record.
 * The host copies and validates 1..RP_MAX_RULES equal-length pairs before publish.
 * No plugin callback, image pointer or context is used on the read hot path.
 * Only changes expressible by these exact byte pairs are supported. */
struct rp_descriptor {
    struct plugin_descriptor header;
    int (*create)(const struct rp_host *, const void *, __u32, void **);
    void (*destroy)(const struct rp_host *, void *);
    int (*rule)(const void *, __u32 index, struct rp_rule *);
};
#define PLUGIN_READ_OPS(create_fn, destroy_fn, rule_fn) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_READ, "read registration requires PLUGIN_READ"); \
    static const struct rp_descriptor __plugin_descriptor = { \
        .header = __PLUGIN_HEADER, .create = (create_fn), \
        .destroy = (destroy_fn), .rule = (rule_fn), \
    }; \
    __PLUGIN_ENTRY()
#endif
