// SPDX-License-Identifier: GPL-2.0
#include <asm-generic/errno.h>
#include "read_sdk.h"

PLUGIN_NAME("read_replace");
PLUGIN_VERSION("1.0.0");
PLUGIN_LICENSE("GPL");
PLUGIN_AUTHOR("");
PLUGIN_DESCRIPTION("Equal-length file-read replacement");
PLUGIN_TYPE(PLUGIN_READ);

struct replace_context {
    __u32 bytes, count;
    __u8 data[];
};
static __u32 get32(const __u8 *p)
{ return (__u32)p[0] | (__u32)p[1]<<8 | (__u32)p[2]<<16 | (__u32)p[3]<<24; }
static int create(const struct rp_host *h, const void *data, __u32 n, void **out)
{
    const __u8 *p = data;
    struct replace_context *c;
    __u32 count, at = 4, i, a, b;
    if (!p || n < 4 || n > RP_MAX_CONFIG - sizeof(*c)) return -EINVAL;
    count = get32(p);
    if (!count || count > RP_MAX_RULES) return -EINVAL;
    for (i = 0; i < count; ++i) {
        if (n-at < 8) return -EINVAL;
        a = get32(p+at); b = get32(p+at+4); at += 8;
        if (!a || a > RP_MAX_BYTES || a != b || a+b > n-at) return -EINVAL;
        at += a+b;
    }
    if (at != n) return -EINVAL;
    c = h->alloc(sizeof(*c)+n);
    if (!c) return -ENOMEM;
    c->bytes = sizeof(*c)+n; c->count = count;
    for (i = 0; i < n; ++i) c->data[i] = p[i];
    *out = c;
    return 0;
}
static void destroy(const struct rp_host *h, void *context)
{
    struct replace_context *c = context;
    if (c) h->free(c, c->bytes);
}
static int rule(const void *context, __u32 index, struct rp_rule *out)
{
    const struct replace_context *c = context;
    __u32 i, at = 4, n;
    if (index >= c->count) return 0;
    for (i = 0; i < index; ++i) at += 8+2*get32(c->data+at);
    n = get32(c->data+at);
    *out = (struct rp_rule){ n, n, c->data+at+8, c->data+at+8+n };
    return 1;
}
PLUGIN_READ_OPS(create, destroy, rule);
