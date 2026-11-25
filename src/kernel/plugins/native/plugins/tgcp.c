// SPDX-License-Identifier: GPL-2.0
/* TGCP wire protocol only. Sockets and stream buffering belong to the host. */
#include <linux/errno.h>
#include "plugins/tcp_sdk.h"
#include "tgcp.h"
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
extern void *memcpy(void *, const void *, __SIZE_TYPE__);
extern void *memset(void *, int, __SIZE_TYPE__);
extern int memcmp(const void *, const void *, __SIZE_TYPE__);
#define TG_HEADER_MAX 4096U
#define TG_BODY_MAX 65536U
#define TG_CAP (TG_HEADER_MAX + TG_BODY_MAX)
static const u8 magic[] = {0x33, 0x66, 0, 0x0b, 0, 0x0c};
static u16 be16(const u8 *p) { return ((u16)p[0] << 8) | p[1]; }
static u32 be32(const u8 *p)
{ return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }
static void wipe(void *p, u32 n)
{ volatile u8 *v = p; while (n--) *v++ = 0; }
static int group_valid(const struct tgcp_config *g)
{
    u32 value = 0, i;
    if (!g->prime_len || g->prime_len > sizeof(g->prime) || !g->prime[0] ||
        !(g->prime[g->prime_len - 1] & 1) || g->generator < 2) return 0;
    for (i = g->prime_len; i < sizeof(g->prime); i++) if (g->prime[i]) return 0;
    if (g->prime_len > 4) return 1;
    for (i = 0; i < g->prime_len; i++) value = (value << 8) | g->prime[i];
    return value >= 5 && g->generator < value - 1;
}
struct tg_flow {
    u8 x[64], y[64], X[64], Y[64], kc[16], ks[16];
    u32 state, key_mode, request_mode;
    void *cipher;
};
static int create(const struct tp_host *h, const void *data, u32 n, void **out)
{
    const struct tgcp_config *g = data;
    *out = 0;
    if (!g || n != sizeof(*g) || !group_valid(g)) return -EINVAL;
    *out = h->alloc(sizeof(*g));
    if (!*out) return -ENOMEM;
    memcpy(*out, g, sizeof(*g));
    return 0;
}
static void destroy(const struct tp_host *h, void *p)
{ h->free(p, sizeof(struct tgcp_config)); }
static int open_flow(const struct tp_host *h, const void *context, void **out)
{
    struct tg_flow *f = h->alloc(sizeof(*f));
    (void)context;
    *out = f;
    if (!f) return -ENOMEM;
    f->cipher = h->cbc_create();
    return f->cipher ? 0 : -ENOMEM;
}
static void close_flow(const struct tp_host *h, void *p)
{
    struct tg_flow *f = p;
    if (!f) return;
    h->cbc_destroy(f->cipher);
    h->free(f, sizeof(*f));
}
/* Public/share values must satisfy 1 < value < p - 1, in fixed 64-byte form. */
static int valid_value(const struct tgcp_config *g, const u8 value[64])
{
    u8 limit[64] = {0}, one[64] = {0};
    u32 i;
    memcpy(limit + 64 - g->prime_len, g->prime, g->prime_len);
    for (i = 64; i; i--) if (limit[i - 1]--) break;
    one[63] = 1;
    return memcmp(value, one, 64) > 0 && memcmp(value, limit, 64) < 0;
}
static int keypair(const struct tp_host *h, const struct tgcp_config *g,
                    u8 private[64], u8 public[64])
{
    u8 generator[4] = {g->generator >> 24, g->generator >> 16,
                       g->generator >> 8, g->generator};
    int rc = h->random(private, 64);
    if (rc) return rc;
    private[0] = (private[0] & 0x7f) | 0x40;
    rc = h->modexp(generator, 4, private, 64, g->prime, g->prime_len, public, 64);
    return rc ? rc : valid_value(g, public) ? 0 : -EINVAL;
}
static int derive(const struct tp_host *h, const struct tgcp_config *g,
                   const u8 peer[64], const u8 private[64], u8 key[16])
{
    u8 shared[64];
    u32 offset = 0;
    int rc;
    if (!valid_value(g, peer)) return -EINVAL;
    rc = h->modexp(peer, 64, private, 64, g->prime, g->prime_len, shared, 64);
    if (!rc && !valid_value(g, shared)) rc = -EINVAL;
    if (!rc) {
        while (offset < 63 && !shared[offset]) offset++;
        rc = h->md5(shared + offset, 64 - offset, key);
    }
    wipe(shared, sizeof(shared));
    return rc;
}
static int recrypt(const struct tp_host *h, struct tg_flow *f, u32 d, u8 *body, u32 n)
{
    const u8 *source = d ? f->ks : f->kc, *target = d ? f->kc : f->ks;
    u8 iv[16];
    u32 i, padding, length;
    int rc;
    if (!n) return 0;
    if (n < 16 || n % 16) return -EPROTO;
    for (i = 0; i < 16; i++) iv[i] = i;
    rc = h->cbc_run(f->cipher, 0, source, 16, iv, body, n);
    if (rc) return rc;
    padding = body[n - 1];
    if (padding < 6 || padding > 21 || padding > n || memcmp(body + n - 6, "tsf4g", 5))
        return -EBADMSG;
    length = n - padding;
    if (padding != (length % 16 >= 11 ? 32 : 16) - length % 16) return -EBADMSG;
    return h->cbc_run(f->cipher, 1, target, 16, iv, body, n);
}
static int hello(const u8 *p, u32 hl, u16 cmd)
{ return hl >= 88 && be16(p + 6) == cmd && p[21] == 3 && p[22] == 0 && p[23] == 64; }
static int frame_size(const u8 *p, u32 n)
{
    u32 hl, bl;
    if (n < 21) return 0;
    if (memcmp(p, magic, sizeof(magic))) return -EPROTO;
    hl = be32(p + 13); bl = be32(p + 17);
    if (hl < 21 || hl > TG_HEADER_MAX || bl > TG_BODY_MAX) return -EMSGSIZE;
    return n < hl + bl ? 0 : (int)(hl + bl);
}
static int process(const struct tp_host *host, const void *context, void *state,
                    u32 d, u8 *h, u32 n, struct tp_result *out)
{
    const struct tgcp_config *g = context;
    struct tg_flow *f = state;
    u32 hl = be32(h + 13), bl = be32(h + 17), previous = f->state;
    u16 cmd = be16(h + 6);
    int rc;
    if (!d && f->state == 1) return 0;
    if (!f->state) {
        if (d || bl || cmd != 0x1001 || hl < 23) return -EPROTO;
        if (h[21] == 2) {
            if (h[22] != 3) return -EPROTO;
        } else if (h[21] == 3) {
            if (!hello(h, hl, 0x1001)) return -EPROTO;
            rc = keypair(host, g, f->x, f->X);
            if (!rc) rc = keypair(host, g, f->y, f->Y);
            if (!rc) rc = derive(host, g, h + 24, f->x, f->kc);
            if (rc) return rc;
            memcpy(h + 24, f->Y, 64);
        } else return -EPROTO;
        f->request_mode = h[21];
        f->state = 1;
    } else if (f->state == 1) {
        if (d != 1 || cmd != 0x1002 || hl < 23) return -EPROTO;
        if (h[21] == 2) {
            if (h[22] != 16 || hl < 39) return -EPROTO;
            memcpy(f->kc, h + 23, 16); memcpy(f->ks, h + 23, 16);
        } else if (h[21] == 3) {
            if (f->request_mode != 3 || !hello(h, hl, 0x1002)) return -EPROTO;
            rc = derive(host, g, h + 24, f->y, f->ks);
            if (rc) return rc;
            memcpy(h + 24, f->X, 64);
        } else return -EPROTO;
        f->key_mode = h[21]; f->state = 2;
        wipe(f->x, sizeof(f->x)); wipe(f->y, sizeof(f->y));
    } else if (cmd == 0x1001 || cmd == 0x1002) return -EPROTO;
    /* Upstream is encrypted regardless of byte8; downstream honors that byte. */
    rc = (!d || h[8]) ? recrypt(host, f, d, h + hl, bl) : 0;
    if (rc) return rc;
    if (previous != 2 && f->state == 2) {
        struct tgcp_ready ready;
        memcpy(ready.kc, f->kc, sizeof(ready.kc)); ready.key_mode = f->key_mode;
        out->metadata_bytes = sizeof(ready);
        memcpy(out->metadata, &ready, sizeof(ready));
        wipe(&ready, sizeof(ready));
    }
    return n;
}
PLUGIN_NAME("tgcp");
PLUGIN_VERSION("1.0.0");
PLUGIN_LICENSE("GPL");
PLUGIN_AUTHOR("");
PLUGIN_DESCRIPTION("TGCP client-first TCP stream protocol");
PLUGIN_TYPE(PLUGIN_TCP);
PLUGIN_TCP_OPS(create, destroy, open_flow, close_flow, frame_size, process,
               TG_CAP, 6, 0x33, 0x66, 0, 0x0b, 0, 0x0c);
