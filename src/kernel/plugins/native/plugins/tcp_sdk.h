/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TCP_NATIVE_PLUGIN_SDK_H
#define TCP_NATIVE_PLUGIN_SDK_H
#include "plugins/plugin.h"
#include "network/tcp_abi.h"

/* Sleepable helpers. Buffers are borrowed for the duration of each call.
 * Native plugins are trusted code, with no arbitrary kernel symbol imports. */
struct tp_host {
    void *(*alloc)(__u32 bytes);
    void (*free)(void *, __u32 bytes); /* sensitive wipe */
    int (*random)(__u8 *, __u32 bytes);
    int (*modexp)(const __u8 *base, __u32 base_bytes,
                  const __u8 *exponent, __u32 exponent_bytes,
                  const __u8 *modulus, __u32 modulus_bytes,
                  __u8 *output, __u32 output_bytes); /* fixed-width big endian */
    int (*md5)(const __u8 *, __u32 bytes, __u8 output[16]);
    void *(*cbc_create)(void);
    void (*cbc_destroy)(void *);
    int (*cbc_run)(void *, int encrypt, const __u8 *key, __u32 key_bytes,
                   const __u8 iv[16], __u8 *data, __u32 bytes);
};
struct tp_result {
    __u32 metadata_bytes;
    __u8 metadata[TP_MAX_METADATA];
};
/* A single prefix selects client-first streams; partial matches are buffered.
 * Ordinary, server-first and TFO traffic passes through. The host owns sockets,
 * buffers, short-write offsets, backpressure, polling, teardown and event queues.
 * Each flow has independent state. process calls are serialized across TX/RX.
 * frame_size is pure, concurrent and independent of mutable flow state: return
 * 0 for incomplete input, -errno for invalid framing, or a complete frame size.
 * process returns that same size, 0 to wait for peer progress, or -errno.
 * Zero must not change bytes/state; positive results transform one frame in
 * place. Length changes are not supported. Metadata is emitted only on success.
 * create/open failures must leave either NULL or destructible output pointers.
 * No retained host/packet pointers, hooks, background work or deferred callbacks.
 * STOP forbids new processing; image/context pins cover in-flight destruction.
 */
struct tp_descriptor {
    struct plugin_descriptor header;
    __u32 buffer_bytes, prefix_bytes;
    __u8 prefix[TP_MAX_PREFIX];
    int (*create)(const struct tp_host *, const void *, __u32, void **);
    void (*destroy)(const struct tp_host *, void *);
    int (*open)(const struct tp_host *, const void *, void **);
    void (*close)(const struct tp_host *, void *);
    int (*frame_size)(const __u8 *, __u32);
    int (*process)(const struct tp_host *, const void *, void *, __u32 direction,
                   __u8 *frame, __u32 bytes, struct tp_result *);
};
#define PLUGIN_TCP_OPS(create_fn, destroy_fn, open_fn, close_fn, frame_fn, process_fn, capacity, prefix_len, ...) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_TCP, "TCP registration requires PLUGIN_TCP"); \
    _Static_assert((capacity) > 0 && (capacity) <= TP_MAX_BUFFER, "invalid TCP buffer size"); \
    _Static_assert((prefix_len) > 0 && (prefix_len) <= TP_MAX_PREFIX, "invalid TCP prefix size"); \
    static const struct tp_descriptor __plugin_descriptor = { \
        .header = __PLUGIN_HEADER, .buffer_bytes = (capacity), .prefix_bytes = (prefix_len), \
        .prefix = { __VA_ARGS__ }, .create = (create_fn), .destroy = (destroy_fn), \
        .open = (open_fn), .close = (close_fn), .frame_size = (frame_fn), .process = (process_fn), \
    }; \
    __PLUGIN_ENTRY()
#endif
