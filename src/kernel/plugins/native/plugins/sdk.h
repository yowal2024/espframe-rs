/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UDP_NATIVE_PLUGIN_SDK_H
#define UDP_NATIVE_PLUGIN_SDK_H
#include "feature/udp_plugin_abi.h"
#include "plugins/plugin.h"
#define UP_SAME_LENGTH 1U
#define UP_PASS 0
#define UP_REPLACE 1
#define UP_OBSERVE 2
#define UP_USED_PARAMS 1U
/* Helpers marked CONTROL may sleep; never call them from process(). */
struct up_host {
    void *(*alloc)(__u32 bytes);                    /* CONTROL; zero initialized */
    void (*free)(void *, __u32 bytes);               /* CONTROL; wipes bytes */
    void *(*aead_create)(const __u8 *key, __u32 bytes); /* CONTROL; gcm(aes), tag=16 */
    void (*aead_destroy)(void *);                    /* CONTROL */
    int (*aead_run)(void *, int encrypt, const __u8 nonce[12],
                    const __u8 *aad, __u32 aad_bytes,
                    const __u8 *input, __u32 input_bytes,
                    __u8 *output, __u32 capacity); /* synchronous; returns bytes or -errno */
    __u32 (*crc32)(const __u8 *, __u32 bytes);
};
struct up_packet {
    const __u8 *data;
    __u32 bytes;
    __u32 params_available;
    const struct ur_params *params;
    const __u8 *extra;
    __u32 extra_bytes;
    __u32 params_claimed;
    __u64 now_ns, binding_id, session_id, parameter_sequence;
};
/* Host validates all output fields. state is a private transactional copy.
 * Negative result/PASS/OBSERVE/stale output discards changes to state/output.
 * process runs under the binding lock + RCU: bounded, no sleeps, no retention
 * of packet/state/output pointers, no deferred callbacks or background tasks.
 * context is immutable after create; separate bindings may call concurrently.
 * For UP_SAME_LENGTH, output initially contains all packet->bytes original
 * bytes in an independent writable buffer. Edit only the fields that change;
 * packet->data stays immutable, including for original-field copy operations.
 */
struct up_result {
    __u32 bytes, flags, rule_id, matched, limited, stale;
    __u64 expires_ns;
};
struct up_descriptor {
    struct plugin_descriptor header;
    __u32 state_bytes;
    __u32 max_output;
    __u32 flags;
    __u32 reserved;
    int (*create)(const struct up_host *, const void *, __u32, void **);
    void (*destroy)(const struct up_host *, void *);
    int (*process)(const struct up_host *, const void *, const struct up_packet *,
                   void *state, __u8 *output, __u32 capacity, struct up_result *);
};
#define PLUGIN_UDP_OPS(create_fn, destroy_fn, process_fn, state_size, output_limit, options) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_UDP, "UDP registration requires PLUGIN_UDP"); \
    static const struct up_descriptor __plugin_descriptor = { \
        .header = __PLUGIN_HEADER, .state_bytes = (state_size), \
        .max_output = (output_limit), .flags = (options), \
        .create = (create_fn), .destroy = (destroy_fn), .process = (process_fn), \
    }; \
    __PLUGIN_ENTRY()
static inline void *up_copy(void *to, const void *from, __u32 n)
{ __u8 *d=to; const __u8 *s=from; while(n--) *d++=*s++; return to; }
static inline void *up_zero(void *to, __u32 n)
{ __u8 *d=to; while(n--) *d++=0; return to; }
#endif
