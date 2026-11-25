/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RSA_NATIVE_PLUGIN_SDK_H
#define RSA_NATIVE_PLUGIN_SDK_H
#include "plugins/plugin.h"
#include "netspoof/profile/uam/rsa_redirect_abi.h"

enum rsa_plugin_operation { RSA_ADD = 1, RSA_REMOVE, RSA_READ, RSA_STATS, RSA_STOP };
/* Copied buffers borrowed only during create. No userspace pointers cross the
 * callback boundary. The host owns file rules, PID references and result queues. */
struct rsa_plugin_config {
    __u32 expected_crc, original_crc, key_id;
    __u32 private_bytes, public_bytes;
    const __u8 *private_der, *public_der;
};
struct rsa_host {
    void *(*alloc)(__u32);
    void (*free)(void *, __u32);
    int (*key_create)(const __u8 *, __u32, int private_key, void **);
    void (*key_destroy)(void *);
    int (*crypt)(void *, int encrypt, __u8 *source, __u32 bytes,
                 __u8 output[256], __u32 expected);
};
/* Trusted sleepable callbacks, serialized per profile. match is pure and
 * returns 0/1; process returns 0 or -errno and preserves packet length.
 * create failures leave NULL or a destructible context. No retained borrowed
 * pointers, hooks, tasks or deferred callbacks. STOP/UNLOAD drain SRCU before
 * destroying every context and freeing the image. */
struct rsa_descriptor {
    struct plugin_descriptor header;
    __u32 min_packet, max_packet;
    int (*create)(const struct rsa_host *, const struct rsa_plugin_config *, void **);
    void (*destroy)(const struct rsa_host *, void *);
    int (*match)(const void *, const __u8 *, __u32);
    int (*process)(const struct rsa_host *, void *, __u8 *, __u32,
                   __u8 key[32], __u8 nonce[8]);
};
#define PLUGIN_RSA_OPS(create_fn, destroy_fn, match_fn, process_fn, minimum, maximum) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_RSA, "RSA registration requires PLUGIN_RSA"); \
    _Static_assert((minimum) > 0 && (minimum) <= (maximum) && (maximum) <= 4096, "invalid RSA packet bounds"); \
    static const struct rsa_descriptor __plugin_descriptor = { \
        .header = __PLUGIN_HEADER, .min_packet = (minimum), .max_packet = (maximum), \
        .create = (create_fn), .destroy = (destroy_fn), .match = (match_fn), .process = (process_fn), \
    }; \
    __PLUGIN_ENTRY()
#endif
