/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NATIVE_SERVICE_SDK_H
#define NATIVE_SERVICE_SDK_H
#include "plugins/plugin.h"
#define SP_MAX_CONFIG 32768U
#define SP_MAX_ALLOCATION (1024U * 1024U)
#define SP_READ 1U
#define SP_UDP_SEND 2U
#define SP_UDP_INCOMPLETE 1U
struct sp_udp {
    __u32 uid, pid, flags;
    __u8 remote[16], local[16];
};
/* token and every event/data pointer are borrowed for this callback only. */
struct sp_read { void *token; __u32 uid, pid; __u64 offset, bytes; };
struct sp_host {
    void *session;
    void *(*alloc)(__u32);
    void (*free)(void *, __u32);
    int (*user_read)(void *, __u64, __u32);
    int (*user_write)(__u64, const void *, __u32);
    void *(*mutex_create)(void);
    void (*mutex_destroy)(void *);
    void (*mutex_lock)(void *);
    void (*mutex_unlock)(void *);
    __u64 (*now_ns)(void);
    int (*selected_uid)(__u32);
    void *(*pid_get)(__s32, int *);
    void (*pid_put)(void *);
    int (*pid_is_current)(void *);
    /* create/control/destroy only. Changes the session's hook interests. */
    int (*interest)(void *session, __u32);
    int (*key_create)(const __u8 *, __u32, int, void **);
    void (*key_destroy)(void *);
    int (*crypt)(void *, int, __u8 *, __u32, __u8 [256], __u32);
    int (*file_create)(const __u8 *, const __u8 *, __u32, void **);
    void (*file_destroy)(void *);
    int (*file_conflict)(const void *, const void *);
    /* read callback only, protected by the plugin's file-binding mutex.
     * begin pins temporary write exclusion; host releases any unused lease.
     * find never binds; apply transfers the lease only for the chosen rule. */
    int (*file_begin)(const struct sp_read *);
    int (*file_find)(void *, const struct sp_read *, __u64 *);
    int (*file_apply)(void *, const struct sp_read *, __u64);
};
/* All callbacks may sleep. UDP/read callbacks may run concurrently; the
 * plugin protects mutable data with host mutexes. create/control/destroy
 * exclude those callbacks. Native file reads run before acquiring this gate,
 * so STOP/unload never waits for unrelated blocked native file reads.
 * No retained borrowed pointers, background workers or deferred callbacks.
 * UDP returns 0/pass, 1/submit unchanged length, or -errno. complete runs
 * exactly once for a non-NULL transaction, before the session can be freed. */
struct sp_descriptor {
    struct plugin_descriptor header;
    __u32 min_packet, max_packet;
    int (*create)(const struct sp_host *, const void *, __u32, __u64, void **);
    void (*destroy)(const struct sp_host *, void *);
    long (*control)(const struct sp_host *, void *, __u64, __u64, __u64, __u64);
    int (*wants_udp)(const struct sp_host *, const void *, const struct sp_udp *);
    int (*udp)(const struct sp_host *, void *, const struct sp_udp *, __u8 *, __u32, void **);
    void (*complete)(const struct sp_host *, void *, const struct sp_udp *, void *, int, __u32);
    long (*read)(const struct sp_host *, void *, const struct sp_read *);
};
#define PLUGIN_SERVICE_OPS(create_fn,destroy_fn,control_fn,wants_fn,udp_fn,done_fn,read_fn,minimum,maximum) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_SERVICE, "service registration requires PLUGIN_SERVICE"); \
    _Static_assert((minimum)>0 && (minimum)<=(maximum) && (maximum)<=4096, "invalid service packet bounds"); \
    static const struct sp_descriptor __plugin_descriptor = { \
        .header=__PLUGIN_HEADER, .min_packet=(minimum), .max_packet=(maximum), \
        .create=(create_fn), .destroy=(destroy_fn), .control=(control_fn), \
        .wants_udp=(wants_fn), .udp=(udp_fn), .complete=(done_fn), .read=(read_fn), \
    }; \
    __PLUGIN_ENTRY()
#endif
