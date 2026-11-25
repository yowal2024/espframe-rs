/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UDP_CAPTURE_NATIVE_PLUGIN_SDK_H
#define UDP_CAPTURE_NATIVE_PLUGIN_SDK_H
#include "plugins/plugin.h"
#include "network/capture_abi.h"
/* Trusted control-time callback. Input is a temporary kernel copy, output is
 * host-owned. No retained pointers, allocations or background work. The host
 * validates/copies the immutable policy; no callback runs on the packet path.
 * This interface supports length-filtered capture into the shared UDP ring. */
struct cp_descriptor {
    struct plugin_descriptor header;
    int (*configure)(const void *, __u32, struct cp_policy *);
};
#define PLUGIN_CAPTURE_OPS(configure_fn) \
    _Static_assert((unsigned)__plugin_type == PLUGIN_CAPTURE, "capture registration requires PLUGIN_CAPTURE"); \
    static const struct cp_descriptor __plugin_descriptor = { \
        .header = __PLUGIN_HEADER, .configure = (configure_fn), \
    }; \
    __PLUGIN_ENTRY()
#endif
