/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef UDP_PLUGIN_ABI_H
#define UDP_PLUGIN_ABI_H
#include "udp_rules_abi.h"
#define UP_MAX_IMAGE (1024U * 1024U)
#define UP_MAX_CONFIG 32768U
#define UP_MAX_EXTRA 4096U
#define UP_MAX_STATE 256U
/* CONTROL(handle, operation, a, b, c). No version negotiation. */
enum up_control_op {
    UP_CONFIG = 1, /* a=config, b=bytes, c=UR_SET_VALIDATE_ONLY or zero; returns NEW handle */
    UP_BIND,      /* a=ur_binding*, b=bytes, c=0; returns binding id */
    UP_PARAMS,    /* a=up_param_update*, b=bytes including extra, c=0; returns sequence */
    UP_STOP,      /* a=b=c=0; drain ingress, clear bindings, retain diagnostics */
    UP_STATS,     /* a=ur_stats*, b=bytes, c=0; handle=0 discovers current */
    UP_READ,      /* a=ur_event*, b=max events, c=0 */
    UP_TARGET,    /* a=target pid, b=c=0; select its socket UID like UDP capture */
};
struct up_param_update {
    __u64 binding_id;
    __u64 expected_sequence;
    struct ur_params value;
    __u32 extra_bytes;
    __u32 reserved;
    __u8 extra[];
};
#endif
