/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef READ_PLUGIN_ABI_H
#define READ_PLUGIN_ABI_H
#include <linux/types.h>
#define RP_MAX_CONFIG (64U * 1024U)
#define RP_MAX_RULES 4U
#define RP_MAX_BYTES 4096U
/* LOAD(image, image_bytes, config, config_bytes, target_tgid) -> handle.
 * CONTROL(handle, op, a, b, c). No version negotiation. */
enum rp_control_op {
    RP_CONFIG = 1, /* a=config, b=bytes, c=0; returns a NEW handle */
    RP_STOP,       /* a=b=c=0; drain reads and release file bindings */
};
/* read_replace plugin config: header, then count variable-sized entries.
 * Each entry is followed by original[original_bytes], replacement[replacement_bytes].
 * Native little-endian ARM64; no pointers, padding between entries or trailing bytes. */
struct rp_replace_config { __u32 count; };
struct rp_replace_entry { __u32 original_bytes, replacement_bytes; };
#endif
