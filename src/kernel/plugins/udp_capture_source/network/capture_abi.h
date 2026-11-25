/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef UDP_CAPTURE_PLUGIN_ABI_H
#define UDP_CAPTURE_PLUGIN_ABI_H
#include <linux/types.h>
enum { CP_START = 1, CP_STOP };
/* LOAD config for the standard UDP capture plugin; PID is load_arg. */
struct cp_policy { __u16 min_payload, max_payload; };
/* CONTROL: handle, CP_START, caller_mmap, mmap_bytes, 0.
 * STOP drains producers and releases pins; UNLOAD also releases the image.
 * All operations retain the original caller-mm ownership. */
#endif
