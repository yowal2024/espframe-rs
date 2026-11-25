/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef TGCP_PLUGIN_ABI_H
#define TGCP_PLUGIN_ABI_H
#include <linux/types.h>
struct tgcp_config { __u32 prime_len, generator; __u8 prime[64]; };
/* TP_EVENT_METADATA payload. DATA remains the client-facing encrypted stream. */
struct tgcp_ready { __u8 kc[16]; __u32 key_mode; };
#endif
