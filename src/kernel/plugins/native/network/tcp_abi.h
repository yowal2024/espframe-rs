/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef NETWORK_TCP_ABI_H
#define NETWORK_TCP_ABI_H
#include <linux/types.h>

#define TP_READ_MAX 16U
#define TP_MAX_PAYLOAD 4096U
#define TP_MAX_BUFFER (128U * 1024U)
#define TP_MAX_CONFIG 32768U
#define TP_MAX_PREFIX 32U
#define TP_MAX_METADATA 64U
#define TP_STATUS_RUNNING 1U
#define TP_DATA_FIRST 1U
#define TP_DATA_LAST 2U
enum tp_control_op {
    TP_CONFIG = 1, /* config, bytes, 0; stopped only; returns a fresh handle */
    TP_STOP,       /* 0, 0, 0; retain handle, terminate transformed flows */
    TP_READ,       /* tp_event*, max_count, tp_read_info*; returns count */
    TP_STATS,      /* tp_stats*, sizeof(tp_stats), 0 */
};
enum tp_event_type { TP_EVENT_METADATA = 1, TP_EVENT_CLOSED, TP_EVENT_ERROR, TP_EVENT_DATA };
/* Scalars native endian; ports host order; IPv4 uses ::ffff:a.b.c.d.
 * METADATA payload belongs to the plugin. DATA is the client-facing RX stream.
 * FIRST marks stream offset zero; LAST ends a frame. All unused bytes are zero.
 * READ consumes records even on a nofault copy failure, accounting them as lost.
 * Callers must supply touched, writable output pages. */
struct tp_event {
    __aligned_u64 seq, session_id, socket_id, ts_ns;
    __u32 target_pid, sock_uid;
    __u16 family, type, local_port, remote_port;
    __u8 local_addr[16], remote_addr[16];
    __s32 error;
    __u32 flags;
    __aligned_u64 stream_offset;
    __u32 payload_len, reserved;
    __u8 payload[TP_MAX_PAYLOAD];
};
struct tp_read_info { __aligned_u64 dropped, session_id; };
struct tp_stats {
    __u32 status, padding;
    __aligned_u64 session_id, emitted, dropped;
    __u32 active_flows, queued_events;
    __aligned_u64 send_hits, recv_hits;
};
#endif
