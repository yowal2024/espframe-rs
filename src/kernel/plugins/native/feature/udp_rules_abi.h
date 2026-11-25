/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef UDP_RULES_ABI_H
#define UDP_RULES_ABI_H
#include <linux/types.h>

#define UR_MAX_RULES 16U
#define UR_MAX_OPS 8U
#define UR_MAX_BINDINGS 8U
#define UR_MAX_PARAMS 8U
#define UR_MAX_PAYLOAD 2048U
#define UR_EVENT_CAPACITY 64U
#define UR_READ_MAX 16U
#define UR_SET_VALIDATE_ONLY 1U
#define UR_RX 1U
#define UR_IPV4 2U
#define UR_RAW 0U
#define UR_LSB0 0U
#define UR_MSB0 1U
#define UR_CONSTANT 0U
#define UR_PARAMETER 1U
#define UR_COPY_FIELD 2U
#define UR_PARAMS_ONCE 1U

/* Host-endian scalars; network-order mapped IPv4 bytes in address arrays.
 * LSB0: low bit at bit_offset becomes value bit 0. MSB0: high bit
 * at bit_offset becomes value bit (width-1). No implicit byte-order swap.
 * Match: (field & mask) == value. Edit: (field & ~mask) | (source & mask).
 * COPY reads the ORIGINAL packet, even after an earlier overlapping edit.
 */
struct ur_op {
    __u32 bit_offset;
    __u16 width;
    __u8 order;
    __u8 source;
    __u64 mask;
    __u64 value;
    __u32 source_bit;
    __u16 parameter;
    __u16 reserved;
};
struct ur_rule {
    __u32 id;
    __u32 priority;             /* ascending priority, then id */
    __u64 expires_ns;           /* CLOCK_MONOTONIC; zero = no rule expiry */
    __u64 max_commits;          /* per binding, zero = unlimited */
    __u16 min_payload;
    __u16 max_payload;
    __u16 match_count;
    __u16 edit_count;           /* zero = observe only */
    struct ur_op matches[UR_MAX_OPS];
    struct ur_op edits[UR_MAX_OPS];
};
struct ur_program {
    __u32 rule_count;
    __u16 direction;            /* UR_RX only */
    __u16 family;               /* UR_IPV4 only */
    __u32 codec;                /* UR_RAW only */
    __u32 reserved;
    struct ur_rule rules[UR_MAX_RULES];
};
struct ur_binding {
    __s32 tgid;
    __u32 fd;
    __u32 socket_uid;
    __u32 netns_inode;
    __u64 session_id;           /* caller's nonzero session identity */
    __u64 expires_ns;           /* mandatory absolute CLOCK_MONOTONIC */
    __u8 local_addr[16];
    __u8 remote_addr[16];
    __u16 local_port;           /* host endian, exact packet tuple */
    __u16 remote_port;
    __u32 reserved;
};
struct ur_params {
    __u64 sampled_ns;           /* zero for constant presets */
    __u64 expires_ns;
    __u64 sample_id;            /* increasing for ONCE samples */
    __u32 flags;               /* ONCE: at most one commit per snapshot */
    __u32 reserved;
    __u64 values[UR_MAX_PARAMS];
};
enum ur_counter {
    UR_SEEN, UR_MATCHED, UR_COMMITTED, UR_STALE, UR_UNSUPPORTED,
    UR_MALFORMED, UR_NO_BUFFER, UR_LIMIT, UR_NATIVE_REJECT,
    UR_NATIVE_ACCEPT, UR_EVENT_OVERFLOW, UR_COPY_LOSS, UR_PLUGIN_ERROR, UR_COUNTERS
};
enum ur_event_status {
    UR_EVENT_COMMIT = 1, UR_EVENT_OBSERVE, UR_EVENT_NO_BUFFER,
    UR_EVENT_LIMIT, UR_EVENT_STALE, UR_EVENT_PLUGIN_ERROR
};
struct ur_stats {
    __u64 generation;
    __u64 counters[UR_COUNTERS];
    __u64 latency[8];           /* <1,2,4,8,16,32,64 us, >=64 us */
    __u64 total_ns;
    __u64 peak_ns;
    __u64 max_sample_age_ns;
    __u32 active;
    __u32 bindings;
};
struct ur_event {
    __u64 timestamp_ns;
    __u64 generation;
    __u64 binding_id;
    __u64 parameter_sequence;
    __u64 elapsed_ns;
    __u32 rule_id;
    __u32 status;
    __s32 native_result;
    __u32 payload_length;
    __s32 plugin_result;
    __u32 reserved;
};
#endif
