//! Raw IPv4 UDP RX rule ABI. Keep in sync with kernel/feature/udp_rules_abi.h.
//! Used by the raw-rules plugin and generic plugin host; see kernel::plugin.
pub const UR_MAX_RULES: usize = 16;
pub const UR_MAX_OPS: usize = 8;
pub const UR_MAX_BINDINGS: usize = 8;
pub const UR_MAX_PARAMS: usize = 8;
pub const UR_MAX_PAYLOAD: usize = 2048;
pub const UR_EVENT_CAPACITY: usize = 64;
pub const UR_READ_MAX: usize = 16;
pub const UR_SET_VALIDATE_ONLY: u32 = 1;
pub const UR_RX: u16 = 1;
pub const UR_IPV4: u16 = 2;
pub const UR_RAW: u32 = 0;
pub const UR_LSB0: u8 = 0;
pub const UR_MSB0: u8 = 1;
pub const UR_CONSTANT: u8 = 0;
pub const UR_PARAMETER: u8 = 1;
pub const UR_COPY_FIELD: u8 = 2;
pub const UR_PARAMS_ONCE: u32 = 1;
pub const UR_SEEN: usize = 0;
pub const UR_MATCHED: usize = UR_SEEN + 1;
pub const UR_COMMITTED: usize = UR_MATCHED + 1;
pub const UR_STALE: usize = UR_COMMITTED + 1;
pub const UR_UNSUPPORTED: usize = UR_STALE + 1;
pub const UR_MALFORMED: usize = UR_UNSUPPORTED + 1;
pub const UR_NO_BUFFER: usize = UR_MALFORMED + 1;
pub const UR_LIMIT: usize = UR_NO_BUFFER + 1;
pub const UR_NATIVE_REJECT: usize = UR_LIMIT + 1;
pub const UR_NATIVE_ACCEPT: usize = UR_NATIVE_REJECT + 1;
pub const UR_EVENT_OVERFLOW: usize = UR_NATIVE_ACCEPT + 1;
pub const UR_COPY_LOSS: usize = UR_EVENT_OVERFLOW + 1;
pub const UR_PLUGIN_ERROR: usize = UR_COPY_LOSS + 1;
pub const UR_COUNTERS: usize = UR_PLUGIN_ERROR + 1;
pub const UR_EVENT_COMMIT: u32 = 1;
pub const UR_EVENT_OBSERVE: u32 = 2;
pub const UR_EVENT_NO_BUFFER: u32 = 3;
pub const UR_EVENT_LIMIT: u32 = 4;
pub const UR_EVENT_STALE: u32 = 5;
pub const UR_EVENT_PLUGIN_ERROR: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrOp {
    pub bit_offset: u32,
    pub width: u16,
    pub order: u8,
    pub source: u8,
    pub mask: u64,
    pub value: u64,
    pub source_bit: u32,
    pub parameter: u16,
    pub reserved: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrRule {
    pub id: u32,
    pub priority: u32,
    pub expires_ns: u64,
    pub max_commits: u64,
    pub min_payload: u16,
    pub max_payload: u16,
    pub match_count: u16,
    pub edit_count: u16,
    pub matches: [UrOp; UR_MAX_OPS],
    pub edits: [UrOp; UR_MAX_OPS],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrProgram {
    pub rule_count: u32,
    pub direction: u16,
    pub family: u16,
    pub codec: u32,
    pub reserved: u32,
    pub rules: [UrRule; UR_MAX_RULES],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrBinding {
    pub tgid: i32,
    pub fd: u32,
    pub socket_uid: u32,
    pub netns_inode: u32,
    pub session_id: u64,
    pub expires_ns: u64,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrParams {
    pub sampled_ns: u64,
    pub expires_ns: u64,
    pub sample_id: u64,
    pub flags: u32,
    pub reserved: u32,
    pub values: [u64; UR_MAX_PARAMS],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrStats {
    pub generation: u64,
    pub counters: [u64; UR_COUNTERS],
    pub latency: [u64; 8],
    pub total_ns: u64,
    pub peak_ns: u64,
    pub max_sample_age_ns: u64,
    pub active: u32,
    pub bindings: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UrEvent {
    pub timestamp_ns: u64,
    pub generation: u64,
    pub binding_id: u64,
    pub parameter_sequence: u64,
    pub elapsed_ns: u64,
    pub rule_id: u32,
    pub status: u32,
    pub native_result: i32,
    pub payload_length: u32,
    pub plugin_result: i32,
    pub reserved: u32,
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};
    #[test]
    fn layouts() {
        assert_eq!(size_of::<UrOp>(), 32);
        assert_eq!(size_of::<UrRule>(), 544);
        assert_eq!(size_of::<UrProgram>(), 8720);
        assert_eq!(size_of::<UrBinding>(), 72);
        assert_eq!(size_of::<UrParams>(), 96);
        assert_eq!(size_of::<UrStats>(), 208);
        assert_eq!(size_of::<UrEvent>(), 64);
        assert_eq!(align_of::<UrProgram>(), 8);
        assert_eq!(offset_of!(UrOp, mask), 8);
        assert_eq!(offset_of!(UrRule, matches), 32);
        assert_eq!(offset_of!(UrBinding, local_addr), 32);
        assert_eq!(offset_of!(UrStats, active), 200);
    }
}
