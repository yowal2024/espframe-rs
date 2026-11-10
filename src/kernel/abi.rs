#![allow(non_upper_case_globals)]

pub const ADDRESS_MASK: u64 = 0xffffffffff;

pub const VM_READ: u8 = 0x01;
pub const VM_WRITE: u8 = 0x02;
pub const VM_EXEC: u8 = 0x04;
pub const VM_SHARED: u8 = 0x08;

pub const MAX_MODULES: usize = 1024;
pub const MAX_SCAN_REGIONS: usize = 16534;
pub const MODULE_NAME_LEN: usize = 256;
pub const MAX_SEGMENTS_PER_MODULE: usize = 512;

pub const CALL_MEMORY_READ: u8 = 0;
pub const CALL_MEMORY_WRITE: u8 = 1;
pub const CALL_MEMORY_NO_CACHE: u8 = 2;
pub const CALL_MEMORY_IO: u8 = 4;
pub const CALL_MEMORY_USER: u8 = 8;
/// Opt-in clean to PoC before a cached kernel-to-user read.
pub const CALL_MEMORY_DCACHE: u8 = 16;

pub const UDP_CAP_MAX_PAYLOAD: u32 = 2048;
pub const UDP_CAP_READ_MAX: usize = 32;
pub const UDP_CAP_F_TRUNC: u16 = 1;
pub const RSA_REDIRECT_MAX_PROFILES: usize = 8;
pub const RSA_REDIRECT_READ_MAX: usize = 16;
pub const RSA_REDIRECT_MAX_ENTRY: usize = 4096;
pub const RSA_REDIRECT_F_FILE: u32 = 1;
pub const MEM_CAPTURE_MAX_GROUPS: usize = 6;
pub const MEM_CAPTURE_MAX_BYTES: usize = 64;
pub const MEM_MODIFY_MAX_GROUPS: usize = 6;

pub const CMD_GRANT_SU: usize = 0x10010;
pub const CMD_IS_ENABLE_SU: usize = CMD_GRANT_SU + 1;
pub const CMD_SET_ENABLE_SU: usize = CMD_IS_ENABLE_SU + 1;
pub const CMD_GET_SERIALNO: usize = CMD_SET_ENABLE_SU + 1;
pub const CMD_IS_TASK_ALIVE: usize = CMD_GET_SERIALNO + 1;
pub const CMD_SET_NOT_FREEZER: usize = CMD_IS_TASK_ALIVE + 1;
pub const CMD_GET_TIDS: usize = CMD_SET_NOT_FREEZER + 1;
pub const CMD_GET_TLS: usize = CMD_GET_TIDS + 1;
pub const CMD_GET_THREAD_BY_COMM: usize = CMD_GET_TLS + 1;
pub const CMD_PROCESS_PAUTH: usize = CMD_GET_THREAD_BY_COMM + 1;
pub const CMD_PROCESS_IOCTL: usize = CMD_PROCESS_PAUTH + 1;
pub const CMD_PEEK_KGSL_SYNCSOURCE_ID: usize = CMD_PROCESS_IOCTL + 1;
pub const CMD_GET_TASK_BY_NAME: usize = CMD_PEEK_KGSL_SYNCSOURCE_ID + 1;
pub const CMD_GET_MOUDLE_BASE_BY_PID_NAME: usize = CMD_GET_TASK_BY_NAME + 1;
pub const CMD_GET_MODULE_BASE_BY_PID_NAME: usize = CMD_GET_MOUDLE_BASE_BY_PID_NAME;
pub const CMD_CALL_MEMORY: usize = CMD_GET_MODULE_BASE_BY_PID_NAME + 1;
pub const CMD_REMOTE_MMAP: usize = CMD_CALL_MEMORY + 1;
pub const CMD_GET_MEM_INFO: usize = CMD_REMOTE_MMAP + 1;
pub const CMD_REGISTER_HBRK: usize = CMD_GET_MEM_INFO + 1;
pub const CMD_UNREGISTER_HBRK: usize = CMD_REGISTER_HBRK + 1;
pub const CMD_SET_HBRK_REGS: usize = CMD_UNREGISTER_HBRK + 1;
pub const CMD_PAUSE_HBRK: usize = CMD_SET_HBRK_REGS + 1;
pub const CMD_RESUME_HBRK: usize = CMD_PAUSE_HBRK + 1;
pub const CMD_HBRK_SET_SHARED: usize = CMD_RESUME_HBRK + 1;
pub const CMD_HBRK_CLEAR_SHARED: usize = CMD_HBRK_SET_SHARED + 1;
pub const CMD_HBRK_SET_MEM_CAPTURE: usize = CMD_HBRK_CLEAR_SHARED + 1;
pub const CMD_HBRK_CLEAR_MEM_CAPTURE: usize = CMD_HBRK_SET_MEM_CAPTURE + 1;
pub const CMD_HBRK_SET_MEM_MODIFY: usize = CMD_HBRK_CLEAR_MEM_CAPTURE + 1;
pub const CMD_HBRK_CLEAR_MEM_MODIFY: usize = CMD_HBRK_SET_MEM_MODIFY + 1;
pub const CMD_REGISTER_PAGE_HBRK: usize = CMD_HBRK_CLEAR_MEM_MODIFY + 1;
pub const CMD_UNREGISTER_PAGE_HBRK: usize = CMD_REGISTER_PAGE_HBRK + 1;
pub const CMD_SET_PAGE_HBRK_REGS: usize = CMD_UNREGISTER_PAGE_HBRK + 1;
pub const CMD_REGISTER_DBI_HBRK: usize = CMD_SET_PAGE_HBRK_REGS + 1;
pub const CMD_UNREGISTER_DBI_HBRK: usize = CMD_REGISTER_DBI_HBRK + 1;
pub const CMD_REGISTER_SHADOW_HOOK: usize = CMD_UNREGISTER_DBI_HBRK + 1;
pub const CMD_UNREGISTER_SHADOW_HOOK: usize = CMD_REGISTER_SHADOW_HOOK + 1;
pub const CMD_REGISTER_MMU_BRK: usize = CMD_UNREGISTER_SHADOW_HOOK + 1;
pub const CMD_UNREGISTER_MMU_BRK: usize = CMD_REGISTER_MMU_BRK + 1;
pub const CMD_SET_MMU_BRK_SHARED: usize = CMD_UNREGISTER_MMU_BRK + 1;
pub const CMD_ARM_MMU_BRK: usize = CMD_SET_MMU_BRK_SHARED + 1;
pub const CMD_CREATE_TOUCH_EVENT_LISTENER: usize = CMD_ARM_MMU_BRK + 1;
pub const CMD_TOUCH_EVENT_UPDATE_SCREEN_INFO: usize = CMD_CREATE_TOUCH_EVENT_LISTENER + 1;
pub const CMD_UDP_CAP_INIT: usize = CMD_TOUCH_EVENT_UPDATE_SCREEN_INFO + 1;
pub const CMD_UDP_CAP_READ: usize = CMD_UDP_CAP_INIT + 1;
pub const CMD_UDP_CAP_STOP: usize = CMD_UDP_CAP_READ + 1;
pub const CMD_GYRO_EVENT_CONFIGURE: usize = CMD_UDP_CAP_STOP + 1;
pub const CMD_NET_SPOOF_SET: usize = CMD_GYRO_EVENT_CONFIGURE + 1;
pub const CMD_NET_SPOOF_STOP: usize = CMD_NET_SPOOF_SET + 1;
pub const CMD_NET_SPOOF_READ: usize = CMD_NET_SPOOF_STOP + 1;
pub const CMD_NET_SPOOF_STATS: usize = CMD_NET_SPOOF_READ + 1;
pub const CMD_NET_SPOOF_BIND: usize = CMD_NET_SPOOF_STATS + 1;
pub const CMD_TGCP_MIDDLE_SET: usize = CMD_NET_SPOOF_BIND + 1;
pub const CMD_TGCP_MIDDLE_STOP: usize = CMD_TGCP_MIDDLE_SET + 1;
pub const CMD_TGCP_MIDDLE_READ: usize = CMD_TGCP_MIDDLE_STOP + 1;
pub const CMD_TGCP_MIDDLE_STATS: usize = CMD_TGCP_MIDDLE_READ + 1;
pub const CMD_READ_SPOOF_SET: usize = CMD_TGCP_MIDDLE_STATS + 1;
pub const CMD_READ_SPOOF_STOP: usize = CMD_READ_SPOOF_SET + 1;
pub const CMD_READ_SPOOF_SET_GROUP: usize = CMD_READ_SPOOF_STOP + 1;

/// Adapter selector passed in the first direct argument slot of spoof commands.
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoofType {
    Uam = 0,
    Dfm = 1,
}

pub const SIGNS_REDIRECT_MAX_ENTRY: usize = 4096;
pub const SIGNS_REDIRECT_GROUP_MAX: usize = 4;
pub const TYPE7_PROXY_READ_MAX: usize = 16;

/// A verified proxy exchange. `key` is the server-side Ks; the client retains
/// its configured K0. IPv4 uses mapped IPv6 bytes; scalars are host-endian.
/// No Debug implementation because this record contains a session key.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Type7ProxyResult {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub socket_id: u64,
    pub pid: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_addr: [u8; 16],
    pub key: [u8; 16],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Type7ProxyReadStats {
    pub count: u32,
    pub dropped: u64,
}

/// One borrowed member of a Signs SET_GROUP call. The kernel copies the
/// descriptor and its byte buffers before returning; `reserved` must be zero.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
pub struct SignsRedirectGroupEntry {
    pub original_ptr: u64,
    pub replacement_ptr: u64,
    pub length: u32,
    pub reserved: u32,
}

pub const TGCP_MIDDLE_READ_MAX: usize = 16;
pub const TGCP_MIDDLE_MAX_PAYLOAD: usize = 4096;
pub const TGCP_MIDDLE_EVENT_READY: u16 = 1;
pub const TGCP_MIDDLE_EVENT_CLOSED: u16 = 2;
pub const TGCP_MIDDLE_EVENT_ERROR: u16 = 3;
pub const TGCP_MIDDLE_EVENT_DATA: u16 = 4;
pub const TGCP_MIDDLE_DATA_FIRST: u32 = 1;
pub const TGCP_MIDDLE_DATA_LAST: u32 = 2;
pub const TGCP_MIDDLE_STATUS_RUNNING: u32 = 1;

/// Only READY carries keys. DATA is the exact client-facing (Kc) ciphertext.
/// Deliberately no Debug implementation: records may contain session secrets.
#[repr(C, align(8))]
#[derive(Clone, PartialEq, Eq)]
pub struct TgcpMiddleEvent {
    pub seq: u64,
    pub session_id: u64,
    pub socket_id: u64,
    pub ts_ns: u64,
    /// Observed connector TGID; never a configured admission filter.
    pub target_pid: u32,
    pub sock_uid: u32,
    pub family: u16,
    pub event_type: u16,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub kc: [u8; 16],
    pub error: i32,
    pub key_mode: u32,
    pub stream_offset: u64,
    pub payload_len: u32,
    pub flags: u32,
    pub payload: [u8; TGCP_MIDDLE_MAX_PAYLOAD],
}

impl Default for TgcpMiddleEvent {
    fn default() -> Self {
        Self {
            seq: 0,
            session_id: 0,
            socket_id: 0,
            ts_ns: 0,
            target_pid: 0,
            sock_uid: 0,
            family: 0,
            event_type: 0,
            local_port: 0,
            remote_port: 0,
            local_addr: [0; 16],
            remote_addr: [0; 16],
            kc: [0; 16],
            error: 0,
            key_mode: 0,
            stream_offset: 0,
            payload_len: 0,
            flags: 0,
            payload: [0; TGCP_MIDDLE_MAX_PAYLOAD],
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgcpMiddleReadStats {
    pub count: u32,
    pub session_id: u64,
    pub dropped: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TgcpMiddleStats {
    pub status: u32,
    pub padding: u32,
    pub session_id: u64,
    pub emitted: u64,
    pub dropped: u64,
    pub active_flows: u32,
    pub queued_events: u32,
    pub send_hits: u64,
    pub recv_hits: u64,
}

pub const GYRO_EVENT_ONCE: u32 = 1 << 0;
pub const GYRO_EVENT_X: u32 = 1 << 1;
pub const GYRO_EVENT_Y: u32 = 1 << 2;
pub const GYRO_EVENT_Z: u32 = 1 << 3;
pub const GYRO_EVENT_APPEND: u32 = 1 << 4;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CallMemoryFlags: u8 {
        const Read = CALL_MEMORY_READ;
        const Write = CALL_MEMORY_WRITE;
        const NoCache = CALL_MEMORY_NO_CACHE;
        const Io = CALL_MEMORY_IO;
        const User = CALL_MEMORY_USER;
        /// Clean source D-cache lines to PoC before copying a cached read to user memory.
        /// Requires kernel support; ignored for Write, NoCache, or non-user destinations.
        /// The public memory syscall adds User internally. Existing modes do not opt in.
        const Dcache = CALL_MEMORY_DCACHE;
    }
}

impl CallMemoryFlags {
    pub const fn Bits(self) -> u8 {
        self.bits()
    }

    pub const fn for_mem_mode(mem_mode: i32) -> Self {
        match mem_mode {
            1 => Self::from_bits_retain(CALL_MEMORY_READ | CALL_MEMORY_NO_CACHE | CALL_MEMORY_IO),
            _ => Self::from_bits_retain(CALL_MEMORY_READ | CALL_MEMORY_NO_CACHE),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRequest {
    pub pid: i32,
    pub address: u64,
    pub length: u64,
    pub flags: u8,
}

impl MemoryRequest {
    pub const fn new(pid: i32, address: u64, length: u64, flags: u8) -> Self {
        Self {
            pid,
            address,
            length,
            flags,
        }
    }

    pub fn IsValid(self, write: bool) -> bool {
        // PID 0 is the scheduler and PID 1 is init; neither is a valid remote
        // memory target for this userspace API.
        self.pid > 1
            && self.address != 0
            && self.length != 0
            && self.length <= isize::MAX as u64
            && self.address.checked_add(self.length - 1).is_some()
            && ((self.flags & CALL_MEMORY_WRITE != 0) == write)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpCapPacket {
    pub seq: u64,
    pub ts_ns: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u16,
    pub flags: u16,
    pub sock_uid: u32,
    pub reserved: u32,
    pub payload: [u8; UDP_CAP_MAX_PAYLOAD as usize],
}

impl Default for UdpCapPacket {
    fn default() -> Self {
        Self {
            seq: 0,
            ts_ns: 0,
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            flags: 0,
            sock_uid: 0,
            reserved: 0,
            payload: [0; UDP_CAP_MAX_PAYLOAD as usize],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpCapInitRequest {
    pub pid: i32,
    pub reserved0: u32,
    pub min_payload: u16,
    pub max_payload: u16,
    pub reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpCapReadRequest {
    pub buf: u64,
    pub max_count: u32,
    pub out_count: u32,
    pub overflow: u64,
    pub captured: u64,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpCapReadStats {
    pub count: u32,
    pub overflow: u64,
    pub captured: u64,
}

/// Wire layout of kernel rsa_redirect_config. Use RsaRedirectConfig
/// and KernelDriver::UamNetSet to keep all pointed-to buffers borrowed.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
pub struct RsaRedirectSetRequest {
    pub flags: u32,
    pub expected_crc: u32,
    pub original_crc: u32,
    pub key_id: u32,
    pub capture_pid: i32,
    pub entry_len: u32,
    pub private_der: u64,
    pub public_der: u64,
    pub original_entry: u64,
    pub replacement_entry: u64,
    pub private_der_len: u32,
    pub public_der_len: u32,
    pub reserved: [u32; 2],
}

/// A successfully submitted rewrapped UDP Hello. The remote address contains
/// IPv6 network-order bytes; IPv4 uses ::ffff:a.b.c.d. Scalar fields are
/// host-endian. Profile ownership is kernel-private. No Debug to avoid logging
/// the session key and nonce accidentally. Sequence supports retry deduplication.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct RsaRedirectResult {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub pid: i32,
    pub remote_addr: [u8; 16],
    pub key: [u8; 32],
    pub nonce: [u8; 8],
    pub _padding: [u8; 4],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RsaRedirectReadStats {
    pub count: u32,
    pub dropped: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RsaRedirectStats {
    pub profiles: u32,
    pub _padding: u32,
    pub rewrapped: u64,
    pub crypto_failed: u64,
    pub send_failed: u64,
    pub rewritten_reads: u64,
    pub read_failed: u64,
    pub captured: u64,
    pub dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentInfo {
    pub index: i16,
    pub prot: u8,
    pub _padding: [u8; 5],
    pub start: u64,
    pub end: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: [u8; MODULE_NAME_LEN],
    pub seg_count: i32,
    pub segments: [SegmentInfo; MAX_SEGMENTS_PER_MODULE],
}

impl Default for ModuleInfo {
    fn default() -> Self {
        Self {
            name: [0; MODULE_NAME_LEN],
            seg_count: 0,
            segments: [SegmentInfo::default(); MAX_SEGMENTS_PER_MODULE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualMemory {
    pub module_count: i32,
    pub modules: [ModuleInfo; MAX_MODULES],
    pub region_count: i32,
    pub regions: [MemoryRegion; MAX_SCAN_REGIONS],
}

impl Default for VirtualMemory {
    fn default() -> Self {
        Self {
            module_count: 0,
            modules: [ModuleInfo::default(); MAX_MODULES],
            region_count: 0,
            regions: [MemoryRegion::default(); MAX_SCAN_REGIONS],
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessPauthOperation {
    Pacga = 0,
    Pacia = 1,
    Pacib = 2,
    Pacda = 3,
    Pacdb = 4,
    Autia = 5,
    Autib = 6,
    Autda = 7,
    Autdb = 8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PtRegsSet {
    pub enable_regs: [bool; 31],
    pub enable_sp: bool,
    pub enable_pc: bool,
    pub enable_pstate: bool,
    pub enable_orig_x0: bool,
    pub enable_syscallno: bool,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub orig_x0: u64,
    pub syscallno: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union RegModifyValue {
    pub int32_val: u32,
    pub int64_val: u64,
    pub float_val: f32,
    pub double_val: f64,
}

impl Default for RegModifyValue {
    fn default() -> Self {
        Self { int64_val: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RegModifyConfig {
    pub reg_index: i32,
    pub reg_type: u8,
    pub _pad: [u8; 3],
    pub value: RegModifyValue,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemCaptureConfig {
    pub base_reg: u8,
    pub _pad0: [u8; 3],
    pub offset: i32,
    pub length: u8,
    pub indirect: u8,
    pub reserved: u8,
    pub _pad1: u8,
    pub deref_offset: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemCaptureResult {
    pub address: u64,
    pub data: [u8; MEM_CAPTURE_MAX_BYTES],
    pub length: u8,
    pub success: u8,
    pub _pad: [u8; 6],
}

impl Default for MemCaptureResult {
    fn default() -> Self {
        Self {
            address: 0,
            data: [0; MEM_CAPTURE_MAX_BYTES],
            length: 0,
            success: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemModifyConfig {
    pub base_reg: u8,
    pub _pad: [u8; 3],
    pub offset: i32,
    pub data_type: u8,
    pub mode: u8,
    pub param_slot: u8,
    pub indirect: u8,
    pub deref_offset: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union MemModifySlot {
    pub i32: i32,
    pub i64: i64,
    pub f32: f32,
    pub f64: f64,
    pub raw: u64,
}

impl Default for MemModifySlot {
    fn default() -> Self {
        Self { raw: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwbpHitItem {
    pub hit_index: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub reserved: [u64; 2],
    pub mem_capture_count: u8,
    pub _pad: [u8; 7],
    pub mem_captures: [MemCaptureResult; MEM_CAPTURE_MAX_GROUPS],
}

impl Default for HwbpHitItem {
    fn default() -> Self {
        Self {
            hit_index: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            reserved: [0; 2],
            mem_capture_count: 0,
            _pad: [0; 7],
            mem_captures: [MemCaptureResult::default(); MEM_CAPTURE_MAX_GROUPS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwbpSharedHeader {
    pub write_idx: u32,
    pub capacity: u32,
    pub reserved: [u32; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HbrkSharedRequest {
    pub handle: usize,
    pub shared_buf_addr: u64,
    pub shared_buf_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HbrkMemCaptureRequest {
    pub handle: usize,
    pub count: u8,
    pub _pad: [u8; 7],
    pub configs: [MemCaptureConfig; MEM_CAPTURE_MAX_GROUPS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HbrkMemModifyRequest {
    pub handle: usize,
    pub count: u8,
    pub _pad: [u8; 7],
    pub configs: [MemModifyConfig; MEM_MODIFY_MAX_GROUPS],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MmuBreakOpKind {
    #[default]
    F32 = 0,
    F64 = 1,
    U32 = 2,
    U64 = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MmuBreakOpAction {
    #[default]
    Overwrite = 0,
    AddClear = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmuBreakOpConfig {
    pub base_reg: u8,
    pub kind: MmuBreakOpKind,
    pub action: MmuBreakOpAction,
    pub _pad: u8,
    pub offset: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmuBreakSharedConfig {
    pub handle: u64,
    pub shared_va: u64,
    pub count: u8,
    pub _pad: [u8; 7],
    pub ops: [MmuBreakOpConfig; 4],
}

pub const fn CanonicalizeAddress(address: u64) -> u64 {
    address & ADDRESS_MASK
}

pub const fn IsValidCachedAddress(address: u64) -> bool {
    (address >> 0x27) == 0 && (address >> 0x26) != 0
}
