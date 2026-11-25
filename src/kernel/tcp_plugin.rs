//! Native TCP protocol plugins: the same LOAD/CONTROL/UNLOAD transport as UDP.
use super::abi::CMD_PLUGIN_CONTROL;
use super::{KernelDriver, KernelTransport};
pub use super::abi::TcpPluginStats;
pub const TP_CONFIG: usize = 1;
pub const TP_STOP: usize = 2;
pub const TP_READ: usize = 3;
pub const TP_STATS: usize = 4;
pub const TP_READ_MAX: usize = 16;
pub const TP_MAX_PAYLOAD: usize = 4096;
pub const TP_MAX_CONFIG: usize = 32768;
pub const TP_EVENT_METADATA: u16 = 1;
pub const TP_EVENT_CLOSED: u16 = 2;
pub const TP_EVENT_ERROR: u16 = 3;
pub const TP_EVENT_DATA: u16 = 4;
pub const TP_STATUS_RUNNING: u32 = 1;
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct TcpPluginEvent {
    pub seq: u64, pub session_id: u64, pub socket_id: u64, pub ts_ns: u64,
    pub target_pid: u32, pub sock_uid: u32,
    pub family: u16, pub event_type: u16, pub local_port: u16, pub remote_port: u16,
    pub local_addr: [u8; 16], pub remote_addr: [u8; 16],
    pub error: i32, pub flags: u32, pub stream_offset: u64,
    pub payload_len: u32, pub reserved: u32, pub payload: [u8; TP_MAX_PAYLOAD],
}
impl Default for TcpPluginEvent {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpPluginReadInfo { pub dropped: u64, pub session_id: u64 }
const _: () = {
    assert!(core::mem::size_of::<TcpPluginEvent>() == 4200);
    assert!(core::mem::size_of::<TcpPluginReadInfo>() == 16);
    assert!(core::mem::size_of::<TcpPluginStats>() == 56);
    assert!(core::mem::size_of::<super::abi::TgcpMiddleEvent>() >= core::mem::size_of::<TcpPluginEvent>());
    assert!(core::mem::align_of::<super::abi::TgcpMiddleEvent>() >= core::mem::align_of::<TcpPluginEvent>());
};
pub(crate) fn wipe<T>(value: &mut T) {
    let p = value as *mut T as *mut u8;
    for i in 0..core::mem::size_of::<T>() { unsafe { core::ptr::write_volatile(p.add(i), 0) }; }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub(super) fn tgcp_config(prime: &[u8], generator: u32) -> Result<[u8; 72], isize> {
    if !super::driver::tgcp_dh_parameters_valid(prime, generator) { return Err(-22); }
    let mut out = [0; 72];
    out[..4].copy_from_slice(&(prime.len() as u32).to_ne_bytes());
    out[4..8].copy_from_slice(&generator.to_ne_bytes());
    out[8..8 + prime.len()].copy_from_slice(prime);
    Ok(out)
}
impl<T: KernelTransport> KernelDriver<T> {
    pub fn TcpPluginStats(&self, handle: u64) -> Result<TcpPluginStats, isize> {
        if handle == 0 { return Err(-22); }
        let mut stats = TcpPluginStats::default();
        let rc = unsafe { self.Invoke(CMD_PLUGIN_CONTROL, [handle as usize, TP_STATS,
            &mut stats as *mut _ as usize, core::mem::size_of::<TcpPluginStats>(), 0]) };
        if rc != 0 { return Err(if rc < 0 { rc } else { -71 }); }
        if stats.session_id != handle || stats.padding != 0 || stats.status & !TP_STATUS_RUNNING != 0 {
            return Err(-71);
        }
        Ok(stats)
    }
    /// Reconfigure a stopped TCP plugin. Success returns a new handle.
    pub fn TcpPluginConfigure(&self, handle: u64, config: &[u8]) -> Result<u64, isize> {
        if handle == 0 || config.len() > TP_MAX_CONFIG { return Err(-22); }
        let p = if config.is_empty() { 0 } else { config.as_ptr() as usize };
        let rc = unsafe { self.Invoke(CMD_PLUGIN_CONTROL, [handle as usize, TP_CONFIG, p, config.len(), 0]) };
        if rc > 0 { Ok(rc as u64) } else { Err(if rc == 0 { -71 } else { rc }) }
    }
    pub fn TcpPluginStop(&self, handle: u64) -> Result<(), isize> {
        if handle == 0 { return Err(-22); }
        let rc = unsafe { self.Invoke(CMD_PLUGIN_CONTROL, [handle as usize, TP_STOP, 0, 0, 0]) };
        if rc == 0 { Ok(()) } else { Err(if rc > 0 { -71 } else { rc }) }
    }
    pub fn TcpPluginRead(&self, handle: u64, records: &mut [TcpPluginEvent]) -> Result<(usize, TcpPluginReadInfo), isize> {
        if handle == 0 || records.is_empty() || records.len() > TP_READ_MAX { return Err(-22); }
        for record in records.iter_mut() { wipe(record); }
        let mut info = TcpPluginReadInfo::default();
        let rc = unsafe { self.Invoke(CMD_PLUGIN_CONTROL, [handle as usize, TP_READ,
            records.as_mut_ptr() as usize, records.len(), &mut info as *mut _ as usize]) };
        let valid = rc >= 0 && rc <= records.len() as isize && info.session_id == handle
            && records.iter().take(rc.max(0) as usize).all(|r|
                r.session_id == handle && r.seq != 0 && r.socket_id != 0 && r.reserved == 0
                && r.payload_len as usize <= TP_MAX_PAYLOAD
                && r.payload[r.payload_len as usize..].iter().all(|b| *b == 0)
                && matches!(r.event_type, TP_EVENT_METADATA | TP_EVENT_CLOSED | TP_EVENT_ERROR | TP_EVENT_DATA));
        if !valid {
            for record in records.iter_mut() { wipe(record); }
            return Err(if rc < 0 { rc } else { -71 });
        }
        Ok((rc as usize, info))
    }
}
