//! Trusted native UDP plugins. Only three kernel commands; CONTROL is typed below.
//! No per-packet userspace callback. CONFIG returns a new handle and clears bindings.
use super::abi::{CMD_PLUGIN_CONTROL, CMD_PLUGIN_LOAD, CMD_PLUGIN_UNLOAD};
use super::udp_rules_abi::{UrBinding, UrEvent, UrParams, UrStats, UR_READ_MAX};
use super::{KernelDriver, KernelTransport};

pub const UP_MAX_IMAGE: usize = 1024 * 1024;
pub const UP_MAX_CONFIG: usize = 32768;
pub const UP_MAX_EXTRA: usize = 4096;
pub const UP_MAX_STATE: usize = 256;
pub const UP_CONFIG: usize = 1;
pub const UP_BIND: usize = 2;
pub const UP_PARAMS: usize = 3;
pub const UP_STOP: usize = 4;
pub const UP_STATS: usize = 5;
pub const UP_READ: usize = 6;
pub const UP_TARGET: usize = 7;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UpParamUpdate {
    pub binding_id: u64,
    pub expected_sequence: u64,
    pub value: UrParams,
    pub extra_bytes: u32,
    pub reserved: u32,
}

/// Output buffers are initialized/touched by these wrappers before nofault copy.
pub enum PluginControl<'a> {
    Configure { config: &'a [u8], validate_only: bool },
    Bind(&'a UrBinding),
    /// Select sockets by the target process UID, matching UDP capture semantics.
    /// Kernel resolves identity; no procfs, FD, netns or endpoint fields required.
    /// Returns a selector id used as binding_id in Parameters. Target exit stops it.
    TargetProcess { pid: i32 },
    Parameters { binding_id: u64, expected_sequence: u64, value: &'a UrParams, extra: &'a [u8] },
    Stop,
    Stats(&'a mut UrStats),
    Read(&'a mut [UrEvent]),
}

fn status(value: isize) -> Result<u64, isize> {
    if value < 0 { Err(value) } else { Ok(value as u64) }
}
fn ptr(bytes: &[u8]) -> usize {
    if bytes.is_empty() { 0 } else { bytes.as_ptr() as usize }
}
fn touch<T>(value: &mut T) {
    // T is one of the fully initialized, padding-free ABI records used below.
    let p = value as *mut T as *mut u8;
    for i in 0..core::mem::size_of::<T>() {
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
}
struct SensitiveBytes(Vec<u8>);
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        for b in &mut self.0 { unsafe { core::ptr::write_volatile(b, 0) }; }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
impl<T: KernelTransport> KernelDriver<T> {
    /// # Safety
    /// image must be trusted native code built for this SDK. It executes in
    /// kernel context and must obey callback lifetime/nonblocking contracts.
    pub unsafe fn PluginLoad(&self, image: &[u8], config: &[u8]) -> Result<u64, isize> {
        if image.is_empty() || image.len() > UP_MAX_IMAGE || config.len() > UP_MAX_CONFIG {
            return Err(-22);
        }
        let value = unsafe { self.Invoke(CMD_PLUGIN_LOAD,
            [ptr(image), image.len(), ptr(config), config.len(), 0]) };
        if value == 0 { Err(-71) } else { status(value) }
    }

    /// Forward a project-owned operation to a loaded plugin.
    /// # Safety
    /// The operation and all scalar/pointer arguments must match that image's
    /// contract. Referenced storage must remain valid throughout this call.
    pub unsafe fn PluginControlRaw(&self, handle: u64, operation: usize, args: [usize; 3]) -> isize {
        if handle == 0 || handle > isize::MAX as u64 { return -22; }
        unsafe { self.Invoke(CMD_PLUGIN_CONTROL,
            [handle as usize, operation, args[0], args[1], args[2]]) }
    }

    /// CONFIG success returns a replacement handle; all older handles/bindings
    /// become stale. PARAMS synchronously drains old readers before wiping data;
    /// it is not promised to be a low-latency per-frame update operation.
    pub fn PluginControl(&self, handle: u64, operation: PluginControl<'_>) -> Result<u64, isize> {
        let mut storage = SensitiveBytes(Vec::new());
        let mut read_limit = None;
        let args = match operation {
            PluginControl::Configure { config, validate_only } => {
                if config.len() > UP_MAX_CONFIG { return Err(-22); }
                [handle as usize, UP_CONFIG, ptr(config), config.len(), usize::from(validate_only)]
            }
            PluginControl::Bind(binding) =>
                [handle as usize, UP_BIND, binding as *const _ as usize, core::mem::size_of::<UrBinding>(), 0],
            PluginControl::TargetProcess { pid } => {
                if pid <= 0 { return Err(-22); }
                [handle as usize, UP_TARGET, pid as usize, 0, 0]
            }
            PluginControl::Parameters { binding_id, expected_sequence, value, extra } => {
                if extra.len() > UP_MAX_EXTRA { return Err(-22); }
                // Explicit encoding avoids padding reads and makes the flexible
                // tail's offset independent of Rust's allocation alignment.
                storage.0.reserve(120 + extra.len());
                for n in [binding_id, expected_sequence, value.sampled_ns, value.expires_ns, value.sample_id] {
                    storage.0.extend_from_slice(&n.to_ne_bytes());
                }
                storage.0.extend_from_slice(&value.flags.to_ne_bytes());
                storage.0.extend_from_slice(&value.reserved.to_ne_bytes());
                for n in value.values { storage.0.extend_from_slice(&n.to_ne_bytes()); }
                storage.0.extend_from_slice(&(extra.len() as u32).to_ne_bytes());
                storage.0.extend_from_slice(&0u32.to_ne_bytes());
                storage.0.extend_from_slice(extra);
                [handle as usize, UP_PARAMS, ptr(&storage.0), storage.0.len(), 0]
            }
            PluginControl::Stop => [handle as usize, UP_STOP, 0, 0, 0],
            PluginControl::Stats(out) => {
                touch(out);
                [handle as usize, UP_STATS, out as *mut _ as usize, core::mem::size_of::<UrStats>(), 0]
            }
            PluginControl::Read(out) => {
                if out.is_empty() || out.len() > UR_READ_MAX { return Err(-22); }
                for item in &mut *out { touch(item); }
                read_limit = Some(out.len());
                [handle as usize, UP_READ, out.as_mut_ptr() as usize, out.len(), 0]
            }
        };
        let value = unsafe { self.Invoke(CMD_PLUGIN_CONTROL, args) };
        if read_limit.is_some_and(|n| value > n as isize) { return Err(-71); }
        status(value)
    }
    pub fn PluginUnload(&self, handle: u64) -> Result<(), isize> {
        let value = unsafe { self.Invoke(CMD_PLUGIN_UNLOAD, [handle as usize, 0, 0, 0, 0]) };
        match value { 0 => Ok(()), n if n < 0 => Err(n), _ => Err(-71) }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    type Calls = Arc<Mutex<Vec<(usize, [usize; 5], Vec<u8>)>>>;
    #[derive(Clone, Default)]
    struct Transport(Calls);
    impl KernelTransport for Transport {
        unsafe fn Invoke(&self, _: i32, _: u64, command: usize, args: [usize; 5]) -> isize {
            let bytes = if command == CMD_PLUGIN_CONTROL && args[1] == UP_PARAMS {
                unsafe { core::slice::from_raw_parts(args[2] as *const u8, args[3]).to_vec() }
            } else { Vec::new() };
            self.0.lock().unwrap().push((command, args, bytes));
            if command == CMD_PLUGIN_LOAD { 7 } else { 0 }
        }
    }
    #[test]
    fn layout_and_three_direct_commands() {
        assert_eq!(core::mem::size_of::<UpParamUpdate>(), 120);
        assert_eq!(core::mem::offset_of!(UpParamUpdate, value), 16);
        assert_eq!(core::mem::offset_of!(UpParamUpdate, extra_bytes), 112);
        let t = Transport::default();
        let k = KernelDriver::new(1, 2, 3, t.clone());
        assert_eq!(unsafe { k.PluginLoad(&[1; 64], &[]) }, Ok(7));
        let params = UrParams { values: [0x55; 8], ..Default::default() };
        assert_eq!(k.PluginControl(7, PluginControl::Parameters {
            binding_id: 11, expected_sequence: 12, value: &params, extra: &[8, 9],
        }), Ok(0));
        assert_eq!(k.PluginUnload(7), Ok(()));
        let calls = t.0.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, CMD_PLUGIN_LOAD);
        assert_eq!(calls[0].1[2], 0);
        assert_eq!(calls[1].0, CMD_PLUGIN_CONTROL);
        assert_eq!(calls[1].1[0..2], [7, UP_PARAMS]);
        assert_eq!(&calls[1].2[0..8], &11u64.to_ne_bytes());
        assert_eq!(&calls[1].2[8..16], &12u64.to_ne_bytes());
        assert_eq!(&calls[1].2[112..116], &2u32.to_ne_bytes());
        assert_eq!(&calls[1].2[120..], &[8, 9]);
        assert_eq!(calls[2].0, CMD_PLUGIN_UNLOAD);
        assert_eq!(calls[2].1, [7, 0, 0, 0, 0]);
    }

    #[test]
    fn project_operation_is_forwarded_with_exact_arguments() {
        let t = Transport::default();
        let k = KernelDriver::new(1, 2, 3, t.clone());
        for handle in [0, u64::MAX] {
            assert_eq!(unsafe { k.PluginControlRaw(handle, 99, [11, 12, 13]) }, -22);
        }
        assert!(t.0.lock().unwrap().is_empty());
        assert_eq!(unsafe { k.PluginControlRaw(7, 99, [11, 12, 13]) }, 0);
        let calls = t.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, CMD_PLUGIN_CONTROL);
        assert_eq!(calls[0].1, [7, 99, 11, 12, 13]);
    }

    #[test]
    fn process_selector_passes_only_pid_and_rejects_invalid_targets() {
        let t = Transport::default();
        let k = KernelDriver::new(1, 2, 3, t.clone());
        for pid in [0, -1, i32::MIN] {
            assert_eq!(k.PluginControl(7, PluginControl::TargetProcess { pid }), Err(-22));
        }
        assert!(t.0.lock().unwrap().is_empty());
        assert_eq!(k.PluginControl(7, PluginControl::TargetProcess { pid: 1234 }), Ok(0));
        let calls = t.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, CMD_PLUGIN_CONTROL);
        assert_eq!(calls[0].1, [7, UP_TARGET, 1234, 0, 0]);
        assert!(calls[0].2.is_empty());
    }
}
