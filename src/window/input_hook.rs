//! Android framework input hook used for the volume-key menu shortcut.
//!
//! The kernel input listener is intentionally kept for touch events. Android
//! volume keys are dispatched through `libinputreader` and never appear on
//! that listener, so this module mirrors the legacy GOT hook for
//! `NotifyKeyArgs` and forwards only the framework volume-down press into the
//! normal input channel. The legacy hook listens to both volume keys and uses
//! one shared double-click window, so both key codes are forwarded here.

use super::input::{InputEvent, ACTION_DOWN};
use crate::sensor::elf::find_relocation_for_symbol_with_resolver;
use crate::sensor::{LoadedElf, SensorError};
use core::ffi::{c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

pub const ANDROID_KEYCODE_VOLUME_UP: i32 = 24;
pub const ANDROID_KEYCODE_VOLUME_DOWN: i32 = 25;
pub const LINUX_KEYCODE_VOLUME_UP: u16 = 115;
pub const LINUX_KEYCODE_VOLUME_DOWN: u16 = 114;
const TARGET_LIBRARY: &CStr = c"libinputreader.so";
const TARGET_SYMBOL: &[u8] =
    b"_ZN7android13NotifyKeyArgsC1EillijNS_2ui16LogicalDisplayIdEjiiiiil\0";

/// Convert the framework constructor's action/key pair to the existing input
/// event representation. Key-up and all other key codes are deliberately
/// ignored; the runtime's existing double-click state machine consumes the
/// resulting key-down events.
pub fn android_volume_key_event(action: i32, key_code: i32) -> Option<InputEvent> {
    if action != ACTION_DOWN as i32 {
        return None;
    }
    let code = match key_code {
        ANDROID_KEYCODE_VOLUME_UP => LINUX_KEYCODE_VOLUME_UP,
        ANDROID_KEYCODE_VOLUME_DOWN => LINUX_KEYCODE_VOLUME_DOWN,
        _ => return None,
    };
    Some(InputEvent::Key { code, down: true })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VolumeHookError {
    #[error("volume-key hook ELF is malformed")]
    MalformedElf,
    #[error("libinputreader.so is not loaded")]
    ModuleNotFound,
    #[error("NotifyKeyArgs relocation was not found")]
    SymbolNotFound,
    #[error("volume-key hook relocation is unsupported")]
    UnsupportedRelocation,
    #[error("volume-key hook platform operation failed")]
    Platform,
    #[error("volume-key hook is already active")]
    AlreadyActive,
    #[error("volume-key hook cleanup failed")]
    CleanupFailed,
}

impl From<SensorError> for VolumeHookError {
    fn from(error: SensorError) -> Self {
        match error {
            SensorError::MalformedElf
            | SensorError::MissingDynamic
            | SensorError::UnterminatedDynamic
            | SensorError::MissingDynamicEntry => Self::MalformedElf,
            SensorError::UnsupportedRelocation => Self::UnsupportedRelocation,
            SensorError::SymbolNotFound => Self::SymbolNotFound,
            SensorError::ModuleNotFound => Self::ModuleNotFound,
            SensorError::CleanupFailed => Self::CleanupFailed,
            SensorError::AlreadyActive => Self::AlreadyActive,
            SensorError::NotActive | SensorError::Platform
            | SensorError::KernelRejected(_) | SensorError::InvalidValue => Self::Platform,
        }
    }
}

/// Platform operations needed by the process-local GOT patcher.
pub trait VolumeHookPlatform: Clone + Send + Sync + 'static {
    fn OpenXdl(&self, name: &CStr) -> Result<LoadedElf, VolumeHookError>;
    fn ResolveAddress(&self, base: usize, value: u64) -> Result<usize, VolumeHookError> {
        base.checked_add(usize::try_from(value).map_err(|_| VolumeHookError::MalformedElf)?)
            .ok_or(VolumeHookError::MalformedElf)
    }
    fn ProtectWritable(&self, page: usize, length: usize) -> Result<i32, VolumeHookError>;
    fn RestoreProtection(
        &self,
        page: usize,
        length: usize,
        protection: i32,
    ) -> Result<(), VolumeHookError>;
    fn ReadPointer(&self, address: usize) -> Result<usize, VolumeHookError>;
    fn WritePointer(&self, address: usize, value: usize) -> Result<(), VolumeHookError>;
    fn PageSize(&self) -> usize {
        4096
    }
}

#[cfg(target_os = "android")]
impl VolumeHookPlatform for crate::sensor::AndroidSensorPlatform {
    fn OpenXdl(&self, name: &CStr) -> Result<LoadedElf, VolumeHookError> {
        crate::sensor::SensorPlatform::OpenXdl(self, name).map_err(Into::into)
    }

    fn ResolveAddress(&self, base: usize, value: u64) -> Result<usize, VolumeHookError> {
        crate::sensor::SensorPlatform::ResolveAddress(self, base, value).map_err(Into::into)
    }

    fn ProtectWritable(&self, page: usize, length: usize) -> Result<i32, VolumeHookError> {
        crate::sensor::SensorPlatform::ProtectWritable(self, page, length).map_err(Into::into)
    }

    fn RestoreProtection(
        &self,
        page: usize,
        length: usize,
        protection: i32,
    ) -> Result<(), VolumeHookError> {
        crate::sensor::SensorPlatform::RestoreProtection(self, page, length, protection)
            .map_err(Into::into)
    }

    fn ReadPointer(&self, address: usize) -> Result<usize, VolumeHookError> {
        crate::sensor::SensorPlatform::ReadPointer(self, address).map_err(Into::into)
    }

    fn WritePointer(&self, address: usize, value: usize) -> Result<(), VolumeHookError> {
        crate::sensor::SensorPlatform::WritePointer(self, address, value).map_err(Into::into)
    }

    fn PageSize(&self) -> usize {
        crate::sensor::SensorPlatform::PageSize(self)
    }
}

type NotifyKeyArgsFn =
    unsafe extern "C" fn(*mut c_void, i32, i64, i64, i32, u32, i32, u32, i32, i32, i32, i32, i64);

struct Dispatch {
    original: usize,
    callback: Arc<dyn Fn(InputEvent) + Send + Sync + 'static>,
    accepting: AtomicBool,
    in_flight: Mutex<usize>,
    drained: Condvar,
}

impl Dispatch {
    fn new(original: usize, callback: Arc<dyn Fn(InputEvent) + Send + Sync + 'static>) -> Self {
        Self {
            original,
            callback,
            accepting: AtomicBool::new(true),
            in_flight: Mutex::new(0),
            drained: Condvar::new(),
        }
    }

    fn enter(&self) -> Option<DispatchGuard<'_>> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        *in_flight += 1;
        Some(DispatchGuard { dispatch: self })
    }

    fn stop_accepting_and_wait(&self) {
        self.accepting.store(false, Ordering::Release);
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *in_flight != 0 {
            in_flight = self
                .drained
                .wait(in_flight)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

struct DispatchGuard<'a> {
    dispatch: &'a Dispatch,
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        let mut in_flight = self
            .dispatch
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            self.dispatch.drained.notify_all();
        }
    }
}

fn global_dispatch() -> &'static Mutex<Option<Arc<Dispatch>>> {
    static GLOBAL: OnceLock<Mutex<Option<Arc<Dispatch>>>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(None))
}

fn publish_dispatch(dispatch: Arc<Dispatch>) -> Result<(), VolumeHookError> {
    let mut global = global_dispatch()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if global.is_some() {
        return Err(VolumeHookError::AlreadyActive);
    }
    *global = Some(dispatch);
    Ok(())
}

fn remove_dispatch(dispatch: &Arc<Dispatch>) {
    let mut global = global_dispatch()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if global
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, dispatch))
    {
        *global = None;
    }
}

/// Replacement for `android::NotifyKeyArgs`'s constructor relocation.
///
/// The ABI intentionally spells every argument explicitly. On AArch64 the
/// first eight values are passed in x0..x7 and the remaining constructor
/// values are read from the caller's stack exactly as in the legacy hook.
unsafe extern "C" fn espframe_notify_key_args_ctor(
    thiz: *mut c_void,
    id: i32,
    event_time: i64,
    read_time: i64,
    device_id: i32,
    source: u32,
    display_id: i32,
    policy_flags: u32,
    action: i32,
    flags: i32,
    key_code: i32,
    scan_code: i32,
    down_time: i64,
) {
    let dispatch = global_dispatch()
        .lock()
        .ok()
        .and_then(|global| global.clone());
    if let Some(dispatch) = dispatch {
        let entered = dispatch.enter();
        if entered.is_some() {
            if let Some(event) = android_volume_key_event(action, key_code) {
                crate::espframe_log!(
                    "window.volume_hook.event",
                    "action={} key_code={}",
                    action,
                    key_code
                );
                let callback = Arc::clone(&dispatch.callback);
                let _ = catch_unwind(AssertUnwindSafe(|| callback(event)));
            }
        }
        // Forward even when teardown has stopped accepting new callbacks: a
        // racing constructor may still have entered through the old GOT value.
        if dispatch.original != 0 {
            let original: NotifyKeyArgsFn = std::mem::transmute(dispatch.original);
            original(
                thiz,
                id,
                event_time,
                read_time,
                device_id,
                source,
                display_id,
                policy_flags,
                action,
                flags,
                key_code,
                scan_code,
                down_time,
            );
        }
        drop(entered);
    }
}

pub struct VolumeKeyHook<P: VolumeHookPlatform> {
    platform: P,
    got_slot: Option<usize>,
    original: Option<usize>,
    original_protection: Option<i32>,
    dispatch: Option<Arc<Dispatch>>,
}

impl<P: VolumeHookPlatform> VolumeKeyHook<P> {
    pub fn New(platform: P) -> Self {
        Self {
            platform,
            got_slot: None,
            original: None,
            original_protection: None,
            dispatch: None,
        }
    }

    pub fn Start<F>(&mut self, callback: F) -> Result<(), VolumeHookError>
    where
        F: Fn(InputEvent) + Send + Sync + 'static,
    {
        if self.dispatch.is_some() {
            return Err(VolumeHookError::AlreadyActive);
        }
        let elf = self.platform.OpenXdl(TARGET_LIBRARY)?;
        let slot = unsafe {
            find_relocation_for_symbol_with_resolver(
                elf.base,
                elf.program_headers,
                elf.program_header_count,
                TARGET_SYMBOL,
                |base, value| {
                    self.platform
                        .ResolveAddress(base, value)
                        .map_err(|_| SensorError::Platform)
                },
            )
        }
        .map_err(VolumeHookError::from)?;
        let original = self.platform.ReadPointer(slot)?;
        if original == 0 {
            return Err(VolumeHookError::Platform);
        }
        let page_size = self.platform.PageSize();
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(VolumeHookError::Platform);
        }
        let page = slot & !(page_size - 1);
        let protection = self.platform.ProtectWritable(page, page_size)?;
        let dispatch: Arc<Dispatch> = Arc::new(Dispatch::new(original, Arc::new(callback)));
        if let Err(error) = publish_dispatch(Arc::clone(&dispatch)) {
            let _ = self.platform.RestoreProtection(page, page_size, protection);
            return Err(error);
        }
        if let Err(error) = self
            .platform
            .WritePointer(slot, espframe_notify_key_args_ctor as *const () as usize)
        {
            remove_dispatch(&dispatch);
            let restore = self.platform.RestoreProtection(page, page_size, protection);
            return if restore.is_err() {
                Err(VolumeHookError::CleanupFailed)
            } else {
                Err(error)
            };
        }
        if let Err(error) = self.platform.RestoreProtection(page, page_size, protection) {
            let rollback = self.platform.WritePointer(slot, original);
            remove_dispatch(&dispatch);
            let restore = self.platform.RestoreProtection(page, page_size, protection);
            return if rollback.is_err() || restore.is_err() {
                Err(VolumeHookError::CleanupFailed)
            } else {
                Err(error)
            };
        }
        self.got_slot = Some(slot);
        self.original = Some(original);
        self.original_protection = Some(protection);
        self.dispatch = Some(dispatch);
        crate::espframe_log!("window.volume_hook.start", "slot={:#x}", slot);
        Ok(())
    }

    pub fn Stop(&mut self) -> Result<(), VolumeHookError> {
        let (Some(slot), Some(original), Some(protection), Some(dispatch)) = (
            self.got_slot,
            self.original,
            self.original_protection,
            self.dispatch.as_ref(),
        ) else {
            return Ok(());
        };
        let page_size = self.platform.PageSize();
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(VolumeHookError::Platform);
        }
        let page = slot & !(page_size - 1);
        self.platform.ProtectWritable(page, page_size)?;
        if let Err(error) = self.platform.WritePointer(slot, original) {
            let _ = self.platform.RestoreProtection(page, page_size, protection);
            return Err(error);
        }
        if let Err(error) = self.platform.RestoreProtection(page, page_size, protection) {
            let _ = self.platform.WritePointer(slot, original);
            return Err(error);
        }
        dispatch.stop_accepting_and_wait();
        remove_dispatch(dispatch);
        self.got_slot = None;
        self.original = None;
        self.original_protection = None;
        self.dispatch = None;
        crate::espframe_log!("window.volume_hook.stop", "slot={:#x}", slot);
        Ok(())
    }

    pub fn IsActive(&self) -> bool {
        self.dispatch.is_some()
    }
}

impl<P: VolumeHookPlatform> Drop for VolumeKeyHook<P> {
    fn drop(&mut self) {
        let _ = self.Stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Dyn {
        tag: i64,
        value: u64,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Sym {
        name: u32,
        info: u8,
        other: u8,
        shndx: u16,
        value: u64,
        size: u64,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Rela {
        offset: u64,
        info: u64,
        addend: i64,
    }

    #[derive(Clone)]
    struct FakePlatform {
        elf: LoadedElf,
        got: usize,
        current: Arc<Mutex<usize>>,
        writes: Arc<Mutex<Vec<(usize, usize)>>>,
    }

    // The fixture intentionally leaks its ELF tables for the test process.
    unsafe impl Send for FakePlatform {}
    unsafe impl Sync for FakePlatform {}

    impl VolumeHookPlatform for FakePlatform {
        fn OpenXdl(&self, _: &CStr) -> Result<LoadedElf, VolumeHookError> {
            Ok(self.elf)
        }
        fn ProtectWritable(&self, _: usize, _: usize) -> Result<i32, VolumeHookError> {
            Ok(5)
        }
        fn RestoreProtection(&self, _: usize, _: usize, _: i32) -> Result<(), VolumeHookError> {
            Ok(())
        }
        fn ReadPointer(&self, address: usize) -> Result<usize, VolumeHookError> {
            if address == self.got {
                Ok(*self.current.lock().unwrap())
            } else {
                Err(VolumeHookError::Platform)
            }
        }
        fn WritePointer(&self, address: usize, value: usize) -> Result<(), VolumeHookError> {
            self.writes.lock().unwrap().push((address, value));
            if address == self.got {
                *self.current.lock().unwrap() = value;
                Ok(())
            } else {
                Err(VolumeHookError::Platform)
            }
        }
        fn PageSize(&self) -> usize {
            4096
        }
    }

    fn fixture(original: usize) -> FakePlatform {
        let names = Box::leak(Box::new(TARGET_SYMBOL.to_vec()));
        let sym = Box::leak(Box::new(Sym::default()));
        let got = Box::leak(Box::new(original));
        let rela = Box::leak(Box::new(Rela {
            offset: got as *mut usize as usize as u64,
            ..Default::default()
        }));
        let dyns = Box::leak(Box::new([
            Dyn {
                tag: 6,
                value: sym as *mut Sym as usize as u64,
            },
            Dyn {
                tag: 5,
                value: names.as_ptr() as usize as u64,
            },
            Dyn {
                tag: 10,
                value: names.len() as u64,
            },
            Dyn {
                tag: 23,
                value: rela as *mut Rela as usize as u64,
            },
            Dyn {
                tag: 2,
                value: std::mem::size_of::<Rela>() as u64,
            },
            Dyn { tag: 20, value: 7 },
            Dyn { tag: 0, value: 0 },
        ]));
        let phdr = Box::leak(Box::new(crate::sensor::elf::Elf64Phdr {
            p_type: 2,
            p_vaddr: dyns.as_ptr() as usize as u64,
            p_filesz: (dyns.len() * std::mem::size_of::<Dyn>()) as u64,
            ..Default::default()
        }));
        FakePlatform {
            elf: LoadedElf {
                base: 0,
                program_headers: phdr,
                program_header_count: 1,
            },
            got: got as *mut usize as usize,
            current: Arc::new(Mutex::new(original)),
            writes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    static ORIGINAL_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn original_notify(
        _: *mut c_void,
        _: i32,
        _: i64,
        _: i64,
        _: i32,
        _: u32,
        _: i32,
        _: u32,
        _: i32,
        _: i32,
        _: i32,
        _: i32,
        _: i64,
    ) {
        ORIGINAL_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn framework_volume_translation_filters_action_and_key() {
        assert!(android_volume_key_event(ACTION_DOWN as i32, 25).is_some());
        assert!(android_volume_key_event(1, 25).is_none());
        assert!(android_volume_key_event(ACTION_DOWN as i32, 24).is_some());
    }

    #[test]
    fn dispatch_only_emits_volume_down_on_press() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let callback_events = Arc::clone(&events);
        let dispatch = Dispatch::new(
            1,
            Arc::new(move |event| callback_events.lock().unwrap().push(event)),
        );
        if let Some(event) = android_volume_key_event(ACTION_DOWN as i32, 25) {
            (dispatch.callback)(event);
        }
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn hook_forwards_every_constructor_and_restores_got_on_stop() {
        let _lock = global_dispatch().lock().unwrap();
        drop(_lock);
        ORIGINAL_CALLS.store(0, Ordering::SeqCst);
        let original = original_notify as *const () as usize;
        let platform = fixture(original);
        let got = platform.got;
        let current = Arc::clone(&platform.current);
        let events = Arc::new(Mutex::new(Vec::new()));
        let callback_events = Arc::clone(&events);
        let mut hook = VolumeKeyHook::New(platform);
        hook.Start(move |event| callback_events.lock().unwrap().push(event))
            .unwrap();
        assert!(hook.IsActive());

        unsafe {
            espframe_notify_key_args_ctor(
                std::ptr::null_mut(),
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                ACTION_DOWN as i32,
                0,
                25,
                0,
                0,
            );
            espframe_notify_key_args_ctor(
                std::ptr::null_mut(),
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                1,
                0,
                25,
                0,
                0,
            );
            espframe_notify_key_args_ctor(
                std::ptr::null_mut(),
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                ACTION_DOWN as i32,
                0,
                24,
                0,
                0,
            );
        }
        assert_eq!(events.lock().unwrap().len(), 2);
        assert_eq!(ORIGINAL_CALLS.load(Ordering::SeqCst), 3);
        hook.Stop().unwrap();
        assert!(!hook.IsActive());
        assert_eq!(*current.lock().unwrap(), original);
        assert!(hook
            .platform
            .writes
            .lock()
            .unwrap()
            .contains(&(got, original)));
    }
}
