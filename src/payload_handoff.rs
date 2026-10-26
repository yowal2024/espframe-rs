use crate::{StubPayloadInit, STUB_PAYLOAD_INIT_VERSION};
use std::mem::align_of;
use std::sync::{Mutex, OnceLock};

fn handoff() -> &'static Mutex<Option<Vec<u8>>> {
    static HANDOFF: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    HANDOFF.get_or_init(|| Mutex::new(None))
}

/// Validate and copy the decoded payload bytes supplied by the loader stub.
///
/// # Safety
/// `init.encrypted_blob` must point to `init.encrypted_size` readable bytes for
/// the duration of this call.
pub unsafe fn validate_and_store(init: &StubPayloadInit) -> bool {
    if init.version != STUB_PAYLOAD_INIT_VERSION {
        crate::espframe_log!(
            "handoff.reject.version",
            "actual={} expected={}",
            init.version,
            STUB_PAYLOAD_INIT_VERSION
        );
        return false;
    }
    if init.reserved != 0 {
        crate::espframe_log!("handoff.reject.reserved", "value={}", init.reserved);
        return false;
    }
    if init.encrypted_blob.is_null() {
        crate::espframe_log!("handoff.reject.null_blob");
        return false;
    }
    if init.encrypted_size == 0 {
        crate::espframe_log!("handoff.reject.empty_blob");
        return false;
    }
    if (init.encrypted_blob as usize)
        .checked_add(init.encrypted_size)
        .is_none()
    {
        crate::espframe_log!(
            "handoff.reject.range_overflow",
            "len={}",
            init.encrypted_size
        );
        return false;
    }
    let payload = unsafe { std::slice::from_raw_parts(init.encrypted_blob, init.encrypted_size) };
    store(payload)
}

/// Validate and store a handoff supplied by the loader stub.
///
/// # Safety
/// `init` must be null or point to a readable, live `StubPayloadInit` for the
/// duration of this call. Its payload byte range must also remain readable.
pub unsafe fn validate_and_store_ptr(init: *mut StubPayloadInit) -> bool {
    if init.is_null() {
        crate::espframe_log!("handoff.reject.null_init");
        return false;
    }
    if !(init as usize).is_multiple_of(align_of::<StubPayloadInit>()) {
        crate::espframe_log!("handoff.reject.unaligned_init");
        return false;
    }
    unsafe { validate_and_store(&*init) }
}

fn store(payload: &[u8]) -> bool {
    if !payload.starts_with(b"\x7fELF") {
        crate::espframe_log!("handoff.reject.not_elf", "len={}", payload.len());
        return false;
    }
    let Ok(mut slot) = handoff().lock() else {
        crate::espframe_log!("handoff.reject.lock_poisoned");
        return false;
    };
    *slot = Some(payload.to_vec());
    crate::espframe_log!("handoff.store.ok", "len={}", payload.len());
    true
}

pub fn snapshot() -> Option<(usize, usize)> {
    handoff().lock().ok().and_then(|slot| {
        slot.as_ref()
            .map(|payload| (payload.as_ptr() as usize, payload.len()))
    })
}

pub fn current() -> Option<(*const u8, usize)> {
    snapshot().map(|(pointer, length)| (pointer as *const u8, length))
}

pub fn load_payload_elf(library: &str) -> Result<Vec<u8>, String> {
    if let Some(payload) = handoff()
        .lock()
        .map_err(|_| "payload handoff lock is poisoned".to_owned())?
        .as_ref()
    {
        crate::espframe_log!("handoff.load.memory", "len={}", payload.len());
        return Ok(payload.clone());
    }
    if library.is_empty() {
        crate::espframe_log!("handoff.load.unavailable");
        return Err("embedded payload handoff is unavailable".to_owned());
    }
    std::fs::read(library)
        .inspect(|payload| {
            crate::espframe_log!("handoff.load.file", "len={}", payload.len());
        })
        .map_err(|error| {
            crate::espframe_log!("handoff.load.file_error", "error={}", error);
            error.to_string()
        })
}

#[doc(hidden)]
pub fn store_for_tests(payload: &[u8]) -> bool {
    store(payload)
}

#[doc(hidden)]
pub fn clear_for_tests() {
    if let Ok(mut slot) = handoff().lock() {
        *slot = None;
    }
}
