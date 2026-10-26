use jni::objects::JString;
use jni::sys::{jbyteArray, jstring, JNIEnv as RawEnv};
use jni::JNIEnv;

/// Convert a JNI string to an owned Rust value before entering application code.
/// A null reference is preserved as `None`; malformed modified UTF-8 is rejected.
///
/// # Safety
/// `env` must be a current-thread-attached JNI environment and `value` must be
/// either null or a live `jstring` valid for this call. `Err(())` means JNI
/// conversion or modified UTF-8 conversion failed.
#[allow(clippy::result_unit_err)] // Result<(),> is retained for the current JNI caller contract.
pub unsafe fn owned_string<'local>(
    env: &mut JNIEnv<'local>,
    value: jstring,
) -> Result<Option<String>, ()> {
    if value.is_null() {
        return Ok(None);
    }
    let java_string = unsafe { JString::from_raw(value) };
    let string = env.get_string(&java_string).map_err(|_| ())?;
    string.to_str().map(str::to_owned).map(Some).map_err(|_| ())
}

pub fn to_java_string<'local>(env: &mut JNIEnv<'local>, value: &str) -> Option<jstring> {
    env.new_string(value)
        .map(|s| s.into_raw())
        .map_err(|_| clear_exception(env))
        .ok()
}

pub fn to_java_bytes<'local>(env: &mut JNIEnv<'local>, value: &[u8]) -> Option<jbyteArray> {
    let length = checked_byte_array_len(value.len())?;
    let array = env
        .new_byte_array(length)
        .map_err(|_| clear_exception(env))
        .ok()?;
    let signed = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<i8>(), value.len()) };
    if env.set_byte_array_region(&array, 0, signed).is_err() {
        clear_exception(env);
        return None;
    }
    Some(array.into_raw())
}

pub fn clear_exception<'local>(env: &mut JNIEnv<'local>) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

/// Reconstructs a JNI environment wrapper from its raw pointer.
///
/// # Safety
/// `raw` must be null or a live `JNIEnv` pointer belonging to the current
/// attached thread and valid for the requested lifetime. In particular, the
/// caller must not provide a fabricated, stale, or detached-thread pointer.
/// This wrapper rejects null; `jni` 0.21's `JNIEnv::from_raw` otherwise only
/// constructs the wrapper, so it does not validate that the pointer meets
/// those JNI preconditions. `Err(())` means the pointer was null or wrapper
/// construction returned an error.
#[allow(clippy::result_unit_err)] // Result<(),> is retained for the current JNI caller contract.
pub unsafe fn from_raw<'local>(raw: *mut RawEnv) -> Result<JNIEnv<'local>, ()> {
    if raw.is_null() {
        return Err(());
    }
    unsafe { JNIEnv::from_raw(raw) }.map_err(|_| ())
}

pub fn path_from(value: Option<String>) -> Option<std::path::PathBuf> {
    value
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .map(std::path::PathBuf::from)
}

pub fn checked_byte_array_len(value: usize) -> Option<i32> {
    i32::try_from(value).ok()
}
