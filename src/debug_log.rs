use core::fmt::Arguments;

pub const fn enabled() -> bool {
    match log_setting(
        option_env!("ESPFRAME_NATIVE_LOG"),
        option_env!("UAM_NATIVE_LOG"),
        option_env!("DELTA_NATIVE_LOG"),
    ) {
        Some(value) => match value.as_bytes().first() {
            Some(byte) => *byte != b'0',
            None => false,
        },
        None => false,
    }
}

pub(crate) fn memory_call_enabled(length: u64, result: isize) -> bool {
    should_log_memory_call(
        enabled(),
        matches!(
            log_setting(
                option_env!("ESPFRAME_MEMORY_LOG"),
                option_env!("UAM_MEMORY_LOG"),
                option_env!("DELTA_MEMORY_LOG"),
            ),
            Some("1")
        ),
        length,
        result,
    )
}

// Prefer the shared setting, including an explicit disable, over legacy aliases.
const fn log_setting(
    shared: Option<&'static str>,
    uam: Option<&'static str>,
    delta: Option<&'static str>,
) -> Option<&'static str> {
    match shared {
        Some(value) => Some(value),
        None => match uam {
            Some(value) => Some(value),
            None => delta,
        },
    }
}

const fn should_log_memory_call(
    native_enabled: bool,
    memory_trace: bool,
    length: u64,
    result: isize,
) -> bool {
    native_enabled && (memory_trace || result < 0 || result as u64 != length)
}

#[cfg(target_os = "android")]
pub fn emit(event: &str, args: Arguments<'_>) {
    if !enabled() {
        return;
    }
    let mut message = String::with_capacity(event.len() + 1);
    message.push_str(event);
    if !event.is_empty() {
        message.push(' ');
    }
    message.push_str(&args.to_string());
    let Ok(message) = std::ffi::CString::new(message) else {
        return;
    };
    const TAG: &[u8] = b"EspFrame\0";
    const FORMAT: &[u8] = b"%s\0";
    unsafe {
        __android_log_print(
            ANDROID_LOG_DEBUG,
            TAG.as_ptr().cast(),
            FORMAT.as_ptr().cast(),
            message.as_ptr(),
        );
    }
}

#[cfg(not(target_os = "android"))]
pub fn emit(_event: &str, _args: Arguments<'_>) {}

#[cfg(target_os = "android")]
const ANDROID_LOG_DEBUG: i32 = 3;

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_print(
        priority: i32,
        tag: *const core::ffi::c_char,
        format: *const core::ffi::c_char,
        ...
    ) -> i32;
}

#[macro_export]
macro_rules! espframe_log {
    ($event:expr) => {{
        $crate::debug_log::emit($event, format_args!(""))
    }};
    ($event:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $crate::debug_log::emit($event, format_args!($fmt $(, $arg)*))
    }};
}

/// Compatibility alias for existing UamEdge consumers.
#[macro_export]
macro_rules! uam_inject_log {
    ($($args:tt)*) => { $crate::espframe_log!($($args)*) };
}

/// Compatibility alias for existing DeltaEdge consumers.
#[macro_export]
macro_rules! delta_inject_log {
    ($($args:tt)*) => { $crate::espframe_log!($($args)*) };
}

#[cfg(test)]
mod tests {
    use super::{log_setting, should_log_memory_call};

    #[test]
    fn shared_log_setting_can_disable_enabled_legacy_settings() {
        assert_eq!(log_setting(Some("0"), Some("1"), Some("1")), Some("0"));
        assert_eq!(log_setting(Some(""), Some("1"), Some("1")), Some(""));
        assert_eq!(log_setting(None, Some("0"), Some("1")), Some("0"));
        assert_eq!(log_setting(None, None, Some("1")), Some("1"));
        assert_eq!(log_setting(None, None, None), None);
    }

    #[test]
    fn both_legacy_macros_accept_the_existing_call_forms() {
        crate::uam_inject_log!("compat.uam");
        crate::delta_inject_log!("compat.delta", "value={}", 1);
        crate::espframe_log!("compat.shared", "value={}", 1,);
    }

    #[test]
    fn complete_memory_calls_require_explicit_trace() {
        assert!(!should_log_memory_call(true, false, 8, 8));
        assert!(should_log_memory_call(true, true, 8, 8));
    }

    #[test]
    fn memory_failures_and_short_reads_keep_native_diagnostics() {
        for result in [-1, 0, 4, 16] {
            assert!(should_log_memory_call(true, false, 8, result));
        }
        assert!(should_log_memory_call(true, false, u64::MAX, -1));
    }

    #[test]
    fn native_master_switch_disables_all_memory_logs() {
        for trace in [false, true] {
            for result in [-1, 0, 4, 8] {
                assert!(!should_log_memory_call(false, trace, 8, result));
            }
        }
    }
}
