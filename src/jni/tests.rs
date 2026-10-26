use super::{NativeRegistration, JNI_VERSION};
use std::cell::Cell;

#[test]
fn vm_discovery_distinguishes_no_vm_from_failed_or_invalid_results() {
    use super::validate_created_vm;
    use jni::sys;

    let absent = std::ptr::null_mut();
    let mut vm_table: sys::JavaVM = std::ptr::null();
    let present = &mut vm_table as *mut sys::JavaVM;
    assert_eq!(validate_created_vm(sys::JNI_OK, 0, absent).unwrap(), absent);
    assert_eq!(validate_created_vm(sys::JNI_OK, 1, present).unwrap(), present);
    for (status, count, pointer) in [
        (sys::JNI_ERR, 0, absent),
        (sys::JNI_OK, 1, absent),
        (sys::JNI_OK, -1, absent),
        (sys::JNI_OK, 2, present),
        (sys::JNI_OK, 0, present),
    ] {
        assert!(validate_created_vm(status, count, pointer).is_err());
    }
}

#[test]
fn registration_short_circuits_after_success() {
    let registration = NativeRegistration::new();
    let calls = Cell::new(0);
    assert_eq!(
        registration
            .register_with(|| {
                calls.set(calls.get() + 1);
                Ok(JNI_VERSION)
            })
            .unwrap(),
        JNI_VERSION
    );
    assert_eq!(
        registration
            .register_with(|| panic!("already registered"))
            .unwrap(),
        JNI_VERSION
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn registration_retries_after_failure() {
    let registration = NativeRegistration::new();
    let calls = Cell::new(0);
    let failed = registration.register_with(|| {
        calls.set(calls.get() + 1);
        Err(jni::errors::Error::NullPtr("registration failed"))
    });
    assert!(failed.is_err());
    assert_eq!(
        registration
            .register_with(|| {
                calls.set(calls.get() + 1);
                Ok(JNI_VERSION)
            })
            .unwrap(),
        JNI_VERSION
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn successful_registration_does_not_skip_another_instance() {
    let first = NativeRegistration::new();
    let second = NativeRegistration::new();
    let calls = Cell::new(0);
    for registration in [&first, &second] {
        assert_eq!(
            registration
                .register_with(|| {
                    calls.set(calls.get() + 1);
                    Ok(JNI_VERSION)
                })
                .unwrap(),
            JNI_VERSION
        );
    }
    assert_eq!(calls.get(), 2);
}

#[test]
fn registration_contains_panics_and_allows_retry() {
    let registration = NativeRegistration::new();
    assert!(registration
        .register_with(|| panic!("registration panic"))
        .is_err());
    assert_eq!(
        registration.register_with(|| Ok(JNI_VERSION)).unwrap(),
        JNI_VERSION
    );
}

#[test]
fn null_vm_is_rejected_even_after_cached_success() {
    let registration = NativeRegistration::new();
    registration.register_with(|| Ok(JNI_VERSION)).unwrap();
    assert!(
        unsafe { registration.register(std::ptr::null_mut(), "example/Natives", &[]) }.is_err()
    );
}

#[test]
fn concurrent_registration_runs_once() {
    let registration = NativeRegistration::new();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                registration
                    .register_with(|| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(JNI_VERSION)
                    })
                    .unwrap();
            });
        }
    });
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}
