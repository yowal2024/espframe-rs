use espframe::kernel::abi::*;
use espframe::kernel::{KernelDriver, KernelTransport, RsaRedirectConfig, RsaRedirectFile};
use std::mem::{align_of, offset_of, size_of};
use std::sync::atomic::{AtomicUsize, Ordering};

// Exercise the real driver across its syscall boundary, without a live module.
struct Transport<F>(F);

impl<F> KernelTransport for Transport<F>
where
    F: Fn(usize, [usize; 5]) -> isize + Send + Sync,
{
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!(scno, 123);
        assert_eq!(option, 456);
        assert_eq!(&args[1..], &[0; 4]);
        (self.0)(command, args)
    }
}

fn config() -> RsaRedirectConfig<'static> {
    RsaRedirectConfig {
        expected_crc: 0x11223344,
        original_crc: 0x55667788,
        key_id: 7,
        private_der: &[0x30, 0x11, 0x22],
        public_der: &[0x30, 0x33],
        ..Default::default()
    }
}

fn file() -> RsaRedirectFile<'static> {
    RsaRedirectFile {
        entry_offset: 4093,
        original_entry: &[1, 2, 3, 4],
        replacement_entry: &[5, 6, 7, 8],
    }
}

#[test]
fn wire_layout_matches_kernel_abi_v3() {
    assert_eq!(RSA_REDIRECT_ABI_VERSION, 3);
    assert_eq!(size_of::<RsaRedirectSetRequest>(), 88);
    assert_eq!(align_of::<RsaRedirectSetRequest>(), 8);
    assert_eq!(offset_of!(RsaRedirectSetRequest, capture_pid), 20);
    assert_eq!(offset_of!(RsaRedirectSetRequest, entry_len), 24);
    assert_eq!(offset_of!(RsaRedirectSetRequest, entry_offset), 32);
    assert_eq!(offset_of!(RsaRedirectSetRequest, private_der), 40);
    assert_eq!(offset_of!(RsaRedirectSetRequest, public_der), 48);
    assert_eq!(offset_of!(RsaRedirectSetRequest, original_entry), 56);
    assert_eq!(offset_of!(RsaRedirectSetRequest, replacement_entry), 64);
    assert_eq!(offset_of!(RsaRedirectSetRequest, private_der_len), 72);
    assert_eq!(offset_of!(RsaRedirectSetRequest, public_der_len), 76);
    assert_eq!(offset_of!(RsaRedirectSetRequest, reserved), 80);
    assert_eq!(size_of::<RsaRedirectDeleteRequest>(), 16);
    assert_eq!(size_of::<RsaRedirectReadRequest>(), 32);
    assert_eq!(offset_of!(RsaRedirectReadRequest, records), 8);
    assert_eq!(offset_of!(RsaRedirectReadRequest, dropped), 24);
    assert_eq!(size_of::<RsaRedirectResult>(), 120);
    assert_eq!(align_of::<RsaRedirectResult>(), 8);
    assert_eq!(offset_of!(RsaRedirectResult, local_addr), 48);
    assert_eq!(offset_of!(RsaRedirectResult, key), 80);
    assert_eq!(offset_of!(RsaRedirectResult, nonce), 112);
    assert_eq!(size_of::<RsaRedirectStats>(), 64);
    assert_eq!(offset_of!(RsaRedirectStats, dropped), 56);
}

#[test]
fn set_borrows_buffers_and_registers_before_a_target_pid_exists() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003d);
            let request = unsafe { &*(args[0] as *const RsaRedirectSetRequest) };
            assert_eq!(request.abi_version, 3);
            assert_eq!(request.flags, 1);
            assert_eq!(request.expected_crc, 0x11223344);
            assert_eq!(request.original_crc, 0x55667788);
            assert_eq!(request.key_id, 7);
            assert_eq!(request.capture_pid, 0);
            assert_eq!(request.entry_len, 4);
            assert_eq!(request.entry_offset, 4093);
            assert_eq!(request.reserved, [0; 2]);
            unsafe {
                assert_eq!(
                    std::slice::from_raw_parts(
                        request.private_der as *const u8,
                        request.private_der_len as usize
                    ),
                    &[0x30, 0x11, 0x22]
                );
                assert_eq!(
                    std::slice::from_raw_parts(
                        request.public_der as *const u8,
                        request.public_der_len as usize
                    ),
                    &[0x30, 0x33]
                );
                assert_eq!(
                    std::slice::from_raw_parts(request.original_entry as *const u8, 4),
                    &[1, 2, 3, 4]
                );
                assert_eq!(
                    std::slice::from_raw_parts(request.replacement_entry as *const u8, 4),
                    &[5, 6, 7, 8]
                );
            }
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    let config = RsaRedirectConfig {
        file: Some(file()),
        ..config()
    };
    assert_eq!(driver.RsaRedirectSet(&config), Ok(()));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn rewrap_only_zeros_file_fields_and_uses_only_explicit_capture_pid() {
    let driver = KernelDriver::new(
        123,
        456,
        999,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003d);
            let request = unsafe { &*(args[0] as *const RsaRedirectSetRequest) };
            assert_eq!(request.capture_pid, 234);
            assert_eq!(request.flags, 0);
            assert_eq!(request.entry_len, 0);
            assert_eq!(request.entry_offset, 0);
            assert_eq!(request.original_entry, 0);
            assert_eq!(request.replacement_entry, 0);
            0
        }),
    );
    let config = RsaRedirectConfig {
        capture_pid: 234,
        ..config()
    };
    assert_eq!(driver.RsaRedirectSet(&config), Ok(()));
}

#[test]
fn invalid_configs_are_rejected_before_invoking_the_kernel() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid request reached kernel")),
    );
    let private_too_long = [0u8; 2049];
    let public_too_long = [0u8; 513];
    let entry_too_long = [0u8; 4097];
    let invalid = [
        RsaRedirectConfig {
            capture_pid: -1,
            ..config()
        },
        RsaRedirectConfig {
            capture_pid: 1,
            ..config()
        },
        RsaRedirectConfig {
            original_crc: 0x11223344,
            ..config()
        },
        RsaRedirectConfig {
            private_der: &[],
            ..config()
        },
        RsaRedirectConfig {
            public_der: &[],
            ..config()
        },
        RsaRedirectConfig {
            private_der: &private_too_long,
            ..config()
        },
        RsaRedirectConfig {
            public_der: &public_too_long,
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                replacement_entry: &[1],
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                original_entry: &[],
                replacement_entry: &[],
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                original_entry: &entry_too_long,
                replacement_entry: &entry_too_long,
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                entry_offset: i64::MAX as u64,
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                entry_offset: i64::MAX as u64 + 1,
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                entry_offset: i64::MAX as u64 - 3,
                ..file()
            }),
            ..config()
        },
        RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                entry_offset: u64::MAX,
                ..file()
            }),
            ..config()
        },
    ];
    for config in invalid {
        assert_eq!(driver.RsaRedirectSet(&config), Err(-22));
    }
}

#[test]
fn file_range_can_end_at_largest_signed_file_offset() {
    let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| 0));
    let config = RsaRedirectConfig {
        file: Some(RsaRedirectFile {
            entry_offset: i64::MAX as u64 - 4,
            ..file()
        }),
        ..config()
    };
    assert_eq!(driver.RsaRedirectSet(&config), Ok(()));
}

#[test]
fn delete_selects_profile_by_crc_with_current_abi() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003e);
            let request = unsafe { &*(args[0] as *const RsaRedirectDeleteRequest) };
            assert_eq!(request.abi_version, 3);
            assert_eq!(request.expected_crc, 0x11223344);
            assert_eq!(request.reserved, [0; 2]);
            0
        }),
    );
    assert_eq!(driver.RsaRedirectDel(0x11223344), Ok(()));
}

#[test]
fn read_returns_key_nonce_identity_and_overflow_and_caps_batch_size() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003f);
            let request = unsafe { &mut *(args[0] as *mut RsaRedirectReadRequest) };
            assert_eq!(request.abi_version, 3);
            assert_eq!(request.max_count, 16);
            assert_eq!(request.reserved, 0);
            unsafe {
                (request.records as *mut RsaRedirectResult).write(RsaRedirectResult {
                    sequence: 10,
                    uid: 12345,
                    pid: 234,
                    tid: 235,
                    expected_crc: 0x11223344,
                    original_crc: 0x55667788,
                    key: [0x42; 32],
                    nonce: [0x24; 8],
                    family: 2,
                    local_port: 1234,
                    remote_port: 5678,
                    ..Default::default()
                });
            }
            request.out_count = 1;
            request.dropped = 7;
            0
        }),
    );
    let mut records = [RsaRedirectResult::default(); 20];
    let stats = driver.RsaRedirectRead(&mut records).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.dropped, 7);
    assert_eq!(records[0].key, [0x42; 32]);
    assert_eq!(records[0].nonce, [0x24; 8]);
    assert_eq!(records[0].uid, 12345);
    assert_eq!(records[0].pid, 234);
    assert_eq!(records[0].sequence, 10);
    assert_eq!(records[0].remote_port, 5678);
    assert_eq!(records[1].sequence, 0);
}

#[test]
fn read_accepts_an_empty_queue_and_rejects_an_empty_buffer() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, args: [usize; 5]| {
            let request = unsafe { &mut *(args[0] as *mut RsaRedirectReadRequest) };
            assert_eq!(request.max_count, 1);
            request.out_count = 0;
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.RsaRedirectRead(&mut []).unwrap_err(), -22);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let mut records = [RsaRedirectResult::default(); 1];
    assert_eq!(driver.RsaRedirectRead(&mut records).unwrap().count, 0);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn read_rejects_oversized_wrong_version_reserved_and_unwritten_replies() {
    for mode in 0..4 {
        let driver = KernelDriver::new(
            123,
            456,
            0,
            Transport(|_, args: [usize; 5]| {
                let request = unsafe { &mut *(args[0] as *mut RsaRedirectReadRequest) };
                match mode {
                    0 => request.out_count = 2,
                    1 => {
                        request.out_count = 0;
                        request.abi_version = 2;
                    }
                    2 => {
                        request.out_count = 0;
                        request.reserved = 1;
                    }
                    _ => {} // An old module did not write anything back.
                }
                0
            }),
        );
        let mut records = [RsaRedirectResult::default(); 1];
        assert_eq!(driver.RsaRedirectRead(&mut records).unwrap_err(), -71);
    }
}

#[test]
fn stats_returns_versioned_counters_and_rejects_old_or_unwritten_replies() {
    for version in [0, 1, 2, 3] {
        let driver = KernelDriver::new(
            123,
            456,
            0,
            Transport(|command, args: [usize; 5]| {
                assert_eq!(command, 0x10040);
                let stats = unsafe { &mut *(args[0] as *mut RsaRedirectStats) };
                stats.abi_version = version;
                stats.profiles = 2;
                stats.rewrapped = 11;
                stats.rewritten_reads = 12;
                stats.captured = 13;
                stats.dropped = 14;
                0
            }),
        );
        let result = driver.RsaRedirectStats();
        if version == 3 {
            let stats = result.unwrap();
            assert_eq!(
                (
                    stats.profiles,
                    stats.rewrapped,
                    stats.rewritten_reads,
                    stats.captured,
                    stats.dropped
                ),
                (2, 11, 12, 13, 14)
            );
        } else {
            assert_eq!(result.unwrap_err(), -71);
        }
    }
}

#[test]
fn all_commands_preserve_negative_errors_and_reject_positive_status() {
    for result in [-1, -14, -17, -22, -28, -38, 1] {
        let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| result));
        let expected = if result > 0 { -71 } else { result };
        let mut records = [RsaRedirectResult::default(); 1];
        assert_eq!(driver.RsaRedirectSet(&config()), Err(expected));
        assert_eq!(driver.RsaRedirectDel(0x11223344), Err(expected));
        assert_eq!(driver.RsaRedirectRead(&mut records).unwrap_err(), expected);
        assert_eq!(driver.RsaRedirectStats().unwrap_err(), expected);
    }
}
