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
        assert_eq!(args[0], 0);
        assert_eq!(scno, 123);
        assert_eq!(option, 456);
        assert_eq!(&args[4..], &[0; 1]);
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
        original_entry: &[1, 2, 3, 4],
        replacement_entry: &[5, 6, 7, 8],
    }
}

#[test]
fn register_contract_set_starts_with_flags_without_version() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_NET_SPOOF_SET);
            assert_eq!(&args[2..], &[0; 3]);
            let words = unsafe { std::slice::from_raw_parts(args[1] as *const u32, 6) };
            assert_eq!(words, &[0, 0x11223344, 0x55667788, 7, 0, 0]);
            0
        }),
    );
    assert_eq!(driver.UamNetSet(&config()), Ok(()));
}

#[test]
fn register_contract_stop_passes_type_and_crc_directly() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_NET_SPOOF_STOP);
            assert_eq!(args, [0, 0x11223344, 0, 0, 0]);
            0
        }),
    );
    assert_eq!(driver.UamNetStop(0x11223344), Ok(()));
}

#[test]
fn register_contract_read_passes_type_and_three_arguments_and_returns_count() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_NET_SPOOF_READ);
            assert_eq!(args[2], 2);
            assert_ne!(args[1], 0);
            assert_ne!(args[3], 0);
            unsafe {
                (args[1] as *mut RsaRedirectResult).write(RsaRedirectResult {
                    sequence: 42,
                    ..Default::default()
                });
                (args[3] as *mut u64).write(9);
            }
            1
        }),
    );
    let mut records = [RsaRedirectResult::default(); 2];
    assert_eq!(
        driver.UamNetRead(&mut records).unwrap(),
        RsaRedirectReadStats {
            count: 1,
            dropped: 9
        }
    );
    assert_eq!(records[0].sequence, 42);
    assert_eq!(records[1].sequence, 0);
}

#[test]
fn register_contract_stats_starts_with_profile_count_without_version() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_NET_SPOOF_STATS);
            assert_eq!(&args[2..], &[0; 3]);
            unsafe {
                (args[1] as *mut u32).write(2);
            }
            0
        }),
    );
    assert_eq!(driver.UamNetStats().unwrap().profiles, 2);
}

#[test]
fn register_contract_result_contains_only_consumer_fields() {
    assert_eq!(size_of::<RsaRedirectResult>(), 80);
    assert_eq!(offset_of!(RsaRedirectResult, pid), 16);
    assert_eq!(offset_of!(RsaRedirectResult, remote_addr), 20);
    assert_eq!(offset_of!(RsaRedirectResult, key), 36);
    assert_eq!(offset_of!(RsaRedirectResult, nonce), 68);
}

#[test]
fn wire_layout_matches_kernel_call_contract() {
    assert_eq!(size_of::<RsaRedirectSetRequest>(), 72);
    assert_eq!(align_of::<RsaRedirectSetRequest>(), 8);
    assert_eq!(offset_of!(RsaRedirectSetRequest, flags), 0);
    assert_eq!(offset_of!(RsaRedirectSetRequest, expected_crc), 4);
    assert_eq!(offset_of!(RsaRedirectSetRequest, original_crc), 8);
    assert_eq!(offset_of!(RsaRedirectSetRequest, key_id), 12);
    assert_eq!(offset_of!(RsaRedirectSetRequest, capture_pid), 16);
    assert_eq!(offset_of!(RsaRedirectSetRequest, entry_len), 20);
    assert_eq!(offset_of!(RsaRedirectSetRequest, private_der), 24);
    assert_eq!(offset_of!(RsaRedirectSetRequest, public_der), 32);
    assert_eq!(offset_of!(RsaRedirectSetRequest, original_entry), 40);
    assert_eq!(offset_of!(RsaRedirectSetRequest, replacement_entry), 48);
    assert_eq!(offset_of!(RsaRedirectSetRequest, private_der_len), 56);
    assert_eq!(offset_of!(RsaRedirectSetRequest, public_der_len), 60);
    assert_eq!(offset_of!(RsaRedirectSetRequest, reserved), 64);
    assert_eq!(size_of::<RsaRedirectResult>(), 80);
    assert_eq!(align_of::<RsaRedirectResult>(), 8);
    assert_eq!(offset_of!(RsaRedirectResult, remote_addr), 20);
    assert_eq!(offset_of!(RsaRedirectResult, key), 36);
    assert_eq!(offset_of!(RsaRedirectResult, nonce), 68);
    assert_eq!(size_of::<RsaRedirectStats>(), 64);
    assert_eq!(offset_of!(RsaRedirectStats, profiles), 0);
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
            let request = unsafe { &*(args[1] as *const RsaRedirectSetRequest) };
            assert_eq!(request.flags, 1);
            assert_eq!(request.expected_crc, 0x11223344);
            assert_eq!(request.original_crc, 0x55667788);
            assert_eq!(request.key_id, 7);
            assert_eq!(request.capture_pid, 0);
            assert_eq!(request.entry_len, 4);
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
    assert_eq!(driver.UamNetSet(&config), Ok(()));
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
            let request = unsafe { &*(args[1] as *const RsaRedirectSetRequest) };
            assert_eq!(request.capture_pid, 234);
            assert_eq!(request.flags, 0);
            assert_eq!(request.entry_len, 0);
            assert_eq!(request.original_entry, 0);
            assert_eq!(request.replacement_entry, 0);
            0
        }),
    );
    let config = RsaRedirectConfig {
        capture_pid: 234,
        ..config()
    };
    assert_eq!(driver.UamNetSet(&config), Ok(()));
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
    ];
    for config in invalid {
        assert_eq!(driver.UamNetSet(&config), Err(-22));
    }
}

#[test]
fn file_patterns_accept_minimum_and_maximum_lengths_without_a_location() {
    let original = [0x12; 4096];
    let replacement = [0x34; 4096];
    for length in [1, 4096] {
        let driver = KernelDriver::new(
            123,
            456,
            0,
            Transport(|command, args: [usize; 5]| {
                assert_eq!(command, CMD_NET_SPOOF_SET);
                let request = unsafe { &*(args[1] as *const RsaRedirectSetRequest) };
                assert_eq!(request.flags, 1);
                assert_eq!(request.entry_len, length as u32);
                assert_eq!(request.original_entry, original.as_ptr() as u64);
                assert_eq!(request.replacement_entry, replacement.as_ptr() as u64);
                0
            }),
        );
        let config = RsaRedirectConfig {
            file: Some(RsaRedirectFile {
                original_entry: &original[..length],
                replacement_entry: &replacement[..length],
            }),
            ..config()
        };
        assert_eq!(driver.UamNetSet(&config), Ok(()));
    }
}

#[test]
fn delete_selects_profile_by_crc() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003e);
            assert_eq!(args, [0, 0x11223344, 0, 0, 0]);
            0
        }),
    );
    assert_eq!(driver.UamNetStop(0x11223344), Ok(()));
}

#[test]
fn read_returns_key_nonce_identity_and_overflow_and_caps_batch_size() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x1003f);
            assert_eq!(args[2], 16);
            assert_ne!(args[3], 0);
            unsafe {
                (args[1] as *mut RsaRedirectResult).write(RsaRedirectResult {
                    sequence: 10,
                    pid: 234,
                    key: [0x42; 32],
                    nonce: [0x24; 8],
                    remote_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 20, 30, 40],
                    ..Default::default()
                });
            }
            unsafe {
                (args[3] as *mut u64).write(7);
            }
            1
        }),
    );
    let mut records = [RsaRedirectResult::default(); 20];
    let stats = driver.UamNetRead(&mut records).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.dropped, 7);
    assert_eq!(records[0].key, [0x42; 32]);
    assert_eq!(records[0].nonce, [0x24; 8]);
    assert_eq!(records[0].pid, 234);
    assert_eq!(records[0].sequence, 10);
    assert_eq!(
        records[0].remote_addr,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 20, 30, 40]
    );
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
            assert_eq!(args[2], 1);
            unsafe {
                (args[3] as *mut u64).write(0);
            }
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.UamNetRead(&mut []).unwrap_err(), -22);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let mut records = [RsaRedirectResult::default(); 1];
    assert_eq!(driver.UamNetRead(&mut records).unwrap().count, 0);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn read_rejects_counts_exceeding_the_supplied_buffer() {
    for count in [2, isize::MAX] {
        let driver = KernelDriver::new(123, 456, 0, Transport(|_, _: [usize; 5]| count));
        let mut records = [RsaRedirectResult::default(); 1];
        assert_eq!(driver.UamNetRead(&mut records).unwrap_err(), -71);
    }
}

#[test]
fn stats_returns_counters_without_version_negotiation() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x10040);
            let stats = unsafe { &mut *(args[1] as *mut RsaRedirectStats) };
            stats.profiles = 2;
            stats.rewrapped = 11;
            stats.rewritten_reads = 12;
            stats.captured = 13;
            stats.dropped = 14;
            0
        }),
    );
    let stats = driver.UamNetStats().unwrap();
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
}

#[test]
fn all_commands_preserve_negative_errors() {
    for result in [-1, -14, -17, -22, -28, -38] {
        let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| result));
        let expected = result;
        let mut records = [RsaRedirectResult::default(); 1];
        assert_eq!(driver.UamNetSet(&config()), Err(expected));
        assert_eq!(driver.UamNetStop(0x11223344), Err(expected));
        assert_eq!(driver.UamNetRead(&mut records).unwrap_err(), expected);
        assert_eq!(driver.UamNetStats().unwrap_err(), expected);
    }
}

#[test]
fn status_commands_reject_positive_status_but_read_accepts_count() {
    let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| 1));
    assert_eq!(driver.UamNetSet(&config()), Err(-71));
    assert_eq!(driver.UamNetStop(0x11223344), Err(-71));
    assert_eq!(driver.UamNetStats().unwrap_err(), -71);
    let mut records = [RsaRedirectResult::default(); 1];
    assert_eq!(driver.UamNetRead(&mut records).unwrap().count, 1);
}
