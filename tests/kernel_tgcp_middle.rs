use espframe::kernel::abi::*;
use espframe::kernel::{KernelDriver, KernelTransport};
use std::mem::{align_of, offset_of, size_of};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!((scno, option), (123, 456));
        if !matches!(command, CMD_TGCP_MIDDLE_READ | CMD_TGCP_MIDDLE_SET) {
            assert_eq!(&args[1..], &[0; 4]);
        }
        (self.0)(command, args)
    }
}

#[test]
fn uid_set_does_not_require_a_target_process() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, _| {
            assert_eq!(command, CMD_TGCP_MIDDLE_SET);
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.TgcpMiddleSet(&[23], 5), Ok(()));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn uid_running_stats_does_not_require_a_live_target_process() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_TGCP_MIDDLE_STATS);
            let stats = unsafe { &mut *(args[0] as *mut TgcpMiddleStats) };
            stats.status = TGCP_MIDDLE_STATUS_RUNNING;
            stats.session_id = 7;
            0
        }),
    );
    assert!(driver.TgcpMiddleStats().is_ok());
}

fn ready() -> TgcpMiddleEvent {
    let mut value = TgcpMiddleEvent::default();
    value.seq = 1;
    value.session_id = 7;
    value.socket_id = 81;
    value.ts_ns = 1_000;
    value.target_pid = 42;
    value.sock_uid = 12345;
    value.family = 2;
    value.event_type = 1;
    value.local_port = 34123;
    value.remote_port = 18081;
    value.local_addr[12..].copy_from_slice(&[10, 24, 0, 1]);
    value.remote_addr[12..].copy_from_slice(&[10, 24, 0, 2]);
    value.local_addr[10..12].fill(0xff);
    value.remote_addr[10..12].fill(0xff);
    value.kc = [0x11; 16];
    value.key_mode = 3;
    value
}

#[test]
fn unified_direct_call_layout_and_compacted_command_sequence_match_c() {
    assert_eq!(size_of::<TgcpMiddleStats>(), 56);
    assert_eq!(offset_of!(TgcpMiddleStats, session_id), 8);
    assert_eq!(offset_of!(TgcpMiddleStats, recv_hits), 48);
    assert_eq!(size_of::<TgcpMiddleEvent>(), 4216);
    assert_eq!(align_of::<TgcpMiddleEvent>(), 8);
    assert_eq!(offset_of!(TgcpMiddleEvent, kc), 80);
    assert_eq!(offset_of!(TgcpMiddleEvent, key_mode), 100);
    assert_eq!(offset_of!(TgcpMiddleEvent, stream_offset), 104);
    assert_eq!(offset_of!(TgcpMiddleEvent, payload), 120);
    assert_eq!(CMD_UDP_CAP_INIT, 0x10039);
    assert_eq!(CMD_GYRO_EVENT_CONFIGURE, 0x1003c);
    assert_eq!(CMD_NET_SPOOF_SET, 0x1003d);
    assert_eq!(CMD_NET_SPOOF_STATS, 0x10040);
    assert_eq!(CMD_TGCP_MIDDLE_SET, 0x10042);
    assert_eq!(CMD_TGCP_MIDDLE_STOP, 0x10043);
    assert_eq!(CMD_TGCP_MIDDLE_READ, 0x10044);
    assert_eq!(CMD_TGCP_MIDDLE_STATS, 0x10045);
}

#[test]
fn set_passes_only_borrowed_prime_length_and_generator_directly() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        999,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x10042);
            assert_eq!(&args[1..], &[1, 5, 0, 0]);
            let prime = unsafe { std::slice::from_raw_parts(args[0] as *const u8, args[1]) };
            assert_eq!(prime, [23]);
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.TgcpMiddleSet(&[23], 5), Ok(()));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn missing_or_oversized_prime_is_rejected_before_syscall() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid config invoked kernel")),
    );
    for prime in [vec![], vec![23; 65]] {
        assert_eq!(driver.TgcpMiddleSet(&prime, 5), Err(-22));
    }
}

#[test]
fn read_preserves_response_mode_and_client_side_data_in_one_ordered_batch() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x10044);
            assert_eq!((args[1], args[4]), (16, 0));
            let out = unsafe { std::slice::from_raw_parts_mut(args[0] as *mut TgcpMiddleEvent, 2) };
            out[0] = ready();
            out[0].key_mode = 2;
            out[1] = ready();
            out[1].seq = 2;
            out[1].event_type = 4;
            out[1].kc = [0; 16];
            out[1].key_mode = 0;
            out[1].payload_len = 3;
            out[1].flags = 3;
            out[1].payload[..3].copy_from_slice(b"abc");
            unsafe {
                *(args[3] as *mut u64) = 7;
                *(args[2] as *mut u64) = 4;
            }
            2
        }),
    );
    let mut records = vec![TgcpMiddleEvent::default(); 18];
    let got = driver.TgcpMiddleRead(&mut records).unwrap();
    assert_eq!((got.count, got.session_id, got.dropped), (2, 7, 4));
    assert_eq!(records[0].kc, [0x11; 16]);
    assert_eq!(records[0].key_mode, 2);
    assert_eq!(&records[1].payload[..3], b"abc");
}

#[test]
fn malformed_kernel_records_are_rejected_and_secret_buffers_cleared() {
    for variant in 0..14 {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |_, args: [usize; 5]| {
                unsafe {
                    *(args[3] as *mut u64) = 7;
                }
                let mut count = 1;
                let out = unsafe { &mut *(args[0] as *mut TgcpMiddleEvent) };
                *out = ready();
                match variant {
                    0 => count = 17,
                    1 => unsafe {
                        *(args[3] as *mut u64) = 0;
                    },
                    2 => out.session_id = 8,
                    3 => out.socket_id = 0,
                    4 => out.event_type = 99,
                    5 => out.key_mode = 1,
                    6 => out.family = 10,
                    7 => out.remote_addr[10] = 0,
                    8 => out.payload_len = 4097,
                    9 => out.event_type = 4, // DATA must never carry READY's key bytes.
                    10 => {
                        out.event_type = 4;
                        out.kc = [0; 16];
                        out.key_mode = 0;
                        out.payload_len = 1;
                        out.stream_offset = u64::MAX;
                    }
                    11 => out.seq = 0,
                    12 => out.sock_uid = 0,
                    _ => out.sock_uid = 32768,
                }
                count
            }),
        );
        let mut records = vec![TgcpMiddleEvent::default(); 16];
        assert!(
            matches!(driver.TgcpMiddleRead(&mut records), Err(-71)),
            "variant {variant}"
        );
        assert!(records.iter().all(|r| r.kc == [0; 16] && r.key_mode == 0));
    }
}

#[test]
fn unsupported_kernel_and_stop_propagate_without_invoking_udp() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, _| {
            assert!(matches!(command, 0x10042..=0x10045));
            -38
        }),
    );
    assert_eq!(driver.TgcpMiddleSet(&[23], 5), Err(-38));
    assert!(matches!(
        driver.TgcpMiddleRead(&mut [TgcpMiddleEvent::default()]),
        Err(-38)
    ));
    assert!(matches!(driver.TgcpMiddleStats(), Err(-38)));
    assert_eq!(driver.TgcpMiddleStop(), Err(-38));
}

#[test]
fn invalid_dh_encoding_and_generator_ranges_are_rejected_before_syscall() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|_, _| panic!("invalid DH invoked kernel")),
    );
    for (prime, generator) in [
        (vec![0], 5),
        (vec![0, 23], 5),
        (vec![22], 5),
        (vec![3], 2),
        (vec![23], 0),
        (vec![23], 1),
        (vec![23], 22),
        (vec![23], 23),
    ] {
        assert_eq!(driver.TgcpMiddleSet(&prime, generator), Err(-22));
    }
}

#[test]
fn dh_range_boundaries_support_short_and_large_explicit_groups_without_primality_claim() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, _| {
            assert_eq!(command, CMD_TGCP_MIDDLE_SET);
            0
        }),
    );
    for (prime, generator, valid) in [
        (vec![5], 2, true),
        (vec![5], 3, true),
        (vec![5], 4, false),
        (vec![9], 2, true), // Encoding/range validation does not prove primality.
        (vec![0xff; 4], u32::MAX - 2, true),
        (vec![0xff; 4], u32::MAX - 1, false),
        (vec![1, 0, 0, 0, 0], u32::MAX, false),
        (vec![1, 0, 0, 0, 1], u32::MAX, true),
        (vec![1, 0, 0, 0, 3], u32::MAX, true),
        (
            {
                let mut p = vec![0; 64];
                p[0] = 1;
                p[63] = 5;
                p
            },
            7,
            true,
        ),
    ] {
        assert_eq!(
            driver.TgcpMiddleSet(&prime, generator),
            if valid { Ok(()) } else { Err(-22) }
        );
    }
}

#[test]
fn stats_is_output_only_with_zero_padding_and_accepts_real_status_bits() {
    for (status, session) in [(0, 0), (0, 7), (1, 7)] {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |command, args: [usize; 5]| {
                assert_eq!(command, CMD_TGCP_MIDDLE_STATS);
                let stats = unsafe { &mut *(args[0] as *mut TgcpMiddleStats) };
                assert_eq!(stats.padding, 0);
                stats.status = status;
                stats.session_id = session;
                0
            }),
        );
        let got = driver.TgcpMiddleStats().unwrap();
        assert_eq!((got.status, got.session_id), (status, session));
    }
}

#[test]
fn stats_rejects_unknown_or_inconsistent_status_bits() {
    for (status, session, padding) in [(2, 7, 0), (4, 7, 0), (1, 0, 0), (3, 7, 0), (1, 7, 1)] {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |_, args: [usize; 5]| {
                let stats = unsafe { &mut *(args[0] as *mut TgcpMiddleStats) };
                stats.status = status;
                stats.session_id = session;
                stats.padding = padding;
                0
            }),
        );
        assert_eq!(driver.TgcpMiddleStats(), Err(-71));
    }
}
