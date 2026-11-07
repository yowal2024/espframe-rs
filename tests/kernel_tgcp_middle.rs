use espframe::kernel::abi::*;
use espframe::kernel::{KernelDriver, KernelTransport};
use std::mem::{align_of, offset_of, size_of};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!((scno, option), (123, 456));
        assert_eq!(&args[1..], &[0; 4]);
        (self.0)(command, args)
    }
}

fn config() -> TgcpMiddleConfig {
    let mut prime = [0; 64];
    prime[0] = 23;
    TgcpMiddleConfig {
        abi_version: 2,
        pid: 42,
        family: 2,
        remote_port: 0,
        flags: 1,
        remote_addr: [0; 16],
        prime_len: 1,
        generator: 5,
        prime,
        reserved: [0; 2],
    }
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
    value.local_addr[..4].copy_from_slice(&[10, 24, 0, 1]);
    value.remote_addr[..4].copy_from_slice(&[10, 24, 0, 2]);
    value.kc = [0x11; 16];
    value.ks = [0x22; 16];
    value
}

#[test]
fn unified_abi2_layout_and_compacted_command_sequence_match_c() {
    assert_eq!(TGCP_MIDDLE_ABI_VERSION, 2);
    assert_eq!(size_of::<TgcpMiddleConfig>(), 112);
    assert_eq!(offset_of!(TgcpMiddleConfig, prime_len), 32);
    assert_eq!(offset_of!(TgcpMiddleConfig, generator), 36);
    assert_eq!(offset_of!(TgcpMiddleConfig, prime), 40);
    assert_eq!(offset_of!(TgcpMiddleConfig, reserved), 104);
    assert_eq!(size_of::<TgcpMiddleReadRequest>(), 40);
    assert_eq!(size_of::<TgcpMiddleStats>(), 64);
    assert_eq!(size_of::<TgcpMiddleEvent>(), 4232);
    assert_eq!(align_of::<TgcpMiddleEvent>(), 8);
    assert_eq!(offset_of!(TgcpMiddleEvent, kc), 80);
    assert_eq!(offset_of!(TgcpMiddleEvent, ks), 96);
    assert_eq!(offset_of!(TgcpMiddleEvent, stream_offset), 120);
    assert_eq!(offset_of!(TgcpMiddleEvent, payload), 136);
    assert_eq!(CMD_UDP_CAP_INIT, 0x10039);
    assert_eq!(CMD_GYRO_EVENT_CONFIGURE, 0x1003c);
    assert_eq!(CMD_RSA_REDIRECT_SET, 0x1003d);
    assert_eq!(CMD_RSA_REDIRECT_STATS, 0x10040);
    assert_eq!(CMD_TGCP_MIDDLE_SET, 0x10041);
    assert_eq!(CMD_TGCP_MIDDLE_STOP, 0x10042);
    assert_eq!(CMD_TGCP_MIDDLE_READ, 0x10043);
    assert_eq!(CMD_TGCP_MIDDLE_STATS, 0x10044);
}

#[test]
fn set_auto_discovery_passes_explicit_target_prime_and_nondefault_generator() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        999,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x10041);
            let req = unsafe { &*(args[0] as *const TgcpMiddleConfig) };
            assert_eq!(
                (req.abi_version, req.pid, req.family, req.flags),
                (2, 42, 2, 1)
            );
            assert_eq!(req.remote_port, 0);
            assert_eq!(req.remote_addr, [0; 16]);
            assert_eq!((req.prime_len, req.generator), (1, 5));
            assert_eq!(req.prime[0], 23);
            assert!(req.prime[1..].iter().all(|byte| *byte == 0));
            assert_eq!(req.reserved, [0; 2]);
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.TgcpMiddleSet(&config()), Ok(()));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn invalid_target_and_discovery_fields_are_rejected_before_syscall() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid config invoked kernel")),
    );
    for variant in 0..6 {
        let mut req = config();
        match variant {
            0 => req.pid = 0,
            1 => req.abi_version = 1,
            2 => req.family = 10,
            3 => req.flags = 2,
            4 => req.remote_port = 18081,
            _ => req.remote_addr[0] = 1,
        }
        assert_eq!(driver.TgcpMiddleSet(&req), Err(-22));
    }
}

#[test]
fn read_preserves_distinct_keys_and_client_side_data_in_one_ordered_batch() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, 0x10043);
            let req = unsafe { &mut *(args[0] as *mut TgcpMiddleReadRequest) };
            assert_eq!((req.abi_version, req.max_count), (2, 16));
            let out =
                unsafe { std::slice::from_raw_parts_mut(req.records as *mut TgcpMiddleEvent, 2) };
            out[0] = ready();
            out[1] = ready();
            out[1].seq = 2;
            out[1].event_type = 4;
            out[1].kc = [0; 16];
            out[1].ks = [0; 16];
            out[1].payload_len = 3;
            out[1].flags = 3;
            out[1].payload[..3].copy_from_slice(b"abc");
            req.out_count = 2;
            req.session_id = 7;
            req.dropped = 4;
            0
        }),
    );
    let mut records = vec![TgcpMiddleEvent::default(); 18];
    let got = driver.TgcpMiddleRead(&mut records).unwrap();
    assert_eq!((got.count, got.session_id, got.dropped), (2, 7, 4));
    assert_eq!(records[0].kc, [0x11; 16]);
    assert_eq!(records[0].ks, [0x22; 16]);
    assert_eq!(&records[1].payload[..3], b"abc");
}

#[test]
fn malformed_kernel_records_are_rejected_and_secret_buffers_cleared() {
    for variant in 0..12 {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |_, args: [usize; 5]| {
                let req = unsafe { &mut *(args[0] as *mut TgcpMiddleReadRequest) };
                req.session_id = 7;
                req.out_count = 1;
                let out = unsafe { &mut *(req.records as *mut TgcpMiddleEvent) };
                *out = ready();
                match variant {
                    0 => req.out_count = 17,
                    1 => req.session_id = 0,
                    2 => out.session_id = 8,
                    3 => out.socket_id = 0,
                    4 => out.event_type = 99,
                    5 => out.reserved = 1,
                    6 => out.family = 10,
                    7 => out.remote_addr[15] = 1,
                    8 => out.payload_len = 4097,
                    9 => out.event_type = 4, // DATA must never carry READY's key bytes.
                    10 => {
                        out.event_type = 4;
                        out.kc = [0; 16];
                        out.ks = [0; 16];
                        out.payload_len = 1;
                        out.stream_offset = u64::MAX;
                    }
                    _ => out.seq = 0,
                }
                0
            }),
        );
        let mut records = vec![TgcpMiddleEvent::default(); 16];
        assert!(
            matches!(driver.TgcpMiddleRead(&mut records), Err(-71)),
            "variant {variant}"
        );
        assert!(records.iter().all(|r| r.kc == [0; 16] && r.ks == [0; 16]));
    }
}

#[test]
fn unsupported_kernel_and_stop_propagate_without_invoking_udp() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, _| {
            assert!(matches!(command, 0x10041..=0x10044));
            -38
        }),
    );
    assert_eq!(driver.TgcpMiddleSet(&config()), Err(-38));
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
    for variant in 0..13 {
        let mut req = config();
        match variant {
            0 => req.prime_len = 0,
            1 => req.prime_len = 65,
            2 => req.prime[0] = 0,
            3 => req.prime[1] = 1,
            4 => req.reserved[0] = 1,
            5 => req.reserved[1] = 1,
            6 => req.prime[0] = 22,
            7 => req.prime[0] = 3,
            8 => req.generator = 0,
            9 => req.generator = 1,
            10 => req.generator = 22,
            11 => req.generator = 23,
            _ => {
                req.prime_len = 2;
                req.prime[0] = 0;
                req.prime[1] = 23;
            }
        }
        assert_eq!(driver.TgcpMiddleSet(&req), Err(-22), "variant {variant}");
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
        let mut req = config();
        req.prime = [0; 64];
        req.prime_len = prime.len() as u32;
        req.prime[..prime.len()].copy_from_slice(&prime);
        req.generator = generator;
        assert_eq!(
            driver.TgcpMiddleSet(&req),
            if valid { Ok(()) } else { Err(-22) }
        );
    }
}

#[test]
fn stats_sends_current_abi_and_zero_reserved_and_accepts_real_status_bits() {
    for (status, session, pid) in [(0, 0, 0), (0, 7, 0), (1, 7, 42), (3, 7, 42)] {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |command, args: [usize; 5]| {
                assert_eq!(command, CMD_TGCP_MIDDLE_STATS);
                let stats = unsafe { &mut *(args[0] as *mut TgcpMiddleStats) };
                assert_eq!(
                    stats.abi_version, TGCP_MIDDLE_ABI_VERSION,
                    "STATS must send the ABI, not zero-initialize it"
                );
                assert_eq!(stats.reserved, 0);
                stats.status = status;
                stats.session_id = session;
                stats.target_pid = pid;
                0
            }),
        );
        let got = driver.TgcpMiddleStats().unwrap();
        assert_eq!(
            (got.status, got.session_id, got.target_pid),
            (status, session, pid)
        );
    }
}

#[test]
fn stats_rejects_unknown_or_inconsistent_status_bits() {
    for (status, session, pid) in [(2, 7, 42), (4, 7, 42), (1, 0, 42), (3, 7, 0)] {
        let driver = KernelDriver::new(
            123,
            456,
            42,
            Transport(move |_, args: [usize; 5]| {
                let stats = unsafe { &mut *(args[0] as *mut TgcpMiddleStats) };
                stats.abi_version = TGCP_MIDDLE_ABI_VERSION;
                stats.status = status;
                stats.session_id = session;
                stats.target_pid = pid;
                0
            }),
        );
        assert_eq!(driver.TgcpMiddleStats(), Err(-71));
    }
}
