use espframe::kernel::abi::{Type7ProxyResult, CMD_NET_SPOOF_READ};
use espframe::kernel::{KernelDriver, KernelTransport, Type7ProxyConfig};
use std::mem::{align_of, offset_of, size_of};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, nr: i32, option: u64, cmd: usize, args: [usize; 5]) -> isize {
        assert_eq!(args[0], 1);
        assert_eq!((nr, option), (123, 456));
        (self.0)(cmd, args)
    }
}

fn config() -> Type7ProxyConfig<'static> {
    Type7ProxyConfig {
        certificate: &[0x52; 128],
        root: &[0x73; 32],
    }
}

#[test]
fn set_passes_only_borrowed_public_material_and_returns_owned_generation() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, 0x1003d);
            assert_eq!(&args[3..], &[0; 2]);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[1] as *const u8, 128) },
                &[0x52; 128]
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[2] as *const u8, 32) },
                &[0x73; 32]
            );
            calls.fetch_add(1, Ordering::Relaxed);
            37
        }),
    );
    assert_eq!(driver.DfmNetSet(&config()), Ok(37));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn bind_supplies_generation_token_and_initial_key_without_uid_or_endpoint() {
    let token = [0x41; 20];
    let key = [0x31; 16];
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, 0x10041);
            assert_eq!((args[1], args[4]), (37, 0));
            assert_eq!(args[2], token.as_ptr() as usize);
            assert_eq!(args[3], key.as_ptr() as usize);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[2] as *const u8, 20) },
                &token
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[3] as *const u8, 16) },
                &key
            );
            0
        }),
    );
    assert_eq!(driver.DfmNetBind(37, &token, &key), Ok(()));
    assert_eq!(key, [0x31; 16]);
}

#[test]
fn invalid_generation_does_not_dispatch_or_touch_output() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid generation dispatched")),
    );
    for generation in [0, u64::MAX] {
        assert_eq!(
            driver.DfmNetBind(generation, &[0x41; 20], &[0x31; 16]),
            Err(-22)
        );
        assert_eq!(driver.DfmNetStop(generation), Err(-22));
        let mut records = [Type7ProxyResult {
            key: [0xcc; 16],
            ..Default::default()
        }];
        assert_eq!(
            driver.DfmNetRead(generation, &mut records).unwrap_err(),
            -22
        );
        assert_eq!(records[0].key, [0xcc; 16]);
    }
}

#[test]
fn stop_passes_the_owned_generation_only() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args| {
            assert_eq!((cmd, args), (0x1003e, [1, 37, 0, 0, 0]));
            0
        }),
    );
    assert_eq!(driver.DfmNetStop(37), Ok(()));
}

#[test]
fn read_exposes_the_exact_64_byte_kernel_record() {
    assert_eq!(
        (
            size_of::<Type7ProxyResult>(),
            align_of::<Type7ProxyResult>()
        ),
        (64, 8)
    );
    assert_eq!(offset_of!(Type7ProxyResult, sequence), 0);
    assert_eq!(offset_of!(Type7ProxyResult, timestamp_ns), 8);
    assert_eq!(offset_of!(Type7ProxyResult, socket_id), 16);
    assert_eq!(offset_of!(Type7ProxyResult, pid), 24);
    assert_eq!(offset_of!(Type7ProxyResult, local_port), 28);
    assert_eq!(offset_of!(Type7ProxyResult, remote_port), 30);
    assert_eq!(offset_of!(Type7ProxyResult, remote_addr), 32);
    assert_eq!(offset_of!(Type7ProxyResult, key), 48);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, 0x1003f);
            assert_eq!((args[1], args[3]), (37, 16));
            unsafe {
                let records = std::slice::from_raw_parts_mut(args[2] as *mut Type7ProxyResult, 16);
                assert!(records.iter().all(|r| r.key == [0; 16] && r.sequence == 0));
                assert_eq!(*(args[4] as *const u64), 0);
                records[0] = Type7ProxyResult {
                    sequence: 17,
                    timestamp_ns: 8_000_000,
                    socket_id: 0xfedc_ba98_7654_3210,
                    pid: 234,
                    local_port: 52546,
                    remote_port: 50425,
                    remote_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 20, 30, 40],
                    key: [0x72; 16],
                };
                *(args[4] as *mut u64) = 7;
            }
            1
        }),
    );
    let mut records = [Type7ProxyResult {
        sequence: 9,
        key: [0xcc; 16],
        ..Default::default()
    }; 20];
    let stats = driver.DfmNetRead(37, &mut records).unwrap();
    assert_eq!((stats.count, stats.dropped), (1, 7));
    assert_eq!(
        (records[0].sequence, records[0].timestamp_ns),
        (17, 8_000_000)
    );
    assert_eq!(records[0].socket_id, 0xfedc_ba98_7654_3210);
    assert_eq!(
        (
            records[0].pid,
            records[0].local_port,
            records[0].remote_port
        ),
        (234, 52546, 50425)
    );
    assert_eq!(
        records[0].remote_addr,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 20, 30, 40]
    );
    assert_eq!(records[0].key, [0x72; 16]);
    assert!(records[1..16]
        .iter()
        .all(|r| r.key == [0; 16] && r.sequence == 0));
    assert_eq!(records[16].key, [0xcc; 16]);
}

#[test]
fn read_rejects_empty_buffer_without_dispatch_and_accepts_empty_queue() {
    let calls = AtomicUsize::new(0);
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!((cmd, args[1], args[3]), (CMD_NET_SPOOF_READ, 37, 1));
            calls.fetch_add(1, Ordering::Relaxed);
            0
        }),
    );
    assert_eq!(driver.DfmNetRead(37, &mut []).unwrap_err(), -22);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let stats = driver
        .DfmNetRead(37, &mut [Type7ProxyResult::default()])
        .unwrap();
    assert_eq!((stats.count, stats.dropped), (0, 0));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn read_clears_partial_outputs_on_kernel_error_or_impossible_count() {
    for (capacity, result, expected) in [
        (1, -14, -14),
        (1, 2, -71),
        (20, 17, -71),
        (1, isize::MAX, -71),
    ] {
        let driver = KernelDriver::new(
            123,
            456,
            0,
            Transport(move |_, args: [usize; 5]| {
                assert_eq!((args[1], args[3]), (37, capacity.min(16)));
                unsafe {
                    (*(args[2] as *mut Type7ProxyResult)).key = [0xaa; 16];
                }
                result
            }),
        );
        let mut records = vec![
            Type7ProxyResult {
                key: [0xcc; 16],
                ..Default::default()
            };
            capacity
        ];
        assert_eq!(
            driver.DfmNetRead(37, &mut records).unwrap_err(),
            expected
        );
        assert!(records[..capacity.min(16)].iter().all(|r| r.key == [0; 16]));
        if capacity > 16 {
            assert_eq!(records[16].key, [0xcc; 16]);
        }
    }
}

#[test]
fn set_bind_stop_and_read_preserve_negative_kernel_errors() {
    for error in [-1, -14, -16, -22, -32, -38, -108] {
        let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| error));
        assert_eq!(driver.DfmNetSet(&config()), Err(error));
        assert_eq!(driver.DfmNetStop(37), Err(error));
        assert_eq!(
            driver.DfmNetBind(37, &[0x41; 20], &[0x31; 16]),
            Err(error)
        );
        assert_eq!(
            driver
                .DfmNetRead(37, &mut [Type7ProxyResult::default()])
                .unwrap_err(),
            error
        );
    }
}

#[test]
fn positive_control_status_is_protocol_error_while_one_record_is_valid() {
    let driver = KernelDriver::new(123, 456, 0, Transport(|_, _| 1));
    assert_eq!(driver.DfmNetSet(&config()), Ok(1));
    assert_eq!(
        driver.DfmNetBind(37, &[0x41; 20], &[0x31; 16]),
        Err(-71)
    );
    let zero = KernelDriver::new(123, 456, 0, Transport(|_, _| 0));
    assert_eq!(zero.DfmNetSet(&config()), Err(-71));
    assert_eq!(driver.DfmNetStop(37), Err(-71));
    assert_eq!(
        driver
            .DfmNetRead(37, &mut [Type7ProxyResult::default()])
            .unwrap()
            .count,
        1
    );
}
