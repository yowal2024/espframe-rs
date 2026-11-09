use espframe::kernel::abi::*;
use espframe::kernel::{KernelDriver, KernelTransport, SignsRedirectConfig};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, nr: i32, option: u64, cmd: usize, args: [usize; 5]) -> isize {
        assert_eq!(args[0], 1);
        assert_eq!((nr, option), (123, 456));
        (self.0)(cmd, args)
    }
}
fn config() -> SignsRedirectConfig<'static> {
    SignsRedirectConfig {
        original_entry: &[0, 13, 255, 11],
        replacement_entry: &[7, 10, 0, 193],
    }
}

#[test]
fn set_passes_type_and_three_direct_arguments_without_request_wrapper() {
    let driver = KernelDriver::new(
        123,
        456,
        999,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, 0x10046);
            assert_eq!((args[1], args[4]), (4, 0));
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[2] as *const u8, args[1]) },
                &[0, 13, 255, 11]
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[3] as *const u8, args[1]) },
                &[7, 10, 0, 193]
            );
            0
        }),
    );
    assert_eq!(driver.DfmReadSet(&config()), Ok(()));
}

#[test]
fn stop_uses_only_type_and_zero_unused_slots() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args| {
            assert_eq!(cmd, 0x10047);
            assert_eq!(args, [1, 0, 0, 0, 0]);
            0
        }),
    );
    assert_eq!(driver.DfmReadStop(), Ok(()));
}

#[test]
fn negative_errno_and_unexpected_positive_status_are_handled() {
    for (status, expected) in [(-16, -16), (-14, -14), (-108, -108), (1, -71)] {
        let driver = KernelDriver::new(123, 456, 0, Transport(move |_, _| status));
        assert_eq!(driver.DfmReadSet(&config()), Err(expected));
        assert_eq!(driver.DfmReadStop(), Err(expected));
    }
}

#[test]
fn invalid_lengths_do_not_reach_transport() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid request dispatched")),
    );
    let huge = [0_u8; 4097];
    for value in [
        SignsRedirectConfig {
            original_entry: &[],
            replacement_entry: &[],
            ..config()
        },
        SignsRedirectConfig {
            replacement_entry: &[1, 2, 3],
            ..config()
        },
        SignsRedirectConfig {
            original_entry: &huge,
            replacement_entry: &huge,
            ..config()
        },
    ] {
        assert_eq!(driver.DfmReadSet(&value), Err(-22));
    }
}

#[test]
fn maximum_entry_is_supported_without_any_offset() {
    let data = [0x80; 4096];
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, CMD_READ_SPOOF_SET);
            assert_eq!((args[1], args[4]), (4096, 0));
            assert_eq!(
                unsafe { std::slice::from_raw_parts(args[2] as *const u8, 4096) },
                &data
            );
            0
        }),
    );
    assert_eq!(
        driver.DfmReadSet(&SignsRedirectConfig {
            original_entry: &data,
            replacement_entry: &data
        }),
        Ok(())
    );
}

#[test]
fn read_commands_follow_shifted_tgcp_commands_and_shared_net_commands() {
    assert_eq!(CMD_READ_SPOOF_SET, CMD_TGCP_MIDDLE_STATS + 1);
    assert_eq!(CMD_READ_SPOOF_STOP, CMD_READ_SPOOF_SET + 1);
    assert_eq!(
        (CMD_NET_SPOOF_SET, CMD_TGCP_MIDDLE_SET),
        (0x1003d, 0x10042)
    );
}

#[test]
fn group_entry_layout_is_24_bytes_without_version_or_request_wrapper() {
    use std::mem::{align_of, offset_of, size_of};
    assert_eq!(size_of::<SignsRedirectGroupEntry>(), 24);
    assert_eq!(align_of::<SignsRedirectGroupEntry>(), 8);
    assert_eq!(offset_of!(SignsRedirectGroupEntry, original_ptr), 0);
    assert_eq!(offset_of!(SignsRedirectGroupEntry, replacement_ptr), 8);
    assert_eq!(offset_of!(SignsRedirectGroupEntry, length), 16);
    assert_eq!(offset_of!(SignsRedirectGroupEntry, reserved), 20);
}

#[test]
fn group_set_passes_signed_configuration_and_independent_root_as_borrowed_entries() {
    let original_config = [0x10_u8; 128];
    let replacement_config = [0x20_u8; 128];
    let original_root = [0x30_u8; 32];
    let replacement_root = [0x40_u8; 32];
    let configurations = [
        SignsRedirectConfig {
            original_entry: &original_config,
            replacement_entry: &replacement_config,
        },
        SignsRedirectConfig {
            original_entry: &original_root,
            replacement_entry: &replacement_root,
        },
    ];
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|cmd, args: [usize; 5]| {
            assert_eq!(cmd, 0x10048);
            assert_eq!((args[1], args[3], args[4]), (2, 0, 0));
            let entries = unsafe {
                std::slice::from_raw_parts(args[2] as *const SignsRedirectGroupEntry, args[1])
            };
            for (entry, configuration) in entries.iter().zip(&configurations) {
                assert_eq!(
                    entry.original_ptr,
                    configuration.original_entry.as_ptr() as u64
                );
                assert_eq!(
                    entry.replacement_ptr,
                    configuration.replacement_entry.as_ptr() as u64
                );
                assert_eq!(entry.length as usize, configuration.original_entry.len());
                assert_eq!(entry.reserved, 0);
                assert_eq!(
                    unsafe {
                        std::slice::from_raw_parts(
                            entry.original_ptr as *const u8,
                            entry.length as usize,
                        )
                    },
                    configuration.original_entry
                );
            }
            0
        }),
    );
    assert_eq!(driver.DfmReadSetGroup(&configurations), Ok(()));
}

#[test]
fn group_rejects_invalid_count_lengths_and_duplicate_originals_before_dispatch() {
    let driver = KernelDriver::new(
        123,
        456,
        0,
        Transport(|_, _| panic!("invalid group dispatched")),
    );
    let values = [config(); 5];
    assert_eq!(driver.DfmReadSetGroup(&[]), Err(-22));
    assert_eq!(driver.DfmReadSetGroup(&values), Err(-22));
    assert_eq!(driver.DfmReadSetGroup(&values[..2]), Err(-22));
    let changed = SignsRedirectConfig {
        replacement_entry: &[1, 2, 3, 4],
        ..config()
    };
    assert_eq!(driver.DfmReadSetGroup(&[config(), changed]), Err(-22));
    let huge = [1_u8; 4097];
    for invalid in [
        SignsRedirectConfig {
            original_entry: &[],
            replacement_entry: &[],
        },
        SignsRedirectConfig {
            replacement_entry: &[1],
            ..config()
        },
        SignsRedirectConfig {
            original_entry: &huge,
            replacement_entry: &huge,
        },
    ] {
        assert_eq!(driver.DfmReadSetGroup(&[config(), invalid]), Err(-22));
    }
}

#[test]
fn group_accepts_one_through_four_members_and_preserves_their_lengths() {
    let configs = [
        SignsRedirectConfig {
            original_entry: &[1],
            replacement_entry: &[11],
        },
        SignsRedirectConfig {
            original_entry: &[2, 3],
            replacement_entry: &[12, 13],
        },
        SignsRedirectConfig {
            original_entry: &[4, 5, 6],
            replacement_entry: &[14, 15, 16],
        },
        SignsRedirectConfig {
            original_entry: &[7, 8, 9, 10],
            replacement_entry: &[17, 18, 19, 20],
        },
    ];
    for count in 1..=4 {
        let driver = KernelDriver::new(
            123,
            456,
            0,
            Transport(|cmd, args: [usize; 5]| {
                assert_eq!(cmd, CMD_READ_SPOOF_SET_GROUP);
                assert_eq!(args[1], count);
                let entries = unsafe {
                    std::slice::from_raw_parts(args[2] as *const SignsRedirectGroupEntry, count)
                };
                for (index, entry) in entries.iter().enumerate() {
                    assert_eq!(entry.length as usize, index + 1);
                }
                0
            }),
        );
        assert_eq!(driver.DfmReadSetGroup(&configs[..count]), Ok(()));
    }
}

#[test]
fn group_preserves_busy_and_copy_errors_and_rejects_positive_status() {
    for (status, expected) in [(-16, -16), (-14, -14), (-22, -22), (-108, -108), (1, -71)] {
        let driver = KernelDriver::new(123, 456, 0, Transport(move |_, _| status));
        assert_eq!(driver.DfmReadSetGroup(&[config()]), Err(expected));
    }
}

#[test]
fn group_command_appends_after_stop_without_shifting_single_entry_commands() {
    assert_eq!(CMD_READ_SPOOF_SET_GROUP, CMD_READ_SPOOF_STOP + 1);
    assert_eq!(
        (
            CMD_READ_SPOOF_SET,
            CMD_READ_SPOOF_STOP,
            CMD_READ_SPOOF_SET_GROUP
        ),
        (0x10046, 0x10047, 0x10048)
    );
}
