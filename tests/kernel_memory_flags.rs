use espframe::kernel::abi::{CallMemoryFlags, CMD_CALL_MEMORY};
use espframe::kernel::{KernelDriver, KernelTransport, SharedMemoryFlags};

struct Transport<F>(F);
impl<F: Fn(usize, [usize; 5]) -> isize + Send + Sync> KernelTransport for Transport<F> {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!((scno, option), (123, 456));
        (self.0)(command, args)
    }
}

fn dcache() -> CallMemoryFlags {
    CallMemoryFlags::from_name("Dcache").expect("the opt-in Dcache flag must be public")
}

fn read_with_flags(flags: CallMemoryFlags, expected_wire_flags: usize) {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|command, args: [usize; 5]| {
            assert_eq!(command, CMD_CALL_MEMORY);
            assert_eq!(
                (args[0], args[1], args[3], args[4]),
                (42, 0x20000, 4, expected_wire_flags)
            );
            let output = unsafe { std::slice::from_raw_parts_mut(args[2] as *mut u8, 4) };
            output.copy_from_slice(&[3, 1, 4, 1]);
            4
        }),
    );
    let mut output = [0; 4];
    assert_eq!(driver.CallMemoryRead(42, 0x20000, &mut output, flags), 4);
    assert_eq!(output, [3, 1, 4, 1]);
}

#[test]
fn explicit_dcache_read_reaches_kernel_with_bit_0x10() {
    read_with_flags(CallMemoryFlags::Read | dcache(), 0x10);
}

#[test]
fn existing_modes_do_not_enable_cache_maintenance() {
    read_with_flags(CallMemoryFlags::Read, 0);
    read_with_flags(CallMemoryFlags::for_mem_mode(0), 2);
    read_with_flags(CallMemoryFlags::for_mem_mode(1), 6);
    read_with_flags(CallMemoryFlags::for_mem_mode(2), 2);
}

#[test]
fn nocache_combinations_are_preserved_for_kernel_to_ignore_dcache() {
    read_with_flags(CallMemoryFlags::NoCache | dcache(), 0x12);
    read_with_flags(
        CallMemoryFlags::NoCache | CallMemoryFlags::Io | dcache(),
        0x16,
    );
}

#[test]
fn dcache_does_not_bypass_read_write_validation() {
    let driver = KernelDriver::new(
        123,
        456,
        42,
        Transport(|_, _| panic!("read must reject the Write flag before dispatch")),
    );
    assert_eq!(
        driver.CallMemoryRead(42, 0x20000, &mut [0; 4], CallMemoryFlags::Write | dcache()),
        0
    );
}

#[test]
fn shared_flags_keep_explicit_opt_in_and_mode_changes_reset_it() {
    let flags = SharedMemoryFlags::new(CallMemoryFlags::Read);
    let reader = flags.clone();
    flags.set(CallMemoryFlags::Read | dcache());
    read_with_flags(reader.load(), 0x10);
    flags.set_mem_mode(0);
    read_with_flags(reader.load(), 2);
}
