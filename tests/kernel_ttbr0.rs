use espframe::kernel::abi::*;
use espframe::kernel::{KernelDriver, KernelTransport, Ttbr0HookType};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Transport(Arc<Mutex<(Vec<(usize, [usize; 5])>, VecDeque<isize>)>>);
impl KernelTransport for Transport {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        assert_eq!((scno, option), (19, 7));
        let mut state = self.0.lock().unwrap();
        state.0.push((command, args));
        state.1.pop_front().expect("unexpected kernel call")
    }
}
fn driver(results: &[isize]) -> (KernelDriver<Transport>, Transport) {
    let transport = Transport::default();
    transport.0.lock().unwrap().1.extend(results);
    (KernelDriver::new(19, 7, 42, transport.clone()), transport)
}

#[test]
fn full_and_leaf_use_five_direct_arguments_and_leave_addresses_untagged() {
    for install_type in [Ttbr0HookType::Full, Ttbr0HookType::Leaf] {
        let (driver, transport) = driver(&[55, 1]);
        let hook = unsafe { driver.RegisterTtbr0Hook(42, 0x1000, 0x2000, 0x3001, install_type) }.unwrap();
        assert_eq!(hook.RawHandle(), 55);
        drop(hook);
        assert_eq!(transport.0.lock().unwrap().0, [
            (CMD_REGISTER_TTBR0_HOOK, [42, 0x1000, 0x2000, 0x3001, install_type as usize]),
            (CMD_UNREGISTER_TTBR0_HOOK, [55, 0, 0, 0, 0]),
        ]);
    }
}

#[test]
fn invalid_input_has_no_side_effect_and_kernel_rejection_has_no_owner() {
    let (driver, transport) = driver(&[0, -95]);
    for (pid, site, replace) in [(0, 0x1000, 0x2000), (1, 0x1000, 0x2000),
        (42, 0, 0x2000), (42, 0x1001, 0x2000), (42, 0x1000, 0), (42, 0x1000, 1), (42, 0x1000, 0x2002)] {
        assert!(unsafe { driver.RegisterTtbr0Hook(pid, site, replace, 0, Ttbr0HookType::Full) }.is_err());
    }
    assert!(transport.0.lock().unwrap().0.is_empty());
    for install_type in [Ttbr0HookType::Full, Ttbr0HookType::Leaf] {
        for replace in [0x2001, 0x2002, 0x2003] {
            assert_eq!(unsafe { driver.RegisterTtbr0HookRaw(42, 0x1000, replace, 0, install_type) }, Err(-22));
        }
    }
    assert!(transport.0.lock().unwrap().0.is_empty());
    assert_eq!(unsafe { driver.RegisterTtbr0HookRaw(42, 0x1000, 0x2000, 0, Ttbr0HookType::Full) }, Err(0));
    assert_eq!(unsafe { driver.RegisterTtbr0HookRaw(42, 0x1000, 0x2000, 0, Ttbr0HookType::Leaf) }, Err(-95));
    assert_eq!(transport.0.lock().unwrap().0.len(), 2);
}

#[test]
fn failed_detach_retains_handle_until_success_and_drop_does_not_repeat_success() {
    let (driver, transport) = driver(&[55, -16, 0, 1]);
    let mut hook = unsafe { driver.RegisterTtbr0Hook(42, 0x1000, 0x2000, 0, Ttbr0HookType::Full) }.unwrap();
    assert_eq!(hook.Unregister(), Err(-16));
    assert_eq!(hook.RawHandle(), 55);
    assert_eq!(hook.Unregister(), Err(0));
    assert_eq!(hook.Unregister(), Ok(()));
    assert_eq!(hook.RawHandle(), 0);
    assert_eq!(hook.Unregister(), Ok(()));
    drop(hook);
    assert_eq!(transport.0.lock().unwrap().0.len(), 4);
}

#[test]
fn remote_mapping_uses_explicit_target_and_rejects_negative_results() {
    let (driver, transport) = driver(&[-12, 0, 0x4000]);
    assert_eq!(driver.RemoteMmapForPid(1, c"key", 4096, 3), Err(-22));
    assert_eq!(driver.RemoteMmapForPid(88, c"key", 0, 3), Err(-22));
    assert_eq!(driver.RemoteMmapForPid(88, c"key", 4096, 8), Err(-22));
    assert_eq!(driver.RemoteMmapForPid(88, c"key", 4096, 5), Err(-12));
    assert_eq!(driver.RemoteMmapForPid(88, c"key", 4096, 5), Err(0));
    assert_eq!(driver.RemoteMmapForPid(88, c"key", 4096, 5), Ok(0x4000));
    for (command, args) in &transport.0.lock().unwrap().0 {
        assert_eq!(*command, CMD_REMOTE_MMAP);
        assert_eq!(&args[..3], &[88, 4096, 5]);
        assert_ne!(args[3], 0);
        assert_eq!(args[4], 0);
    }
}

#[test]
fn context_and_compacted_command_contract() {
    use std::mem::{align_of, offset_of, size_of};
    assert_eq!(Ttbr0HookType::Full as u64, 0);
    assert_eq!(Ttbr0HookType::Leaf as u64, 1);
    assert_eq!(size_of::<Ttbr0HookType>(), 8);
    assert_eq!(size_of::<Ttbr0HookContext>(), 0x320);
    assert_eq!(align_of::<Ttbr0HookContext>(), 8);
    assert_eq!(offset_of!(Ttbr0HookContext, sp), 0xf8);
    assert_eq!(offset_of!(Ttbr0HookContext, nzcv), 0x100);
    assert_eq!(offset_of!(Ttbr0HookContext, fpsr), 0x108);
    assert_eq!(offset_of!(Ttbr0HookContext, q), 0x110);
    assert_eq!(offset_of!(Ttbr0HookContext, fpcr), 0x310);
    assert_eq!(offset_of!(Ttbr0HookContext, pc), 0x318);
    assert_eq!(size_of::<Ttbr0LeafFrame>(), 32);
    assert_eq!([CMD_REGISTER_TTBR0_HOOK, CMD_UNREGISTER_TTBR0_HOOK, CMD_CREATE_TOUCH_EVENT_LISTENER], [0x10021, 0x10022, 0x10023]);
    assert_eq!([CMD_UDP_CAP_INIT, CMD_UDP_CAP_STOP], [0x10025, 0x10026]);
    assert_eq!(CMD_READ_SPOOF_SET_GROUP, 0x1002f);
}

#[test]
fn thread_lookup_is_process_scoped_and_supplies_the_full_kernel_copy_buffer() {
    struct Lookup;
    impl KernelTransport for Lookup {
        unsafe fn Invoke(&self, _: i32, _: u64, command: usize, args: [usize; 5]) -> isize {
            assert_eq!(command, CMD_GET_THREAD_BY_COMM);
            assert_eq!(args[0], 42);
            assert_eq!(&args[2..], &[0, 0, 0]);
            let bytes = unsafe { std::slice::from_raw_parts(args[1] as *const u8, 64) };
            assert_eq!(&bytes[..11], b"GameThread\0");
            assert!(bytes[11..].iter().all(|byte| *byte == 0));
            84
        }
    }
    let driver = KernelDriver::new(19, 7, 999, Lookup);
    assert_eq!(driver.GetThreadByComm(42, c"GameThread"), Ok(84));
    assert_eq!(driver.GetThreadByComm(1, c"GameThread"), Err(-22));
    assert_eq!(driver.GetThreadByComm(42, c""), Err(-22));
    assert_eq!(driver.GetThreadByComm(42, c"1234567890123456"), Err(-22));
    let (driver, _) = crate::driver(&[-1, -3, 0, 1]);
    for expected in [-1, -3, -71, -71] {
        assert_eq!(driver.GetThreadByComm(42, c"GameThread"), Err(expected));
    }
}
