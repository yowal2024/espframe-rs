pub trait KernelTransport: Send + Sync {
    /// # Safety
    ///
    /// Every nonzero pointer in `args` must be valid for the kernel command's
    /// documented access and duration requirements.
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallTransport;

impl KernelTransport for SyscallTransport {
    unsafe fn Invoke(&self, scno: i32, option: u64, command: usize, args: [usize; 5]) -> isize {
        #[cfg(target_arch = "aarch64")]
        {
            let mut result = option as usize;
            unsafe {
                core::arch::asm!(
                    "svc 0",
                    in("x8") scno as isize,
                    inout("x0") result,
                    in("x1") command,
                    in("x2") args[0],
                    in("x3") args[1],
                    in("x4") args[2],
                    in("x5") args[3],
                    in("x6") args[4],
                    options(nostack),
                );
            }
            result as isize
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (scno, option, command, args);
            -38
        }
    }
}
