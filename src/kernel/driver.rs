use super::abi::*;
use super::transport::KernelTransport;
use std::ffi::{CStr, CString};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleBaseLookup {
    Missing,
    IoError(isize),
    Ready(u64),
    Fatal(String),
}

#[derive(Clone)]
pub struct KernelDriver<T: KernelTransport> {
    pid: i32,
    scno: i32,
    option: u64,
    configuration_revision: u64,
    transport: T,
}

impl<T: KernelTransport> KernelDriver<T> {
    pub fn new(scno: i32, option: u64, pid: i32, transport: T) -> Self {
        Self {
            pid,
            scno,
            option: u64::from(option as u32),
            configuration_revision: 0,
            transport,
        }
    }

    pub const fn Pid(&self) -> i32 {
        self.pid
    }

    pub const fn Scno(&self) -> i32 {
        self.scno
    }

    pub const fn Option(&self) -> u64 {
        self.option
    }

    pub const fn ConfigurationRevision(&self) -> u64 {
        self.configuration_revision
    }

    pub fn SetPid(&mut self, pid: i32) {
        self.pid = pid;
    }

    pub fn SetScno(&mut self, scno: i32) {
        self.scno = scno;
        self.configuration_revision = self.configuration_revision.wrapping_add(1);
    }

    pub fn SetOption(&mut self, option: u64) {
        self.option = u64::from(option as u32);
        self.configuration_revision = self.configuration_revision.wrapping_add(1);
    }

    unsafe fn Invoke(&self, command: usize, args: [usize; 5]) -> isize {
        unsafe { self.transport.Invoke(self.scno, self.option, command, args) }
    }

    /// Configure the module's sensor packet modifier. Zero flags disable it.
    /// Raw binary32 values cross the ABI as integers; no kernel FP is used.
    /// Persistent until replaced/disabled, or consumed when Once is set.
    pub fn ConfigureGyroEvent(&self, flags: u32, xyz: [f32; 3]) -> Result<(), isize> {
        if flags
            & !(GYRO_EVENT_ONCE | GYRO_EVENT_X | GYRO_EVENT_Y | GYRO_EVENT_Z | GYRO_EVENT_APPEND)
            != 0
            || !xyz.iter().all(|v| v.is_finite())
        {
            return Err(-22);
        }
        let result = unsafe {
            self.Invoke(
                CMD_GYRO_EVENT_CONFIGURE,
                [
                    flags as usize,
                    xyz[0].to_bits() as usize,
                    xyz[1].to_bits() as usize,
                    xyz[2].to_bits() as usize,
                    0,
                ],
            )
        };
        if result == 1 {
            Ok(())
        } else {
            Err(result)
        }
    }

    fn InvokeMemory(&self, request: MemoryRequest, buffer: usize, expected_write: bool) -> isize {
        if !request.IsValid(expected_write) || buffer == 0 {
            crate::espframe_log!(
                "kernel.memory.reject",
                "pid={} address={:#x} len={} flags={:#x} buffer={:#x} expected_write={}",
                request.pid,
                request.address,
                request.length,
                request.flags,
                buffer,
                expected_write
            );
            return 0;
        }
        let result = unsafe {
            self.Invoke(
                CMD_CALL_MEMORY,
                [
                    request.pid as usize,
                    CanonicalizeAddress(request.address) as usize,
                    buffer,
                    request.length as usize,
                    request.flags as usize,
                ],
            )
        };
        if crate::debug_log::memory_call_enabled(request.length, result) {
            crate::espframe_log!(
                "kernel.memory.invoke",
                "pid={} address={:#x} len={} flags={:#x} buffer={:#x} result={}",
                request.pid,
                request.address,
                request.length,
                request.flags,
                buffer,
                result
            );
        }
        result
    }

    pub fn CallMemory(
        &self,
        pid: i32,
        address: u64,
        buffer: &mut [u8],
        flags: CallMemoryFlags,
    ) -> isize {
        let expected_write = flags.contains(CallMemoryFlags::Write);
        let request = MemoryRequest::new(pid, address, buffer.len() as u64, flags.Bits());
        self.InvokeMemory(request, buffer.as_mut_ptr() as usize, expected_write)
    }

    pub fn CallMemoryRead(
        &self,
        pid: i32,
        address: u64,
        buffer: &mut [u8],
        flags: CallMemoryFlags,
    ) -> isize {
        let request = MemoryRequest::new(pid, address, buffer.len() as u64, flags.Bits());
        self.InvokeMemory(request, buffer.as_mut_ptr() as usize, false)
    }

    pub fn CallMemory_Read(
        &self,
        pid: i32,
        address: u64,
        buffer: &mut [u8],
        flags: CallMemoryFlags,
    ) -> isize {
        self.CallMemoryRead(pid, address, buffer, flags)
    }

    pub fn CallMemoryWrite(
        &self,
        pid: i32,
        address: u64,
        buffer: &[u8],
        flags: CallMemoryFlags,
    ) -> isize {
        let request = MemoryRequest::new(pid, address, buffer.len() as u64, flags.Bits());
        self.InvokeMemory(request, buffer.as_ptr() as usize, true)
    }

    pub fn CallMemory_Write(
        &self,
        pid: i32,
        address: u64,
        buffer: &[u8],
        flags: CallMemoryFlags,
    ) -> isize {
        self.CallMemoryWrite(pid, address, buffer, flags)
    }

    pub fn ReadMemory(&self, address: u64, buffer: &mut [u8], cache: bool) -> isize {
        buffer.fill(0);
        if cache && !IsValidCachedAddress(address) {
            return 0;
        }
        let flags = if cache {
            CALL_MEMORY_READ | CALL_MEMORY_NO_CACHE | CALL_MEMORY_IO
        } else {
            CALL_MEMORY_READ
        };
        let request = MemoryRequest::new(self.pid, address, buffer.len() as u64, flags);
        self.InvokeMemory(request, buffer.as_mut_ptr() as usize, false)
    }

    pub fn WriteMemory(&self, address: u64, buffer: &[u8], cache: bool) -> isize {
        if cache && !IsValidCachedAddress(address) {
            return 0;
        }
        let request = MemoryRequest::new(self.pid, address, buffer.len() as u64, CALL_MEMORY_WRITE);
        self.InvokeMemory(request, buffer.as_ptr() as usize, true)
    }

    pub fn ProcessPauth(
        &self,
        tid: i32,
        operation: ProcessPauthOperation,
        value: u64,
        modifier: u64,
        result: &mut u64,
    ) -> i32 {
        if tid <= 0 {
            return -1;
        }
        *result = 0;
        unsafe {
            self.Invoke(
                CMD_PROCESS_PAUTH,
                [
                    tid as usize,
                    operation as usize,
                    value as usize,
                    modifier as usize,
                    result as *mut u64 as usize,
                ],
            ) as i32
        }
    }

    pub fn SerialNumber(&self) -> Result<String, &'static str> {
        let mut bytes = [0_u8; 128];
        let result =
            unsafe { self.Invoke(CMD_GET_SERIALNO, [bytes.as_mut_ptr() as usize, 0, 0, 0, 0]) };
        if result < 0 {
            crate::espframe_log!(
                "kernel.serial.error",
                "result={} scno={}",
                result,
                self.scno
            );
            return Err("kernel serial number call failed");
        }
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if length == 0 {
            return Err("kernel serial number is empty");
        }
        std::str::from_utf8(&bytes[..length])
            .map(str::to_owned)
            .map_err(|_| "kernel serial number is not UTF-8")
    }

    /// Enable or disable the driver's SU capability for this process.
    ///
    /// The kernel ABI returns the requested state on success:
    /// `1` when enabling and `0` when disabling. Any other value is a
    /// failure and must not be treated as success.
    pub fn SetSuEnabled(&self, enabled: bool) -> Result<(), String> {
        let expected = isize::from(enabled as i8);
        let result = unsafe { self.Invoke(CMD_SET_ENABLE_SU, [usize::from(enabled), 0, 0, 0, 0]) };
        if result == expected {
            Ok(())
        } else {
            Err(format!(
                "kernel set SU failed: expected {expected}, got {result}"
            ))
        }
    }

    /// Query whether the driver's SU capability is currently enabled.
    pub fn IsSuEnabled(&self) -> bool {
        unsafe { self.Invoke(CMD_IS_ENABLE_SU, [0; 5]) > 0 }
    }

    /// Grant SU to the current caller through the kernel driver.
    ///
    /// The ABI returns exactly `1` on success. Any other value, including
    /// zero and other positive values, is a failure.
    pub fn GrantSuRaw(&self) -> isize {
        unsafe { self.Invoke(CMD_GRANT_SU, [0; 5]) }
    }

    pub fn GrantSu(&self) -> Result<(), String> {
        let result = self.GrantSuRaw();
        if result == 1 {
            Ok(())
        } else {
            Err(format!("kernel grant SU failed: expected 1, got {result}"))
        }
    }

    pub fn CreateTouchInputEventListener(&self) -> Result<i32, String> {
        let result = unsafe { self.Invoke(CMD_CREATE_TOUCH_EVENT_LISTENER, [0; 5]) };
        if result > 0 && result <= i32::MAX as isize {
            Ok(result as i32)
        } else {
            Err(format!("kernel touch listener creation failed: {result}"))
        }
    }

    pub fn UpdateTouchScreenInfo(
        &self,
        listener_fd: i32,
        width: u32,
        height: u32,
        orientation: i8,
    ) -> Result<(), String> {
        if listener_fd <= 0
            || width == 0
            || height == 0
            || width > i32::MAX as u32
            || height > i32::MAX as u32
            || !(0..=3).contains(&orientation)
        {
            return Err("invalid kernel touch screen information".to_owned());
        }
        let result = unsafe {
            self.Invoke(
                CMD_TOUCH_EVENT_UPDATE_SCREEN_INFO,
                [
                    listener_fd as usize,
                    width as usize,
                    height as usize,
                    orientation as usize,
                    0,
                ],
            )
        };
        if result >= 0 {
            Ok(())
        } else {
            Err(format!("kernel touch screen update failed: {result}"))
        }
    }

    pub fn ProcessIoctl(&self, tgid: i32, ufd: u32, request: u32, raw_arg: u64) -> isize {
        if tgid <= 0 {
            return -22;
        }
        unsafe {
            self.Invoke(
                CMD_PROCESS_IOCTL,
                [
                    tgid as usize,
                    ufd as usize,
                    request as usize,
                    raw_arg as usize,
                    0,
                ],
            )
        }
    }

    pub fn PeekKgslSyncsourceId(&self, tgid: i32, ufd: u32, min_id: u32) -> isize {
        if tgid <= 0 {
            return -22;
        }
        unsafe {
            self.Invoke(
                CMD_PEEK_KGSL_SYNCSOURCE_ID,
                [tgid as usize, ufd as usize, min_id as usize, 0, 0],
            )
        }
    }

    pub fn GetTaskByName(&self, name: &CStr) -> i32 {
        unsafe { self.Invoke(CMD_GET_TASK_BY_NAME, [name.as_ptr() as usize, 0, 0, 0, 0]) as i32 }
    }

    pub fn ModuleBaseByPidName(&self, pid: i32, module_name: &str) -> Option<u64> {
        match self.ModuleBaseByPidNameTyped(pid, module_name) {
            ModuleBaseLookup::Ready(base) => Some(base),
            ModuleBaseLookup::Missing
            | ModuleBaseLookup::IoError(_)
            | ModuleBaseLookup::Fatal(_) => None,
        }
    }

    pub fn ModuleBaseByPidNameTyped(&self, pid: i32, module_name: &str) -> ModuleBaseLookup {
        if pid <= 0 {
            return ModuleBaseLookup::Fatal("module lookup pid is invalid".to_owned());
        }
        if module_name.is_empty() {
            return ModuleBaseLookup::Fatal("module name is empty".to_owned());
        }
        let module_name = match CString::new(module_name) {
            Ok(module_name) => module_name,
            Err(_) => return ModuleBaseLookup::Fatal("module name contains NUL".to_owned()),
        };
        let result = unsafe {
            self.Invoke(
                CMD_GET_MODULE_BASE_BY_PID_NAME,
                [pid as usize, module_name.as_ptr() as usize, 0, 0, 0],
            )
        };
        if result == 0 {
            return ModuleBaseLookup::Missing;
        }
        if result < 0 {
            return ModuleBaseLookup::IoError(result);
        }
        let base = CanonicalizeAddress(result as u64);
        if base == 0 {
            ModuleBaseLookup::Fatal("module lookup returned a non-canonical base".to_owned())
        } else {
            ModuleBaseLookup::Ready(base)
        }
    }

    pub fn ReadableMemoryRanges(&self) -> Option<Vec<MemoryRegion>> {
        if self.pid <= 0 {
            return None;
        }

        // This ABI buffer is roughly 13 MiB. Initialize it in its final heap
        // allocation so Android worker threads never place it on their stack.
        let mut info = Box::<VirtualMemory>::new_uninit();
        unsafe {
            info.as_mut_ptr().write_bytes(0, 1);
        }
        let result = unsafe {
            self.Invoke(
                CMD_GET_MEM_INFO,
                [self.pid as usize, info.as_mut_ptr() as usize, 0, 0, 0],
            )
        };
        if result != 0 {
            return None;
        }
        let info = unsafe { info.assume_init() };

        let region_count = usize::try_from(info.region_count)
            .unwrap_or(0)
            .min(MAX_SCAN_REGIONS);
        let module_count = usize::try_from(info.module_count)
            .unwrap_or(0)
            .min(MAX_MODULES);
        let mut ranges =
            Vec::with_capacity(region_count.saturating_add(module_count.saturating_mul(3)));

        for region in &info.regions[..region_count] {
            if region.end > region.start {
                ranges.push(*region);
            }
        }
        for module in &info.modules[..module_count] {
            let segment_count = usize::try_from(module.seg_count)
                .unwrap_or(0)
                .min(MAX_SEGMENTS_PER_MODULE);
            for segment in &module.segments[..segment_count] {
                if segment.prot & VM_READ != 0 && segment.end > segment.start {
                    ranges.push(MemoryRegion {
                        start: segment.start,
                        end: segment.end,
                    });
                }
            }
        }

        ranges.sort_unstable_by_key(|range| (range.start, range.end));
        let mut merged: Vec<MemoryRegion> = Vec::with_capacity(ranges.len());
        for range in ranges {
            if let Some(previous) = merged.last_mut() {
                if range.start <= previous.end {
                    previous.end = previous.end.max(range.end);
                    continue;
                }
            }
            merged.push(range);
        }
        Some(merged)
    }

    pub fn RemoteMmap(&self, name: &CStr, len: u64, flags: u64) -> u64 {
        if self.pid <= 0 {
            return 0;
        }
        unsafe {
            self.Invoke(
                CMD_REMOTE_MMAP,
                [
                    self.pid as usize,
                    len as usize,
                    flags as usize,
                    name.as_ptr() as usize,
                    0,
                ],
            ) as u64
        }
    }

    pub fn UdpCapInitRaw(&self, target_pid: i32, min_payload: u16, max_payload: u16) -> isize {
        if target_pid <= 0
            || min_payload > max_payload
            || u32::from(max_payload) > UDP_CAP_MAX_PAYLOAD
        {
            return -22;
        }
        let request = UdpCapInitRequest {
            pid: target_pid,
            min_payload,
            max_payload,
            ..Default::default()
        };
        unsafe {
            self.Invoke(
                CMD_UDP_CAP_INIT,
                [(&request as *const UdpCapInitRequest) as usize, 0, 0, 0, 0],
            )
        }
    }

    pub fn UdpCapInit(&self, target_pid: i32, min_payload: u16, max_payload: u16) -> bool {
        self.UdpCapInitRaw(target_pid, min_payload, max_payload) >= 0
    }

    pub fn UdpCapRead(&self, packets: &mut [UdpCapPacket]) -> Option<UdpCapReadStats> {
        if packets.is_empty() {
            return None;
        }
        let max_count = packets.len().min(UDP_CAP_READ_MAX) as u32;
        let mut request = UdpCapReadRequest {
            buf: packets.as_mut_ptr() as u64,
            max_count,
            ..Default::default()
        };
        let result = unsafe {
            self.Invoke(
                CMD_UDP_CAP_READ,
                [
                    (&mut request as *mut UdpCapReadRequest) as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        if result < 0
            || request.out_count > max_count
            || request.out_count as usize > packets.len()
            || packets
                .iter()
                .take(request.out_count as usize)
                .any(|packet| u32::from(packet.payload_len) > UDP_CAP_MAX_PAYLOAD)
        {
            return None;
        }
        Some(UdpCapReadStats {
            count: request.out_count,
            overflow: request.overflow,
            captured: request.captured,
        })
    }

    pub fn UdpCapStop(&self) -> bool {
        unsafe { self.Invoke(CMD_UDP_CAP_STOP, [0; 5]) >= 0 }
    }

    /// 新内核的可选接口。错误码原样返回，由调用者决定何时重试；不重启 UDP。
    pub fn TcpCapInitRaw(&self, target_pid: i32) -> isize {
        if target_pid <= 0 {
            return -22;
        }
        let request = TcpCapInitRequest {
            pid: target_pid,
            abi_version: TCP_CAP_ABI_VERSION,
            ..Default::default()
        };
        unsafe {
            self.Invoke(
                CMD_TCP_CAP_INIT,
                [(&request as *const TcpCapInitRequest) as usize, 0, 0, 0, 0],
            )
        }
    }

    pub fn TcpCapRead(&self, chunks: &mut [TcpCapChunk]) -> Result<TcpCapReadStats, isize> {
        if chunks.is_empty() {
            return Err(-22);
        }
        let max_count = chunks.len().min(TCP_CAP_READ_MAX) as u32;
        let mut request = TcpCapReadRequest {
            buf: chunks.as_mut_ptr() as u64,
            max_count,
            ..Default::default()
        };
        let result = unsafe {
            self.Invoke(
                CMD_TCP_CAP_READ,
                [
                    (&mut request as *mut TcpCapReadRequest) as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(result);
        }
        // 未实现接口的旧驱动可能没有写回请求，不能将全零结果当成采集成功。
        if request.out_count > max_count
            || request.capture_id == 0
            || !matches!(
                request.status,
                TCP_CAP_STATUS_RUNNING | TCP_CAP_STATUS_TARGET_DEAD
            )
            || request.reserved != 0
            || chunks.iter().take(request.out_count as usize).any(|chunk| {
                chunk.capture_id != request.capture_id
                    || chunk.socket_id == 0
                    || chunk.payload_len as usize > TCP_CAP_MAX_PAYLOAD
                    || !matches!(chunk.family, 2 | 10)
                    || chunk.flags & !(TCP_CAP_F_NEW | TCP_CAP_F_GAP | TCP_CAP_F_CLOSED) != 0
                    || chunk
                        .stream_offset
                        .checked_add(u64::from(chunk.payload_len))
                        .is_none()
            })
        {
            return Err(-71); // EPROTO：拒绝错误的 ABI 布局或越界输出。
        }
        Ok(TcpCapReadStats {
            count: request.out_count,
            dropped: request.dropped,
            captured: request.captured,
            capture_id: request.capture_id,
            status: request.status,
        })
    }

    pub fn TcpCapStopRaw(&self) -> isize {
        unsafe { self.Invoke(CMD_TCP_CAP_STOP, [0; 5]) }
    }

    pub fn RegisterPageBreak(&self, pid: i32, address: u64) -> Option<PageBreakHandle<T>>
    where
        T: Clone,
    {
        self.RegisterOwned(pid, address, CMD_REGISTER_PAGE_HBRK)
            .map(|handle| PageBreakHandle {
                owner: BreakOwner::new(
                    self.scno,
                    self.option,
                    handle,
                    CMD_UNREGISTER_PAGE_HBRK,
                    self.transport.clone(),
                ),
            })
    }

    pub fn RegisterMmuBreak(&self, pid: i32, address: u64) -> Option<MmuBreakHandle<T>>
    where
        T: Clone,
    {
        self.RegisterOwned(pid, address, CMD_REGISTER_MMU_BRK)
            .map(|handle| MmuBreakHandle {
                owner: BreakOwner::new(
                    self.scno,
                    self.option,
                    handle,
                    CMD_UNREGISTER_MMU_BRK,
                    self.transport.clone(),
                ),
            })
    }

    pub fn RegisterShadowBreak(&self, pid: i32, address: u64) -> Option<ShadowBreakHandle<T>>
    where
        T: Clone,
    {
        self.RegisterOwned(pid, address, CMD_REGISTER_HBRK)
            .map(|handle| ShadowBreakHandle {
                owner: BreakOwner::new(
                    self.scno,
                    self.option,
                    handle,
                    CMD_UNREGISTER_HBRK,
                    self.transport.clone(),
                ),
            })
    }

    pub fn RegisterShadowHook(
        &self,
        pid: i32,
        address: u64,
        callback: u64,
        params: u64,
    ) -> Option<ShadowHookHandle<T>>
    where
        T: Clone,
    {
        if pid <= 0 || address == 0 {
            return None;
        }
        let result = unsafe {
            self.Invoke(
                CMD_REGISTER_SHADOW_HOOK,
                [
                    pid as usize,
                    address as usize,
                    callback as usize,
                    params as usize,
                    0,
                ],
            )
        };
        (result > 0).then(|| ShadowHookHandle {
            owner: BreakOwner::new(
                self.scno,
                self.option,
                result as u64,
                CMD_UNREGISTER_SHADOW_HOOK,
                self.transport.clone(),
            ),
        })
    }

    fn RegisterOwned(&self, pid: i32, address: u64, command: usize) -> Option<u64> {
        if pid <= 0 || address == 0 {
            return None;
        }
        let result = unsafe { self.Invoke(command, [pid as usize, address as usize, 0, 0, 0]) };
        (result > 0).then_some(result as u64)
    }
}

struct BreakOwner<T: KernelTransport> {
    scno: i32,
    option: u64,
    handle: u64,
    unregister_command: usize,
    transport: T,
}

impl<T: KernelTransport> BreakOwner<T> {
    fn new(scno: i32, option: u64, handle: u64, unregister_command: usize, transport: T) -> Self {
        Self {
            scno,
            option,
            handle,
            unregister_command,
            transport,
        }
    }

    fn RawHandle(&self) -> u64 {
        self.handle
    }

    unsafe fn Invoke(&self, command: usize, args: [usize; 5]) -> isize {
        unsafe { self.transport.Invoke(self.scno, self.option, command, args) }
    }
}

impl<T: KernelTransport> Drop for BreakOwner<T> {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        unsafe {
            let _ = self.Invoke(self.unregister_command, [self.handle as usize, 0, 0, 0, 0]);
        }
        self.handle = 0;
    }
}

pub struct PageBreakHandle<T: KernelTransport> {
    owner: BreakOwner<T>,
}

impl<T: KernelTransport> PageBreakHandle<T> {
    pub fn RawHandle(&self) -> u64 {
        self.owner.RawHandle()
    }

    pub fn SetRegisters(&self, registers: &mut PtRegsSet) -> bool {
        unsafe {
            self.owner.Invoke(
                CMD_SET_PAGE_HBRK_REGS,
                [
                    self.RawHandle() as usize,
                    registers as *mut PtRegsSet as usize,
                    0,
                    0,
                    0,
                ],
            ) > 0
        }
    }
}

pub struct MmuBreakHandle<T: KernelTransport> {
    owner: BreakOwner<T>,
}

impl<T: KernelTransport> MmuBreakHandle<T> {
    pub fn RawHandle(&self) -> u64 {
        self.owner.RawHandle()
    }

    pub fn SetShared(&self, config: &mut MmuBreakSharedConfig) -> bool {
        config.handle = self.RawHandle();
        unsafe {
            self.owner.Invoke(
                CMD_SET_MMU_BRK_SHARED,
                [config as *mut MmuBreakSharedConfig as usize, 0, 0, 0, 0],
            ) > 0
        }
    }

    pub fn Arm(&self) -> bool {
        unsafe {
            self.owner
                .Invoke(CMD_ARM_MMU_BRK, [self.RawHandle() as usize, 0, 0, 0, 0])
                > 0
        }
    }
}

pub struct ShadowBreakHandle<T: KernelTransport> {
    owner: BreakOwner<T>,
}

impl<T: KernelTransport> ShadowBreakHandle<T> {
    pub fn RawHandle(&self) -> u64 {
        self.owner.RawHandle()
    }

    pub fn SetRegister(&self, register: i8, value: u64) -> bool {
        unsafe {
            self.owner.Invoke(
                CMD_SET_HBRK_REGS,
                [
                    self.RawHandle() as usize,
                    register as usize,
                    value as usize,
                    0,
                    0,
                ],
            ) > 0
        }
    }
}

pub struct ShadowHookHandle<T: KernelTransport> {
    owner: BreakOwner<T>,
}

impl<T: KernelTransport> ShadowHookHandle<T> {
    pub fn RawHandle(&self) -> u64 {
        self.owner.RawHandle()
    }
}
