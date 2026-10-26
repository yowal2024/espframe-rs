use crate::monarch::arm64::{Executor, PAuthService, SystemRegisterService};
use crate::monarch::memory::{GuestMemory, MemoryError, TargetMemory};
use crate::monarch::svc_timing::SvcExceptionTicks;

use super::{
    EncodeErrno, GuestServices, KernelServices, ServiceError, ServiceWriteProvenance,
    SyscallResult, EFAULT, EINVAL, ENOSYS, ESRCH,
};

const NR_IOCTL: u64 = 29;
const NR_LSEEK: u64 = 62;
const NR_GETPID: u64 = 172;
const NR_GETTID: u64 = 178;
const NR_PROCESS_VM_WRITEV: u64 = 271;
const GUEST_IOV_MAX: u64 = 1024;
const PROCESS_VM_COPY_CHUNK_SIZE: usize = 0x1000;

impl<K: KernelServices> GuestServices<K> {
    pub fn DispatchSvc<M, P, S>(
        &mut self,
        executor: &mut Executor<M, P, S>,
    ) -> Result<SyscallResult, ServiceError>
    where
        M: TargetMemory,
        P: PAuthService,
        S: SystemRegisterService,
    {
        let post_svc_pc = executor.Cpu().pc;
        let svc_pc = post_svc_pc
            .checked_sub(4)
            .ok_or_else(|| ServiceError::Infrastructure {
                operation: "svc-pc".to_owned(),
                errno: EINVAL,
                backend: 0,
            })?;
        let syscall_number = executor
            .Cpu()
            .X(8)
            .map_err(|_| ServiceError::Infrastructure {
                operation: "svc-x8".to_owned(),
                errno: EINVAL,
                backend: 0,
            })?;
        let mut arguments = [0_u64; 6];
        for (index, value) in arguments.iter_mut().enumerate() {
            *value = executor
                .Cpu()
                .X(index)
                .map_err(|_| ServiceError::Infrastructure {
                    operation: "svc-arguments".to_owned(),
                    errno: EINVAL,
                    backend: 0,
                })?;
        }
        self.memory_diff.clear();
        self.exception_ticks = self.exception_ticks.wrapping_add(SvcExceptionTicks(
            syscall_number,
            NR_GETPID,
            NR_IOCTL,
            self.config.default_exception_ticks,
            self.config.getpid_exception_ticks,
            self.config.ioctl_exception_ticks,
        ));

        let state_before = self.state.clone();
        let memory_checkpoint = executor.MemoryMut().Checkpoint();
        let write_start = executor.Memory().Writes().len();
        let dispatched =
            self.DispatchSyscall::<M>(executor.MemoryMut(), svc_pc, syscall_number, arguments);
        match dispatched {
            Ok(x0) => {
                executor
                    .MemoryMut()
                    .Commit(memory_checkpoint)
                    .map_err(MemoryInfrastructure)?;
                executor
                    .CpuMut()
                    .SetX(0, x0)
                    .map_err(|_| ServiceError::Infrastructure {
                        operation: "svc-result".to_owned(),
                        errno: EINVAL,
                        backend: 0,
                    })?;
                debug_assert_eq!(executor.Cpu().pc, post_svc_pc);
                Ok(SyscallResult {
                    x0,
                    copied_out: executor.Memory().Writes()[write_start..].to_vec(),
                    memory_diff: self.memory_diff.clone(),
                    exception_ticks: self.exception_ticks,
                })
            }
            Err(ServiceError::GuestErrno { errno, .. }) => {
                let x0 = EncodeErrno(errno);
                executor
                    .MemoryMut()
                    .Commit(memory_checkpoint)
                    .map_err(MemoryInfrastructure)?;
                executor
                    .CpuMut()
                    .SetX(0, x0)
                    .map_err(|_| ServiceError::Infrastructure {
                        operation: "svc-guest-errno".to_owned(),
                        errno: EINVAL,
                        backend: 0,
                    })?;
                debug_assert_eq!(executor.Cpu().pc, post_svc_pc);
                Ok(SyscallResult {
                    x0,
                    copied_out: executor.Memory().Writes()[write_start..].to_vec(),
                    memory_diff: self.memory_diff.clone(),
                    exception_ticks: self.exception_ticks,
                })
            }
            Err(error) => {
                self.state = state_before;
                self.memory_diff.clear();
                executor
                    .MemoryMut()
                    .Rollback(memory_checkpoint)
                    .map_err(MemoryInfrastructure)?;
                executor.CpuMut().pc = svc_pc;
                Err(error)
            }
        }
    }

    fn DispatchSyscall<M>(
        &mut self,
        memory: &mut GuestMemory<M>,
        svc_pc: u64,
        syscall_number: u64,
        arguments: [u64; 6],
    ) -> Result<u64, ServiceError>
    where
        M: TargetMemory,
    {
        match syscall_number {
            NR_GETPID => Ok(self.config.pid as i64 as u64),
            NR_GETTID => Ok(self.config.tid as i64 as u64),
            NR_IOCTL => self.DispatchIoctl::<M>(
                memory,
                svc_pc,
                arguments[0] as u32,
                arguments[1] as u32,
                arguments[2],
            ),
            NR_LSEEK => Ok(0),
            NR_PROCESS_VM_WRITEV => self.EmulateProcessVmWritev(memory, svc_pc, arguments),
            _ => Ok(EncodeErrno(ENOSYS)),
        }
    }

    fn EmulateProcessVmWritev<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        svc_pc: u64,
        arguments: [u64; 6],
    ) -> Result<u64, ServiceError> {
        let requested_pid = arguments[0] as i64 as i32;
        let local_iov_address = arguments[1];
        let local_count = arguments[2];
        let remote_iov_address = arguments[3];
        let remote_count = arguments[4];
        let flags = arguments[5];
        if requested_pid != self.config.pid {
            return Ok(EncodeErrno(ESRCH));
        }
        if flags != 0 {
            return Ok(EncodeErrno(EINVAL));
        }
        if local_count == 0 || remote_count == 0 {
            return Ok(0);
        }
        if local_count > GUEST_IOV_MAX || remote_count > GUEST_IOV_MAX {
            return Ok(EncodeErrno(EINVAL));
        }
        let local = match SnapshotIovecs(memory, local_iov_address, local_count) {
            Ok(value) => value,
            Err(_) => return Ok(EncodeErrno(EFAULT)),
        };
        let remote = match SnapshotIovecs(memory, remote_iov_address, remote_count) {
            Ok(value) => value,
            Err(_) => return Ok(EncodeErrno(EFAULT)),
        };
        if !ValidIovecs(&local) || !ValidIovecs(&remote) {
            return Ok(EncodeErrno(EINVAL));
        }
        for iov in &local {
            if PreflightRange(memory, *iov).is_err() {
                return Ok(EncodeErrno(EFAULT));
            }
        }

        let mut local_index = 0_usize;
        let mut local_offset = 0_u64;
        let mut bytes_written = 0_u64;
        let mut buffer = [0_u8; PROCESS_VM_COPY_CHUNK_SIZE];
        for remote_iov in &remote {
            if PreflightRange(memory, *remote_iov).is_err() {
                if bytes_written == 0 {
                    return Ok(EncodeErrno(EFAULT));
                }
                break;
            }
            let mut remote_offset = 0_u64;
            while remote_offset < remote_iov.len {
                let local_iov = loop {
                    let Some(local_iov) = local.get(local_index) else {
                        return Ok(bytes_written);
                    };
                    if local_offset < local_iov.len {
                        break local_iov;
                    }
                    local_index = local_index
                        .checked_add(1)
                        .ok_or_else(|| MemoryInfrastructure(MemoryError::AddressOverflow))?;
                    local_offset = 0;
                };
                let count = (local_iov.len - local_offset)
                    .min(remote_iov.len - remote_offset)
                    .min(PROCESS_VM_COPY_CHUNK_SIZE as u64) as usize;
                let local_address = local_iov
                    .base
                    .checked_add(local_offset)
                    .ok_or(MemoryError::AddressOverflow)
                    .map_err(MemoryInfrastructure)?;
                let remote_address = remote_iov
                    .base
                    .checked_add(remote_offset)
                    .ok_or(MemoryError::AddressOverflow)
                    .map_err(MemoryInfrastructure)?;
                memory
                    .Read(local_address, &mut buffer[..count])
                    .map_err(MemoryInfrastructure)?;
                self.WriteMemory(
                    memory,
                    remote_address,
                    &buffer[..count],
                    svc_pc,
                    ServiceWriteProvenance::GuestCow,
                )
                .map_err(|_| ServiceError::Infrastructure {
                    operation: "process-vm-writev-cow".to_owned(),
                    errno: EFAULT,
                    backend: 0,
                })?;
                let count = count as u64;
                local_offset = local_offset
                    .checked_add(count)
                    .ok_or_else(|| MemoryInfrastructure(MemoryError::AddressOverflow))?;
                remote_offset = remote_offset
                    .checked_add(count)
                    .ok_or_else(|| MemoryInfrastructure(MemoryError::AddressOverflow))?;
                bytes_written = bytes_written
                    .checked_add(count)
                    .ok_or_else(|| MemoryInfrastructure(MemoryError::AddressOverflow))?;
            }
        }
        Ok(bytes_written)
    }
}

#[derive(Clone, Copy)]
struct GuestIovec {
    base: u64,
    len: u64,
}

fn ReadIovec<M: TargetMemory>(
    memory: &mut GuestMemory<M>,
    address: u64,
    index: u64,
) -> Result<GuestIovec, MemoryError> {
    let offset = index.checked_mul(16).ok_or(MemoryError::AddressOverflow)?;
    let address = address
        .checked_add(offset)
        .ok_or(MemoryError::AddressOverflow)?;
    let mut bytes = [0_u8; 16];
    memory.Read(address, &mut bytes)?;
    Ok(GuestIovec {
        base: u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        len: u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
    })
}

fn SnapshotIovecs<M: TargetMemory>(
    memory: &mut GuestMemory<M>,
    address: u64,
    count: u64,
) -> Result<Vec<GuestIovec>, MemoryError> {
    let capacity = usize::try_from(count).map_err(|_| MemoryError::AccessTooLarge)?;
    let mut iovecs = Vec::new();
    iovecs
        .try_reserve_exact(capacity)
        .map_err(|_| MemoryError::AccessTooLarge)?;
    for index in 0..count {
        iovecs.push(ReadIovec(memory, address, index)?);
    }
    Ok(iovecs)
}

fn ValidIovecs(iovecs: &[GuestIovec]) -> bool {
    let mut total = 0_u64;
    for iov in iovecs {
        if iov.len != 0 && iov.base.checked_add(iov.len - 1).is_none() {
            return false;
        }
        let Some(next) = total.checked_add(iov.len) else {
            return false;
        };
        if next > i64::MAX as u64 {
            return false;
        }
        total = next;
    }
    true
}

fn PreflightRange<M: TargetMemory>(
    memory: &mut GuestMemory<M>,
    iov: GuestIovec,
) -> Result<(), MemoryError> {
    let mut buffer = [0_u8; PROCESS_VM_COPY_CHUNK_SIZE];
    let mut offset = 0_u64;
    while offset < iov.len {
        let count = (iov.len - offset).min(PROCESS_VM_COPY_CHUNK_SIZE as u64) as usize;
        let address = iov
            .base
            .checked_add(offset)
            .ok_or(MemoryError::AddressOverflow)?;
        memory.Read(address, &mut buffer[..count])?;
        offset = offset
            .checked_add(count as u64)
            .ok_or(MemoryError::AddressOverflow)?;
    }
    Ok(())
}

fn MemoryInfrastructure(error: MemoryError) -> ServiceError {
    ServiceError::Infrastructure {
        operation: format!("guest-memory-transaction: {error}"),
        errno: EFAULT,
        backend: 0,
    }
}
