use std::sync::{Arc, Mutex};

use crate::monarch::arm64::{SystemRegister, SystemRegisterError, SystemRegisterService};
use crate::monarch::memory::{GuestMemory, MemoryError, MemoryWrite, TargetMemory};
use crate::monarch::svc_timing::GuestCounterValue;

mod ioctl;
mod kgsl;
mod syncsource;
mod syscall;

pub use ioctl::IoctlRequest;
pub use kgsl::VirtualKgslObject;

pub const EBADF: i32 = 9;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const ENOTTY: i32 = 25;
pub const ENOSPC: i32 = 28;
pub const ENOSYS: i32 = 38;
pub const ESRCH: i32 = 3;

pub trait KernelServices: Send + Sync {
    fn ValidateKgslFd(&self, pid: i32, fd: u32) -> bool;

    fn ValidateKgslFdChecked(&self, pid: i32, fd: u32) -> Result<bool, ServiceError> {
        Ok(self.ValidateKgslFd(pid, fd))
    }

    fn PeekKgslSyncsourceId(&self, pid: i32, fd: u32, min_id: u32) -> Result<u32, ServiceError>;

    fn PeekKgslSyncsourceIdChecked(
        &self,
        pid: i32,
        fd: u32,
        min_id: u32,
    ) -> Result<SyncsourcePeek, ServiceError> {
        self.PeekKgslSyncsourceId(pid, fd, min_id)
            .map(|id| SyncsourcePeek { id, backend: 0 })
    }

    fn GpuobjIoctl(
        &self,
        pid: i32,
        fd: u32,
        request: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<i64, ServiceError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncsourcePeek {
    pub id: u32,
    pub backend: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("guest service errno {errno} (backend 0x{backend:X})")]
    GuestErrno { errno: i32, backend: u32 },
    #[error(
        "service infrastructure failure during {operation}: errno={errno} backend=0x{backend:X}"
    )]
    Infrastructure {
        operation: String,
        errno: i32,
        backend: u32,
    },
    #[error("invalid service checkpoint")]
    InvalidCheckpoint,
}

impl ServiceError {
    pub fn GuestErrnoWithBackend(errno: i32, backend: u32) -> Self {
        Self::GuestErrno { errno, backend }
    }

    pub fn Errno(&self) -> i32 {
        match self {
            Self::GuestErrno { errno, .. } | Self::Infrastructure { errno, .. } => *errno,
            Self::InvalidCheckpoint => EINVAL,
        }
    }

    pub fn Backend(&self) -> u32 {
        match self {
            Self::GuestErrno { backend, .. } | Self::Infrastructure { backend, .. } => *backend,
            Self::InvalidCheckpoint => 0,
        }
    }

    pub fn IsInfrastructure(&self) -> bool {
        matches!(self, Self::Infrastructure { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    pub pid: i32,
    pub tid: i32,
    pub default_exception_ticks: u64,
    pub getpid_exception_ticks: u64,
    pub ioctl_exception_ticks: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            pid: -1,
            tid: -1,
            default_exception_ticks: 1,
            getpid_exception_ticks: 1,
            ioctl_exception_ticks: 1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtualServiceState {
    pub syncsources: Vec<u32>,
    pub objects: Vec<VirtualKgslObject>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCheckpoint {
    id: u64,
}

#[derive(Clone, Debug)]
struct CheckpointState {
    id: u64,
    state: VirtualServiceState,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct KernelCall {
    pub operation: String,
    pub pid: i32,
    pub fd: u32,
    pub min_id: u32,
    pub request: u64,
    pub input: String,
    pub output: String,
    pub result: i64,
    pub errno: i32,
    pub backend: u32,
}

impl KernelCall {
    pub fn Validation(pid: i32, fd: u32, valid: bool) -> Self {
        Self::ValidationResult(pid, fd, &Ok(valid))
    }

    pub fn ValidationResult(pid: i32, fd: u32, result: &Result<bool, ServiceError>) -> Self {
        let (rc, errno, backend) = match result {
            Ok(true) => (0, 0, 0),
            Ok(false) => (-1, EBADF, 0),
            Err(error) => (-1, error.Errno(), error.Backend()),
        };
        Self {
            operation: "validate-kgsl-fd".to_owned(),
            pid,
            fd,
            min_id: 0,
            request: 0,
            input: String::new(),
            output: String::new(),
            result: rc,
            errno,
            backend,
        }
    }

    pub fn Peek(
        pid: i32,
        fd: u32,
        min_id: u32,
        result: &Result<SyncsourcePeek, ServiceError>,
    ) -> Self {
        let (output, rc, errno, backend) = match result {
            Ok(peek) => (hex_u32(peek.id), 0, 0, peek.backend),
            Err(error) => (String::new(), -1, error.Errno(), error.Backend()),
        };
        Self {
            operation: "peek-syncsource".to_owned(),
            pid,
            fd,
            min_id,
            request: 0,
            input: String::new(),
            output,
            result: rc,
            errno,
            backend,
        }
    }

    pub fn Gpuobj(
        pid: i32,
        fd: u32,
        request: u64,
        input: &[u8],
        output: &[u8],
        result: &Result<i64, ServiceError>,
    ) -> Self {
        let (rc, errno, backend) = match result {
            Ok(value) => (*value, 0, 0),
            Err(error) => (-1, error.Errno(), error.Backend()),
        };
        Self {
            operation: "gpuobj-ioctl".to_owned(),
            pid,
            fd,
            min_id: 0,
            request,
            input: hex_bytes(input),
            output: hex_bytes(output),
            result: rc,
            errno,
            backend,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallResult {
    pub x0: u64,
    pub copied_out: Vec<MemoryWrite>,
    pub memory_diff: Vec<ServiceMemoryWrite>,
    pub exception_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceWriteProvenance {
    ServiceCopyOut,
    GuestCow,
}

impl ServiceWriteProvenance {
    pub fn Name(self) -> &'static str {
        match self {
            Self::ServiceCopyOut => "service-copy-out",
            Self::GuestCow => "guest-cow",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceMemoryWrite {
    pub pc: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub slot_mask: u8,
    pub provenance: ServiceWriteProvenance,
}

pub struct GuestServices<K> {
    kernel: K,
    config: ServiceConfig,
    state: VirtualServiceState,
    checkpoints: Vec<CheckpointState>,
    next_checkpoint_id: u64,
    exception_ticks: u64,
    kernel_calls: Vec<KernelCall>,
    memory_diff: Vec<ServiceMemoryWrite>,
}

impl<K: KernelServices> GuestServices<K> {
    pub fn New(kernel: K, config: ServiceConfig) -> Self {
        Self {
            kernel,
            config,
            state: VirtualServiceState::default(),
            checkpoints: Vec::new(),
            next_checkpoint_id: 1,
            exception_ticks: 0,
            kernel_calls: Vec::new(),
            memory_diff: Vec::new(),
        }
    }

    pub fn Kernel(&self) -> &K {
        &self.kernel
    }

    pub fn KernelCalls(&self) -> &[KernelCall] {
        &self.kernel_calls
    }

    pub fn MemoryDiff(&self) -> &[ServiceMemoryWrite] {
        &self.memory_diff
    }

    pub fn ExceptionTicks(&self) -> u64 {
        self.exception_ticks
    }

    pub fn SetExceptionTicks(&mut self, value: u64) {
        self.exception_ticks = value;
    }

    pub fn VirtualSyncsources(&self) -> &[u32] {
        &self.state.syncsources
    }

    pub fn VirtualObjects(&self) -> &[VirtualKgslObject] {
        &self.state.objects
    }

    pub fn SeedVirtualSyncsources(&mut self, ids: &[u32]) {
        self.state.syncsources = ids.to_vec();
        self.state.syncsources.sort_unstable();
        self.state.syncsources.dedup();
    }

    pub fn SeedVirtualObjects<I>(&mut self, objects: I)
    where
        I: IntoIterator<Item = VirtualKgslObject>,
    {
        self.state.objects = objects.into_iter().collect();
        self.state
            .objects
            .sort_by_key(|object| (object.fd, object.id));
    }

    pub fn RemoveVirtualSyncsource(&mut self, id: u32) -> Result<(), ServiceError> {
        let Some(index) = self
            .state
            .syncsources
            .iter()
            .position(|candidate| *candidate == id)
        else {
            return Err(ServiceError::GuestErrno {
                errno: EINVAL,
                backend: 0,
            });
        };
        self.state.syncsources.remove(index);
        Ok(())
    }

    pub fn Checkpoint(&mut self) -> ServiceCheckpoint {
        let id = self.next_checkpoint_id;
        self.next_checkpoint_id = self.next_checkpoint_id.wrapping_add(1).max(1);
        self.checkpoints.push(CheckpointState {
            id,
            state: self.state.clone(),
        });
        ServiceCheckpoint { id }
    }

    pub fn Rollback(&mut self, checkpoint: ServiceCheckpoint) -> Result<(), ServiceError> {
        let index = self
            .checkpoints
            .iter()
            .position(|state| state.id == checkpoint.id)
            .ok_or(ServiceError::InvalidCheckpoint)?;
        let snapshot = self.checkpoints.remove(index);
        self.checkpoints.truncate(index);
        self.state = snapshot.state;
        Ok(())
    }

    pub fn Commit(&mut self, checkpoint: ServiceCheckpoint) -> Result<(), ServiceError> {
        let index = self
            .checkpoints
            .iter()
            .position(|state| state.id == checkpoint.id)
            .ok_or(ServiceError::InvalidCheckpoint)?;
        self.checkpoints.remove(index);
        Ok(())
    }

    pub(super) fn WriteMemory<M: TargetMemory>(
        &mut self,
        memory: &mut GuestMemory<M>,
        address: u64,
        bytes: &[u8],
        pc: u64,
        provenance: ServiceWriteProvenance,
    ) -> Result<(), MemoryError> {
        memory.Write(address, bytes, pc)?;
        let write = memory.Writes().last().expect("successful guest write");
        self.memory_diff.push(ServiceMemoryWrite {
            pc: write.pc,
            address: write.address,
            bytes: write.bytes.clone(),
            slot_mask: write.slot_mask,
            provenance,
        });
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewedSystemRegisterValues {
    pub ctr_el0: u64,
    pub cntfrq_el0: u64,
    pub tpidr_el0: u64,
    pub cntvct_base: u64,
    pub instruction_count: u64,
    pub exception_ticks: u64,
    pub scale_by_core_frequency: bool,
    pub assumed_core_frequency: u64,
}

#[derive(Clone)]
pub struct ReviewedSystemRegisterService {
    values: Arc<Mutex<ReviewedSystemRegisterValues>>,
}

impl ReviewedSystemRegisterService {
    pub fn New(ctr_el0: u64, cntfrq_el0: u64, tpidr_el0: u64, cntvct_base: u64) -> Self {
        Self {
            values: Arc::new(Mutex::new(ReviewedSystemRegisterValues {
                ctr_el0,
                cntfrq_el0,
                tpidr_el0,
                cntvct_base,
                instruction_count: 0,
                exception_ticks: 0,
                scale_by_core_frequency: false,
                assumed_core_frequency: 2_600_000_000,
            })),
        }
    }

    pub fn ReviewedValues(&self) -> ReviewedSystemRegisterValues {
        *self.values.lock().expect("reviewed system register lock")
    }

    pub fn SetProgress(&self, instruction_count: u64, exception_ticks: u64) {
        let mut values = self.values.lock().expect("reviewed system register lock");
        values.instruction_count = instruction_count;
        values.exception_ticks = exception_ticks;
    }

    pub fn SetCounterScaling(&self, enabled: bool, assumed_core_frequency: u64) {
        let mut values = self.values.lock().expect("reviewed system register lock");
        values.scale_by_core_frequency = enabled;
        values.assumed_core_frequency = assumed_core_frequency;
    }
}

impl SystemRegisterService for ReviewedSystemRegisterService {
    fn Read(&self, _tid: i32, register: SystemRegister) -> Result<u64, SystemRegisterError> {
        let values = self.values.lock().expect("reviewed system register lock");
        match register {
            SystemRegister::CtrEl0 => Ok(values.ctr_el0),
            SystemRegister::CntfrqEl0 => Ok(values.cntfrq_el0),
            SystemRegister::TpidrEl0 => Ok(values.tpidr_el0),
            SystemRegister::CntvctEl0 => Ok(GuestCounterValue(
                values.cntvct_base,
                values.instruction_count,
                values.exception_ticks,
                values.scale_by_core_frequency,
                values.cntfrq_el0,
                values.assumed_core_frequency,
            )),
        }
    }

    fn Write(
        &self,
        _tid: i32,
        register: SystemRegister,
        value: u64,
    ) -> Result<(), SystemRegisterError> {
        if register != SystemRegister::TpidrEl0 {
            return Err(SystemRegisterError::Unavailable(register));
        }
        self.values
            .lock()
            .expect("reviewed system register lock")
            .tpidr_el0 = value;
        Ok(())
    }
}

pub(super) fn EncodeErrno(errno: i32) -> u64 {
    (-i64::from(errno)) as u64
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}

fn hex_u32(value: u32) -> String {
    hex_bytes(&value.to_le_bytes())
}
