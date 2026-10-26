use std::time::{Duration, Instant};

use crate::monarch::arm64::{
    CpuState, DecodeError, DecodedInstruction, Decoder, ExclusiveMonitorState, ExecutionError,
    Executor, Mnemonic, PAuthService, Register, RejectSystemRegisterService, SystemRegisterService,
};
use crate::monarch::memory::TargetMemory;
use crate::monarch::services::{
    GuestServices, KernelServices, ServiceError as GuestServiceError, ENOSYS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    None,
    Completed,
    InstructionLimit,
    WallClockLimit,
    Cancelled,
    ObserverStop,
    HookStop,
    DecodeError,
    UnsupportedInstruction,
    MemoryFault,
    HookError,
    InternalError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    pub pc: u64,
    pub raw: u32,
    pub mnemonic_text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverPhase {
    Before,
    After,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverInfo {
    pub phase: ObserverPhase,
    pub pc: u64,
    pub raw: u32,
    pub mnemonic_text: String,
    pub instruction_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookAction {
    Unhandled,
    Continue,
    Return,
    Stop,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookResult {
    pub action: HookAction,
    pub value: u64,
    pub error: String,
}

impl HookResult {
    pub fn Handled(value: u64) -> Self {
        Self {
            action: HookAction::Continue,
            value,
            error: String::new(),
        }
    }

    pub fn Return(value: u64) -> Self {
        Self {
            action: HookAction::Return,
            value,
            error: String::new(),
        }
    }

    pub fn Stop(value: u64) -> Self {
        Self {
            action: HookAction::Stop,
            value,
            error: String::new(),
        }
    }

    pub fn Error(message: impl Into<String>) -> Self {
        Self {
            action: HookAction::Error,
            value: 0,
            error: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub begin: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn Contains(&self, address: u64) -> bool {
        self.begin < self.end && address >= self.begin && address < self.end
    }

    pub fn Single(address: u64) -> Self {
        Self {
            begin: address,
            end: if address == u64::MAX {
                address
            } else {
                address + 1
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallInfo {
    pub source_pc: u64,
    pub target: u64,
    pub return_address: u64,
    pub indirect: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallInfo {
    pub pc: u64,
    pub immediate: u32,
    pub number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonarchContext {
    pub state: CpuState,
    pub exclusive_monitor: Option<ExclusiveMonitorState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunOptions {
    pub instruction_limit: u64,
    pub wall_clock_limit: Duration,
    pub trace_limit: usize,
    pub stop_address: Option<u64>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            instruction_limit: 1_000_000,
            wall_clock_limit: Duration::ZERO,
            trace_limit: 0,
            stop_address: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResult {
    pub stop_reason: StopReason,
    pub error: String,
    pub pc: u64,
    pub instruction_count: u64,
    pub elapsed: Duration,
    pub trace: Vec<TraceEntry>,
}

impl Default for RunResult {
    fn default() -> Self {
        Self {
            stop_reason: StopReason::None,
            error: String::new(),
            pc: 0,
            instruction_count: 0,
            elapsed: Duration::ZERO,
            trace: Vec::new(),
        }
    }
}

impl RunResult {
    pub fn ok(&self) -> bool {
        matches!(
            self.stop_reason,
            StopReason::Completed | StopReason::HookStop | StopReason::ObserverStop
        )
    }
}

pub type CallHook = Box<dyn FnMut(&mut CpuState, &CallInfo) -> HookResult>;
pub type SyscallHook = Box<dyn FnMut(&mut CpuState, &SyscallInfo) -> HookResult>;
pub type Observer = Box<dyn FnMut(&mut CpuState, &ObserverInfo) -> HookResult>;
pub type CancelCallback = Box<dyn FnMut() -> bool>;

pub struct NoKernelServices;

impl KernelServices for NoKernelServices {
    fn ValidateKgslFd(&self, _pid: i32, _fd: u32) -> bool {
        false
    }

    fn PeekKgslSyncsourceId(
        &self,
        _pid: i32,
        _fd: u32,
        _min_id: u32,
    ) -> Result<u32, GuestServiceError> {
        Err(GuestServiceError::Infrastructure {
            operation: "kernel-services-unavailable".to_owned(),
            errno: ENOSYS,
            backend: 0,
        })
    }

    fn GpuobjIoctl(
        &self,
        _pid: i32,
        _fd: u32,
        _request: u64,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<i64, GuestServiceError> {
        Err(GuestServiceError::Infrastructure {
            operation: "kernel-services-unavailable".to_owned(),
            errno: ENOSYS,
            backend: 0,
        })
    }
}

struct CallHookEntry {
    range: AddressRange,
    callback: CallHook,
}

struct StepResult {
    executed: bool,
    stop_reason: StopReason,
    error: String,
}

pub struct Monarch<M, P, S = RejectSystemRegisterService, K = NoKernelServices>
where
    M: TargetMemory,
    P: PAuthService,
    S: SystemRegisterService,
    K: KernelServices,
{
    executor: Executor<M, P, S>,
    services: Option<GuestServices<K>>,
    decoder: Decoder,
    call_hooks: Vec<CallHookEntry>,
    syscall_hook: Option<SyscallHook>,
    observer: Option<Observer>,
    observe_after: bool,
    cancel_callback: Option<CancelCallback>,
    address_normalizer: fn(u64) -> u64,
}

impl<M, P, S> Monarch<M, P, S, NoKernelServices>
where
    M: TargetMemory,
    P: PAuthService,
    S: SystemRegisterService,
{
    pub fn New(executor: Executor<M, P, S>) -> Result<Self, DecodeError> {
        Ok(Self {
            executor,
            services: None,
            decoder: Decoder::New()?,
            call_hooks: Vec::new(),
            syscall_hook: None,
            observer: None,
            observe_after: true,
            cancel_callback: None,
            address_normalizer: IdentityAddress,
        })
    }
}

impl<M, P, S, K> Monarch<M, P, S, K>
where
    M: TargetMemory,
    P: PAuthService,
    S: SystemRegisterService,
    K: KernelServices,
{
    pub fn NewWithServices(
        executor: Executor<M, P, S>,
        services: GuestServices<K>,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            executor,
            services: Some(services),
            decoder: Decoder::New()?,
            call_hooks: Vec::new(),
            syscall_hook: None,
            observer: None,
            observe_after: true,
            cancel_callback: None,
            address_normalizer: IdentityAddress,
        })
    }

    pub fn Executor(&self) -> &Executor<M, P, S> {
        &self.executor
    }

    pub fn ExecutorMut(&mut self) -> &mut Executor<M, P, S> {
        &mut self.executor
    }

    pub fn Services(&self) -> Option<&GuestServices<K>> {
        self.services.as_ref()
    }

    pub fn ServicesMut(&mut self) -> Option<&mut GuestServices<K>> {
        self.services.as_mut()
    }

    pub fn SaveContext(&self) -> MonarchContext {
        MonarchContext {
            state: self.executor.Cpu().clone(),
            exclusive_monitor: self.executor.ExclusiveMonitor(),
        }
    }

    pub fn RestoreContext(&mut self, context: &MonarchContext) {
        *self.executor.CpuMut() = context.state.clone();
        self.executor.SetExclusiveMonitor(context.exclusive_monitor);
    }

    pub fn Reset(&mut self) {
        *self.executor.CpuMut() = CpuState::default();
        self.executor.SetExclusiveMonitor(None);
    }

    pub fn AddCallHook(&mut self, address: AddressRange, hook: CallHook) {
        if address.begin < address.end {
            self.call_hooks.push(CallHookEntry {
                range: address,
                callback: hook,
            });
        }
    }

    pub fn SetSyscallHook(&mut self, hook: SyscallHook) {
        self.syscall_hook = Some(hook);
    }

    pub fn ClearSyscallHook(&mut self) {
        self.syscall_hook = None;
    }

    pub fn SetObserver(&mut self, observer: Observer, observe_after: bool) {
        self.observer = Some(observer);
        self.observe_after = observe_after;
    }

    pub fn ClearObserver(&mut self) {
        self.observer = None;
    }

    pub fn SetCancelCallback(&mut self, callback: CancelCallback) {
        self.cancel_callback = Some(callback);
    }

    pub fn ClearCancelCallback(&mut self) {
        self.cancel_callback = None;
    }

    pub fn SetAddressNormalizer(&mut self, normalizer: fn(u64) -> u64) {
        self.address_normalizer = normalizer;
        self.executor.SetAddressNormalizer(normalizer);
    }

    pub fn ClearDecodeCache(&mut self) {}

    pub fn InvalidateDecodeCache(&mut self, _pc: u64) {}

    pub fn Run(&mut self, options: RunOptions) -> RunResult {
        let mut result = RunResult::default();
        let mut trace_cursor = 0;
        let mut trace_wrapped = false;
        if options.trace_limit != 0 {
            result.trace.reserve(options.trace_limit);
        }
        let started = Instant::now();

        loop {
            let pc = self.executor.Cpu().pc;
            if options.stop_address == Some(pc) {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    StopReason::Completed,
                    String::new(),
                );
            }
            if self
                .cancel_callback
                .as_mut()
                .is_some_and(|callback| callback())
            {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    StopReason::Cancelled,
                    String::new(),
                );
            }
            if options.instruction_limit != 0
                && result.instruction_count >= options.instruction_limit
            {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    StopReason::InstructionLimit,
                    "AArch64 instruction limit reached".to_owned(),
                );
            }
            if options.wall_clock_limit > Duration::ZERO
                && started.elapsed() >= options.wall_clock_limit
            {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    StopReason::WallClockLimit,
                    "AArch64 wall-clock limit reached".to_owned(),
                );
            }

            let (decoded, raw) = match self.PeekDecoded(pc) {
                Ok(value) => value,
                Err((reason, error)) => {
                    return self.Finish(
                        result,
                        trace_cursor,
                        trace_wrapped,
                        started,
                        reason,
                        error,
                    );
                }
            };

            if options.trace_limit != 0 {
                let entry = TraceEntry {
                    pc,
                    raw,
                    mnemonic_text: decoded.mnemonic_text.clone(),
                };
                if result.trace.len() < options.trace_limit {
                    result.trace.push(entry);
                } else {
                    result.trace[trace_cursor] = entry;
                    trace_cursor = (trace_cursor + 1) % options.trace_limit;
                    trace_wrapped = true;
                }
            }

            if let Some(step) = self.RunObserver(
                ObserverPhase::Before,
                &decoded,
                raw,
                result.instruction_count,
            ) {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    step.stop_reason,
                    step.error,
                );
            }
            if self.executor.Cpu().pc != pc {
                continue;
            }

            let step = self.ExecuteStep(&decoded);
            if step.executed {
                result.instruction_count += 1;
            }
            if step.stop_reason != StopReason::None {
                return self.Finish(
                    result,
                    trace_cursor,
                    trace_wrapped,
                    started,
                    step.stop_reason,
                    step.error,
                );
            }

            if self.observe_after {
                if let Some(step) = self.RunObserver(
                    ObserverPhase::After,
                    &decoded,
                    raw,
                    result.instruction_count,
                ) {
                    return self.Finish(
                        result,
                        trace_cursor,
                        trace_wrapped,
                        started,
                        step.stop_reason,
                        step.error,
                    );
                }
            }
        }
    }

    fn Finish(
        &self,
        mut result: RunResult,
        trace_cursor: usize,
        trace_wrapped: bool,
        started: Instant,
        stop_reason: StopReason,
        error: String,
    ) -> RunResult {
        if trace_wrapped && !result.trace.is_empty() {
            result.trace.rotate_left(trace_cursor);
        }
        result.stop_reason = stop_reason;
        result.error = error;
        result.pc = self.executor.Cpu().pc;
        result.elapsed = started.elapsed();
        result
    }

    fn PeekDecoded(&mut self, pc: u64) -> Result<(DecodedInstruction, u32), (StopReason, String)> {
        let mut bytes = [0_u8; 4];
        self.executor
            .MemoryMut()
            .Read(pc, &mut bytes)
            .map_err(|_| {
                (
                    StopReason::MemoryFault,
                    format!("instruction fetch failed at 0x{pc:X}"),
                )
            })?;
        let raw = u32::from_le_bytes(bytes);
        let decoded = self
            .decoder
            .Decode(pc, raw)
            .map_err(|error| (StopReason::DecodeError, error.to_string()))?;
        if matches!(decoded.mnemonic, Mnemonic::Unsupported(_)) {
            return Err((
                StopReason::UnsupportedInstruction,
                format!("unsupported AArch64 instruction 0x{raw:08X} at 0x{pc:X}"),
            ));
        }
        Ok((decoded, raw))
    }

    fn RunObserver(
        &mut self,
        phase: ObserverPhase,
        decoded: &DecodedInstruction,
        raw: u32,
        instruction_count: u64,
    ) -> Option<StepResult> {
        let observer = self.observer.as_mut()?;
        let info = ObserverInfo {
            phase,
            pc: decoded.pc,
            raw,
            mnemonic_text: decoded.mnemonic_text.clone(),
            instruction_count,
        };
        let observed = observer(self.executor.CpuMut(), &info);
        match observed.action {
            HookAction::Stop | HookAction::Return => Some(StepResult {
                executed: false,
                stop_reason: StopReason::ObserverStop,
                error: String::new(),
            }),
            HookAction::Error => Some(StepResult {
                executed: false,
                stop_reason: StopReason::HookError,
                error: if observed.error.is_empty() {
                    match phase {
                        ObserverPhase::Before => "AArch64 pre-observer failed".to_owned(),
                        ObserverPhase::After => "AArch64 post-observer failed".to_owned(),
                    }
                } else {
                    observed.error
                },
            }),
            HookAction::Unhandled | HookAction::Continue => None,
        }
    }

    fn ExecuteStep(&mut self, decoded: &DecodedInstruction) -> StepResult {
        if let Some(step) = self.TryExecuteDirectCall(decoded) {
            return step;
        }
        if let Some(step) = self.TryExecuteIndirectBranch(decoded) {
            return step;
        }
        if let Some(step) = self.TryExecuteAuthenticatedCall(decoded) {
            return step;
        }
        if matches!(decoded.mnemonic, Mnemonic::Svc) {
            return self.ExecuteSvc(decoded);
        }

        match self.executor.Step() {
            Ok(_) => StepResult {
                executed: true,
                stop_reason: StopReason::None,
                error: String::new(),
            },
            Err(error) => Self::MapExecutionError(error),
        }
    }

    fn TryExecuteDirectCall(&mut self, decoded: &DecodedInstruction) -> Option<StepResult> {
        if !matches!(decoded.mnemonic, Mnemonic::Bl) {
            return None;
        }
        let target = match decoded.operands.first() {
            Some(crate::monarch::arm64::Operand::Immediate(value)) => *value as u64,
            _ => {
                return Some(StepResult {
                    executed: true,
                    stop_reason: StopReason::DecodeError,
                    error: format!("malformed compact IR for BL at 0x{:X}", decoded.pc),
                });
            }
        };
        Some(self.ExecuteCall(decoded.pc, target, false))
    }

    fn TryExecuteIndirectBranch(&mut self, decoded: &DecodedInstruction) -> Option<StepResult> {
        match decoded.mnemonic {
            Mnemonic::Blr => {
                let register = self.BranchRegister(decoded)?;
                let target = Self::Normalize(
                    self.address_normalizer,
                    Self::ReadBranchRegister(self.executor.Cpu(), register),
                );
                Some(self.ExecuteCall(decoded.pc, target, true))
            }
            Mnemonic::Br => {
                let register = self.BranchRegister(decoded)?;
                let target = Self::Normalize(
                    self.address_normalizer,
                    Self::ReadBranchRegister(self.executor.Cpu(), register),
                );
                self.executor.CpuMut().pc = target;
                Some(StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                })
            }
            Mnemonic::Ret => {
                let register = self.BranchRegister(decoded).unwrap_or(Register::X(30));
                let target = Self::Normalize(
                    self.address_normalizer,
                    Self::ReadBranchRegister(self.executor.Cpu(), register),
                );
                self.executor.CpuMut().pc = target;
                Some(StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                })
            }
            _ => None,
        }
    }

    fn TryExecuteAuthenticatedCall(&mut self, decoded: &DecodedInstruction) -> Option<StepResult> {
        if !matches!(decoded.mnemonic, Mnemonic::Blraa | Mnemonic::Blrab) {
            return None;
        }

        let source_pc = decoded.pc;
        let next_pc = source_pc.wrapping_add(4);
        match self.executor.Step() {
            Ok(_) => {}
            Err(error) => return Some(Self::MapExecutionError(error)),
        }

        let target = self.executor.Cpu().pc;
        self.executor.CpuMut().pc = source_pc;
        let hooked = self.InvokeCallHook(CallInfo {
            source_pc,
            target,
            return_address: next_pc,
            indirect: true,
        });

        Some(match hooked.action {
            HookAction::Return => {
                if let Err(error) = self.executor.CpuMut().SetX(0, hooked.value) {
                    return Some(StepResult {
                        executed: true,
                        stop_reason: StopReason::InternalError,
                        error: error.to_string(),
                    });
                }
                self.executor.CpuMut().pc = next_pc;
                StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                }
            }
            HookAction::Stop => StepResult {
                executed: true,
                stop_reason: StopReason::HookStop,
                error: String::new(),
            },
            HookAction::Error => StepResult {
                executed: true,
                stop_reason: StopReason::HookError,
                error: if hooked.error.is_empty() {
                    "AArch64 call hook failed".to_owned()
                } else {
                    hooked.error
                },
            },
            HookAction::Unhandled | HookAction::Continue => {
                self.executor.CpuMut().pc = target;
                StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                }
            }
        })
    }

    fn ExecuteCall(&mut self, source_pc: u64, target: u64, indirect: bool) -> StepResult {
        let next_pc = source_pc.wrapping_add(4);
        if let Err(error) = self.executor.CpuMut().SetX(30, next_pc) {
            return StepResult {
                executed: true,
                stop_reason: StopReason::InternalError,
                error: error.to_string(),
            };
        }
        let info = CallInfo {
            source_pc,
            target,
            return_address: next_pc,
            indirect,
        };
        let hooked = self.InvokeCallHook(info);
        match hooked.action {
            HookAction::Return => {
                if let Err(error) = self.executor.CpuMut().SetX(0, hooked.value) {
                    return StepResult {
                        executed: true,
                        stop_reason: StopReason::InternalError,
                        error: error.to_string(),
                    };
                }
                self.executor.CpuMut().pc = next_pc;
                StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                }
            }
            HookAction::Stop => StepResult {
                executed: true,
                stop_reason: StopReason::HookStop,
                error: String::new(),
            },
            HookAction::Error => StepResult {
                executed: true,
                stop_reason: StopReason::HookError,
                error: if hooked.error.is_empty() {
                    "AArch64 call hook failed".to_owned()
                } else {
                    hooked.error
                },
            },
            HookAction::Unhandled | HookAction::Continue => {
                self.executor.CpuMut().pc = target;
                StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                }
            }
        }
    }

    fn ExecuteSvc(&mut self, decoded: &DecodedInstruction) -> StepResult {
        let svc_pc = decoded.pc;
        let next_pc = svc_pc.wrapping_add(4);
        let syscall_number = self.executor.Cpu().X(8).unwrap_or(0);
        let immediate = match decoded.operands.first() {
            Some(crate::monarch::arm64::Operand::Immediate(value)) => *value as u32,
            _ => 0,
        };

        match self.executor.Step() {
            Ok(_) => {}
            Err(error) => return Self::MapExecutionError(error),
        }

        let info = SyscallInfo {
            pc: svc_pc,
            immediate,
            number: syscall_number,
        };

        if let Some(hook) = self.syscall_hook.as_mut() {
            self.executor.CpuMut().pc = svc_pc;
            let hooked = hook(self.executor.CpuMut(), &info);
            return match hooked.action {
                HookAction::Error => {
                    self.executor.CpuMut().pc = svc_pc;
                    StepResult {
                        executed: true,
                        stop_reason: StopReason::HookError,
                        error: if hooked.error.is_empty() {
                            "AArch64 syscall hook failed".to_owned()
                        } else {
                            hooked.error
                        },
                    }
                }
                HookAction::Stop => {
                    self.executor.CpuMut().pc = svc_pc;
                    StepResult {
                        executed: true,
                        stop_reason: StopReason::HookStop,
                        error: String::new(),
                    }
                }
                HookAction::Unhandled => {
                    self.executor.CpuMut().pc = svc_pc;
                    StepResult {
                        executed: true,
                        stop_reason: StopReason::UnsupportedInstruction,
                        error: format!(
                            "unsupported AArch64 svc 0x{:08X} at 0x{:X}",
                            decoded.word, svc_pc
                        ),
                    }
                }
                HookAction::Continue | HookAction::Return => {
                    if let Err(error) = self.executor.CpuMut().SetX(0, hooked.value) {
                        return StepResult {
                            executed: true,
                            stop_reason: StopReason::InternalError,
                            error: error.to_string(),
                        };
                    }
                    self.executor.CpuMut().pc = next_pc;
                    StepResult {
                        executed: true,
                        stop_reason: StopReason::None,
                        error: String::new(),
                    }
                }
            };
        }

        if let Some(services) = self.services.as_mut() {
            return match services.DispatchSvc(&mut self.executor) {
                Ok(_) => StepResult {
                    executed: true,
                    stop_reason: StopReason::None,
                    error: String::new(),
                },
                Err(error) => {
                    self.executor.CpuMut().pc = svc_pc;
                    StepResult {
                        executed: true,
                        stop_reason: StopReason::HookError,
                        error: error.to_string(),
                    }
                }
            };
        }

        self.executor.CpuMut().pc = svc_pc;
        StepResult {
            executed: true,
            stop_reason: StopReason::UnsupportedInstruction,
            error: format!(
                "unsupported AArch64 svc 0x{:08X} at 0x{:X}",
                decoded.word, svc_pc
            ),
        }
    }

    fn InvokeCallHook(&mut self, info: CallInfo) -> HookResult {
        for entry in &mut self.call_hooks {
            if !entry.range.Contains(info.target) {
                continue;
            }
            let result = (entry.callback)(self.executor.CpuMut(), &info);
            if result.action != HookAction::Unhandled {
                return result;
            }
        }
        HookResult {
            action: HookAction::Unhandled,
            value: 0,
            error: String::new(),
        }
    }

    fn BranchRegister(&self, decoded: &DecodedInstruction) -> Option<Register> {
        match decoded.operands.first() {
            Some(crate::monarch::arm64::Operand::Register(register)) => Some(register.register),
            _ => None,
        }
    }

    fn ReadBranchRegister(cpu: &CpuState, register: Register) -> u64 {
        match register {
            Register::X(index) | Register::W(index) => cpu.x[index as usize],
            Register::Sp | Register::Wsp => cpu.sp,
            Register::Xzr | Register::Wzr => 0,
            Register::Vector { .. } => 0,
        }
    }

    fn Normalize(normalizer: fn(u64) -> u64, address: u64) -> u64 {
        normalizer(address)
    }

    fn MapExecutionError(error: ExecutionError) -> StepResult {
        match error {
            ExecutionError::Decode(error) => StepResult {
                executed: false,
                stop_reason: StopReason::DecodeError,
                error: error.to_string(),
            },
            ExecutionError::Unsupported { .. } => StepResult {
                executed: true,
                stop_reason: StopReason::UnsupportedInstruction,
                error: error.to_string(),
            },
            ExecutionError::Memory(_) => StepResult {
                executed: true,
                stop_reason: StopReason::MemoryFault,
                error: error.to_string(),
            },
            ExecutionError::PAuth { .. }
            | ExecutionError::SystemRegister { .. }
            | ExecutionError::AdvancedService { .. } => StepResult {
                executed: true,
                stop_reason: StopReason::HookError,
                error: error.to_string(),
            },
            ExecutionError::Malformed { .. } => StepResult {
                executed: true,
                stop_reason: StopReason::DecodeError,
                error: error.to_string(),
            },
            ExecutionError::Register(_) => StepResult {
                executed: true,
                stop_reason: StopReason::InternalError,
                error: error.to_string(),
            },
        }
    }
}

fn IdentityAddress(address: u64) -> u64 {
    address
}
