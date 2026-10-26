use super::decode::{
    AddressMode, DecodedInstruction, Decoder, Extend, Mnemonic, Operand, RegisterOperand, Shift,
};
use super::pauth::{PAuthOperation, PAuthService};
use super::system_registers::{RejectSystemRegisterService, SystemRegister, SystemRegisterService};
use super::{Condition, CpuState, Register, RegisterError, VectorArrangement};
use crate::monarch::advanced_services::{
    AdvancedServiceError, AtomicRcwInfo, AtomicRcwOperation, AtomicRcwService, ExceptionReturnInfo,
    ExceptionReturnService, GcsInfo, GcsOperation, GcsService, MemoryTagInfo, MemoryTagOperation,
    MemoryTagService, MopsInfo, MopsOperation, MopsService, RejectAtomicRcwService,
    RejectExceptionReturnService, RejectGcsService, RejectMemoryTagService, RejectMopsService,
    RejectStore64Service, Store64Info, Store64Operation, Store64Service,
};
use crate::monarch::memory::{GuestMemory, MemoryError, TargetMemory};

const N: u32 = 1 << 31;
const Z: u32 = 1 << 30;
const C: u32 = 1 << 29;
const V: u32 = 1 << 28;
const FPSR_IOC: u32 = 1 << 0;
const FPSR_IXC: u32 = 1 << 4;
const FPSR_ARCHITECTED_MASK: u32 = 0xF800_009F;
#[cfg(target_arch = "aarch64")]
const FPCR_EXCEPTION_ENABLE_MASK: u32 =
    (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 15);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepWrite {
    pub pc: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub slot_mask: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExclusiveMonitorState {
    pub address: u64,
    pub size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Continue,
    Branch,
    Svc,
}

impl StepOutcome {
    pub fn Name(&self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Branch => "branch",
            Self::Svc => "svc",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error(transparent)]
    Decode(#[from] super::decode::DecodeError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error(transparent)]
    Register(#[from] RegisterError),
    #[error("unsupported AArch64 {mnemonic} 0x{word:08X} at 0x{pc:X}")]
    Unsupported {
        pc: u64,
        word: u32,
        mnemonic: String,
    },
    #[error("malformed {mnemonic} instruction at 0x{pc:X}")]
    Malformed { pc: u64, mnemonic: String },
    #[error("pointer authentication callback failed at 0x{pc:X}: {message}")]
    PAuth { pc: u64, message: String },
    #[error("system register callback failed for {mnemonic} at 0x{pc:X}: {message}")]
    SystemRegister {
        pc: u64,
        mnemonic: String,
        message: String,
    },
    #[error("advanced service callback failed for {mnemonic} at 0x{pc:X}: {message}")]
    AdvancedService {
        pc: u64,
        mnemonic: String,
        message: String,
    },
}

pub struct Executor<
    M,
    P,
    S = RejectSystemRegisterService,
    A = RejectAtomicRcwService,
    T = RejectMemoryTagService,
    L = RejectStore64Service,
    G = RejectGcsService,
    O = RejectMopsService,
    E = RejectExceptionReturnService,
> {
    cpu: CpuState,
    memory: GuestMemory<M>,
    pauth: P,
    system_registers: S,
    atomic_rcw: A,
    memory_tags: T,
    store64: L,
    gcs: G,
    mops: O,
    exception_return: E,
    tid: i32,
    decoder: Decoder,
    exclusive: Option<(u64, usize)>,
    address_normalizer: fn(u64) -> u64,
}

impl<M: TargetMemory, P: PAuthService>
    Executor<
        M,
        P,
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
    >
{
    pub fn New(
        cpu: CpuState,
        memory: GuestMemory<M>,
        pauth: P,
        tid: i32,
    ) -> Result<Self, ExecutionError> {
        Self::NewWithSystemRegisters(cpu, memory, pauth, RejectSystemRegisterService, tid)
    }
}

impl<M: TargetMemory, P: PAuthService, S: SystemRegisterService>
    Executor<
        M,
        P,
        S,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
    >
{
    pub fn NewWithSystemRegisters(
        cpu: CpuState,
        memory: GuestMemory<M>,
        pauth: P,
        system_registers: S,
        tid: i32,
    ) -> Result<Self, ExecutionError> {
        Self::NewWithAdvancedServices(
            cpu,
            memory,
            pauth,
            system_registers,
            RejectAtomicRcwService,
            RejectMemoryTagService,
            RejectStore64Service,
            RejectGcsService,
            RejectMopsService,
            RejectExceptionReturnService,
            tid,
        )
    }
}

impl<
        M: TargetMemory,
        P: PAuthService,
        S: SystemRegisterService,
        A: AtomicRcwService,
        T: MemoryTagService,
        L: Store64Service,
        G: GcsService,
        O: MopsService,
        E: ExceptionReturnService,
    > Executor<M, P, S, A, T, L, G, O, E>
{
    #[allow(clippy::too_many_arguments)]
    pub fn NewWithAdvancedServices(
        cpu: CpuState,
        memory: GuestMemory<M>,
        pauth: P,
        system_registers: S,
        atomic_rcw: A,
        memory_tags: T,
        store64: L,
        gcs: G,
        mops: O,
        exception_return: E,
        tid: i32,
    ) -> Result<Self, ExecutionError> {
        Ok(Self {
            cpu,
            memory,
            pauth,
            system_registers,
            atomic_rcw,
            memory_tags,
            store64,
            gcs,
            mops,
            exception_return,
            tid,
            decoder: Decoder::New()?,
            exclusive: None,
            address_normalizer: IdentityAddress,
        })
    }

    pub fn Cpu(&self) -> &CpuState {
        &self.cpu
    }

    pub fn CpuMut(&mut self) -> &mut CpuState {
        &mut self.cpu
    }

    pub fn ExclusiveMonitor(&self) -> Option<ExclusiveMonitorState> {
        self.exclusive
            .map(|(address, size)| ExclusiveMonitorState { address, size })
    }

    pub fn SetExclusiveMonitor(&mut self, monitor: Option<ExclusiveMonitorState>) {
        self.exclusive = monitor.map(|state| (state.address, state.size));
    }

    pub fn Memory(&self) -> &GuestMemory<M> {
        &self.memory
    }

    pub fn MemoryMut(&mut self) -> &mut GuestMemory<M> {
        &mut self.memory
    }

    pub fn SetAddressNormalizer(&mut self, normalizer: fn(u64) -> u64) {
        self.address_normalizer = normalizer;
    }

    pub fn Step(&mut self) -> Result<StepOutcome, ExecutionError> {
        let pc = self.cpu.pc;
        let mut bytes = [0; 4];
        self.memory.Read(pc, &mut bytes)?;
        let word = u32::from_le_bytes(bytes);
        let instruction = self.decoder.Decode(pc, word)?;
        self.Execute(instruction)
    }

    fn Execute(&mut self, instruction: DecodedInstruction) -> Result<StepOutcome, ExecutionError> {
        let _advanced_services = (
            &self.memory_tags,
            &self.store64,
            &self.gcs,
            &self.mops,
            &self.exception_return,
        );
        let pc = instruction.pc;
        let next_pc = pc.wrapping_add(4);
        let mnemonic = instruction.mnemonic.clone();
        let result = match mnemonic {
            Mnemonic::Nop
            | Mnemonic::Hint
            | Mnemonic::Dmb
            | Mnemonic::Dsb
            | Mnemonic::Isb
            | Mnemonic::Ic
            | Mnemonic::Dc
            | Mnemonic::Prfm
            | Mnemonic::Clrex => {
                if matches!(instruction.mnemonic, Mnemonic::Clrex) {
                    self.exclusive = None;
                }
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Brk => return Err(self.Unsupported(&instruction)),
            Mnemonic::Svc => {
                self.exclusive = None;
                self.cpu.pc = next_pc;
                StepOutcome::Svc
            }
            Mnemonic::B => {
                let target = Self::Immediate(&instruction, 0)? as u64;
                let taken = instruction.condition == Condition::None
                    || instruction.condition == Condition::Al
                    || instruction.condition.Holds(self.cpu.nzcv);
                self.cpu.pc = if taken { target } else { next_pc };
                if taken {
                    StepOutcome::Branch
                } else {
                    StepOutcome::Continue
                }
            }
            Mnemonic::Bl => {
                let target = Self::Immediate(&instruction, 0)? as u64;
                self.cpu.SetX(30, next_pc)?;
                self.cpu.pc = target;
                StepOutcome::Branch
            }
            Mnemonic::Br | Mnemonic::Blr | Mnemonic::Ret => {
                let register = Self::Register(&instruction, 0)?;
                let target = self.cpu.ReadRegister(register)?;
                if matches!(instruction.mnemonic, Mnemonic::Blr) {
                    self.cpu.SetX(30, next_pc)?;
                }
                self.cpu.pc = target;
                StepOutcome::Branch
            }
            Mnemonic::Braa
            | Mnemonic::Brab
            | Mnemonic::Blraa
            | Mnemonic::Blrab
            | Mnemonic::Retaa
            | Mnemonic::Retab => {
                let call = matches!(instruction.mnemonic, Mnemonic::Blraa | Mnemonic::Blrab);
                let target = self.ExecuteAuthenticatedBranch(&instruction, call)?;
                self.cpu.pc = target;
                StepOutcome::Branch
            }
            Mnemonic::Eretaa | Mnemonic::Eretab => {
                let target = self.ExecuteExceptionReturn(&instruction)?;
                self.cpu.pc = target;
                StepOutcome::Branch
            }
            Mnemonic::Cbz | Mnemonic::Cbnz => {
                let value = self.cpu.ReadRegister(Self::Register(&instruction, 0)?)?;
                let target = Self::Immediate(&instruction, 1)? as u64;
                let zero = value == 0;
                let taken = if matches!(instruction.mnemonic, Mnemonic::Cbz) {
                    zero
                } else {
                    !zero
                };
                self.cpu.pc = if taken { target } else { next_pc };
                if taken {
                    StepOutcome::Branch
                } else {
                    StepOutcome::Continue
                }
            }
            Mnemonic::Tbz | Mnemonic::Tbnz => {
                let value = self.cpu.ReadRegister(Self::Register(&instruction, 0)?)?;
                let bit = Self::Immediate(&instruction, 1)? as u32;
                let target = Self::Immediate(&instruction, 2)? as u64;
                let set = ((value >> (bit & 63)) & 1) != 0;
                let taken = if matches!(instruction.mnemonic, Mnemonic::Tbz) {
                    !set
                } else {
                    set
                };
                self.cpu.pc = if taken { target } else { next_pc };
                if taken {
                    StepOutcome::Branch
                } else {
                    StepOutcome::Continue
                }
            }
            Mnemonic::Addg
            | Mnemonic::Subg
            | Mnemonic::Gmi
            | Mnemonic::Irg
            | Mnemonic::Subp
            | Mnemonic::Subps => {
                self.ExecuteTaggedArithmetic(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Adr | Mnemonic::Adrp => {
                let destination = Self::Register(&instruction, 0)?;
                let immhi = u64::from((instruction.word >> 5) & 0x7ffff);
                let immlo = u64::from((instruction.word >> 29) & 3);
                let immediate = SignExtend((immhi << 2) | immlo, 21) as i64;
                let value = if matches!(instruction.mnemonic, Mnemonic::Adrp) {
                    (pc & !0xfff).wrapping_add((immediate * 4096) as u64)
                } else {
                    pc.wrapping_add(immediate as u64)
                };
                self.cpu.WriteRegister(destination, value)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Mov
            | Mnemonic::Ins
            | Mnemonic::Umov
            | Mnemonic::Movz
            | Mnemonic::Movn
            | Mnemonic::Movk => {
                self.ExecuteMove(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Mvn => {
                if HasVectorOperand(&instruction) {
                    self.ExecuteVector(&instruction)?;
                } else {
                    let destination = Self::Register(&instruction, 0)?;
                    let source = Self::Value(&mut self.cpu, &instruction, 1)?;
                    self.cpu.WriteRegister(destination, !source)?;
                }
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Sxtw
            | Mnemonic::Bfm
            | Mnemonic::Sbfm
            | Mnemonic::Ubfm
            | Mnemonic::Ubfiz
            | Mnemonic::Ubfx
            | Mnemonic::Bfi
            | Mnemonic::Sbfx
            | Mnemonic::Bfxil
            | Mnemonic::Bfc
            | Mnemonic::Sbfiz => {
                self.ExecuteBitfield(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Neg => {
                let destination = Self::Register(&instruction, 0)?;
                let source = Self::Value(&mut self.cpu, &instruction, 1)?;
                self.cpu
                    .WriteRegister(destination, 0_u64.wrapping_sub(source))?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Add
            | Mnemonic::Adds
            | Mnemonic::Sub
            | Mnemonic::Subs
            | Mnemonic::Adc
            | Mnemonic::Adcs
            | Mnemonic::Sbc
            | Mnemonic::Sbcs => {
                if HasVectorOperand(&instruction)
                    && matches!(instruction.mnemonic, Mnemonic::Add | Mnemonic::Sub)
                {
                    self.ExecuteVector(&instruction)?;
                } else {
                    self.ExecuteAddSub(&instruction)?;
                }
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::And
            | Mnemonic::Ands
            | Mnemonic::Bic
            | Mnemonic::Bics
            | Mnemonic::Orr
            | Mnemonic::Orn
            | Mnemonic::Eor
            | Mnemonic::Eon => {
                if HasVectorOperand(&instruction) {
                    self.ExecuteVector(&instruction)?;
                } else {
                    self.ExecuteLogical(&instruction)?;
                }
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Lsl | Mnemonic::Lsr | Mnemonic::Asr | Mnemonic::Ror => {
                self.ExecuteShift(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Clz | Mnemonic::Rbit | Mnemonic::Rev | Mnemonic::Rev16 | Mnemonic::Rev32 => {
                if HasVectorArrangement(&instruction) {
                    self.ExecuteVector(&instruction)?;
                } else {
                    self.ExecuteBitOperation(&instruction)?;
                }
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Extr => {
                self.ExecuteExtract(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Madd
            | Mnemonic::Mul
            | Mnemonic::Msub
            | Mnemonic::Umaddl
            | Mnemonic::Umsubl
            | Mnemonic::Smaddl
            | Mnemonic::Smull
            | Mnemonic::Smsubl
            | Mnemonic::Umull => {
                self.ExecuteMultiply(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Smulh | Mnemonic::Umulh => {
                self.ExecuteMultiplyHigh(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Udiv | Mnemonic::Sdiv => {
                let destination = Self::Register(&instruction, 0)?;
                let lhs = Self::Value(&mut self.cpu, &instruction, 1)?;
                let rhs = Self::Value(&mut self.cpu, &instruction, 2)?;
                let value = if rhs == 0 {
                    0
                } else if matches!(instruction.mnemonic, Mnemonic::Udiv) {
                    if destination.Width() == 32 {
                        u64::from((lhs as u32) / (rhs as u32))
                    } else {
                        lhs / rhs
                    }
                } else if destination.Width() == 32 {
                    u64::from((lhs as u32 as i32).wrapping_div(rhs as u32 as i32) as u32)
                } else {
                    ((lhs as i64).wrapping_div(rhs as i64)) as u64
                };
                self.cpu.WriteRegister(destination, value)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Cmp | Mnemonic::Cmn | Mnemonic::Tst => {
                self.ExecuteCompare(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ccmp | Mnemonic::Ccmn => {
                self.ExecuteConditionalCompare(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Csel
            | Mnemonic::Cset
            | Mnemonic::Csinc
            | Mnemonic::Csinv
            | Mnemonic::Csneg => {
                self.ExecuteConditionalSelect(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldraa | Mnemonic::Ldrab => {
                self.ExecuteAuthenticatedLoad(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldr
            | Mnemonic::Ldur
            | Mnemonic::Ldurb
            | Mnemonic::Ldrb
            | Mnemonic::Ldrh
            | Mnemonic::Ldpsw
            | Mnemonic::Ldurh
            | Mnemonic::Ldursb
            | Mnemonic::Ldursh
            | Mnemonic::Ldursw
            | Mnemonic::Ldrsb
            | Mnemonic::Ldrsh
            | Mnemonic::Ldrsw
            | Mnemonic::Ldp
            | Mnemonic::Str
            | Mnemonic::Stur
            | Mnemonic::Sturb
            | Mnemonic::Sturh
            | Mnemonic::Strb
            | Mnemonic::Strh
            | Mnemonic::Stp => {
                self.ExecuteLoadStore(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ld1 => {
                self.ExecuteLd1(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldadd
            | Mnemonic::Ldclr
            | Mnemonic::Ldeor
            | Mnemonic::Ldset
            | Mnemonic::Ldsmax
            | Mnemonic::Ldsmin
            | Mnemonic::Ldumax
            | Mnemonic::Ldumin
            | Mnemonic::Swp => {
                self.ExecuteAtomicRmw(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldclrp | Mnemonic::Ldsetp | Mnemonic::Swpp => {
                self.ExecuteAtomicRmwPair(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Rcwcas
            | Mnemonic::Rcwscas
            | Mnemonic::Rcwclr
            | Mnemonic::Rcwsclr
            | Mnemonic::Rcwset
            | Mnemonic::Rcwsset
            | Mnemonic::Rcwswp
            | Mnemonic::Rcwsswp
            | Mnemonic::Rcwcasp
            | Mnemonic::Rcwscasp
            | Mnemonic::Rcwclrp
            | Mnemonic::Rcwsclrp
            | Mnemonic::Rcwsetp
            | Mnemonic::Rcwssetp
            | Mnemonic::Rcwswpp
            | Mnemonic::Rcwsswpp => {
                self.ExecuteAtomicRcw(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldfadd
            | Mnemonic::Ldfmax
            | Mnemonic::Ldfmin
            | Mnemonic::Ldfmaxnm
            | Mnemonic::Ldfminnm
            | Mnemonic::Ldbfadd
            | Mnemonic::Ldbfmax
            | Mnemonic::Ldbfmin
            | Mnemonic::Ldbfmaxnm
            | Mnemonic::Ldbfminnm => {
                self.ExecuteLsfe(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ld64b | Mnemonic::St64b | Mnemonic::St64bv | Mnemonic::St64bv0 => {
                self.ExecuteStore64(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldg
            | Mnemonic::Ldgm
            | Mnemonic::Stg
            | Mnemonic::Stgm
            | Mnemonic::Stgp
            | Mnemonic::Stzg
            | Mnemonic::Stzgm
            | Mnemonic::St2g
            | Mnemonic::Stz2g => {
                self.ExecuteMemoryTag(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::MopsCopy | Mnemonic::MopsSet | Mnemonic::MopsSetg | Mnemonic::MopsSetgo => {
                self.ExecuteMops(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Gcspopcx
            | Mnemonic::Gcspopm
            | Mnemonic::Gcspopx
            | Mnemonic::Gcspushm
            | Mnemonic::Gcspushx
            | Mnemonic::Gcsss1
            | Mnemonic::Gcsss2 => {
                self.ExecuteGcs(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Ldxr | Mnemonic::Ldaxr | Mnemonic::Stxr | Mnemonic::Stlxr => {
                self.ExecuteExclusive(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Cas | Mnemonic::Casp => {
                self.ExecuteCompareAndSwap(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Mrs | Mnemonic::Msr => {
                self.ExecuteSystemRegister(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Pacga
            | Mnemonic::Pacia
            | Mnemonic::Pacib
            | Mnemonic::Pacda
            | Mnemonic::Pacdb
            | Mnemonic::Autia
            | Mnemonic::Autib
            | Mnemonic::Autda
            | Mnemonic::Autdb
            | Mnemonic::Xpaci
            | Mnemonic::Xpacd => {
                self.ExecutePAuth(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::PaciaSp | Mnemonic::PacibSp | Mnemonic::AutiaSp | Mnemonic::AutibSp => {
                self.ExecutePAuthSp(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Fmov
            | Mnemonic::Ucvtf
            | Mnemonic::Scvtf
            | Mnemonic::Fcvtzu
            | Mnemonic::Fcvtzs
            | Mnemonic::Fabs
            | Mnemonic::Fneg
            | Mnemonic::Fsqrt
            | Mnemonic::Fmax
            | Mnemonic::Fmin
            | Mnemonic::Fmaxnm
            | Mnemonic::Fminnm
            | Mnemonic::Fnmul
            | Mnemonic::Fcmp
            | Mnemonic::Fcmpe
            | Mnemonic::Fcsel
            | Mnemonic::Fadd
            | Mnemonic::Fsub
            | Mnemonic::Fmul
            | Mnemonic::Fdiv
            | Mnemonic::Fmadd
            | Mnemonic::Fmsub
            | Mnemonic::Fnmadd
            | Mnemonic::Fnmsub
            | Mnemonic::Fmla
            | Mnemonic::Fmls => {
                self.ExecuteFloating(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Movi
            | Mnemonic::Bit
            | Mnemonic::Bif
            | Mnemonic::Bsl
            | Mnemonic::Dup
            | Mnemonic::Cmeq
            | Mnemonic::Cmhs
            | Mnemonic::Uzp1
            | Mnemonic::Uzp2
            | Mnemonic::Addv
            | Mnemonic::Addp
            | Mnemonic::Umaxp
            | Mnemonic::Ushl
            | Mnemonic::Xtn
            | Mnemonic::Xtn2 => {
                self.ExecuteVector(&instruction)?;
                self.cpu.pc = next_pc;
                StepOutcome::Continue
            }
            Mnemonic::Unsupported(_) => return Err(self.Unsupported(&instruction)),
        };
        Ok(result)
    }

    fn ExecuteMove(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let register_operands: Vec<RegisterOperand> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(register) => Some(*register),
                _ => None,
            })
            .collect();
        if register_operands
            .iter()
            .any(|operand| operand.lane.is_some())
        {
            let destination = *register_operands
                .first()
                .ok_or_else(|| self.Malformed(instruction))?;
            let source = *register_operands
                .get(1)
                .ok_or_else(|| self.Malformed(instruction))?;
            if let (Some(destination_index), Some(lane), Some(arrangement)) = (
                destination.register.VectorIndex(),
                destination.lane,
                destination.arrangement,
            ) {
                let value =
                    if let (Some(source_index), Some(source_lane), Some(source_arrangement)) = (
                        source.register.VectorIndex(),
                        source.lane,
                        source.arrangement,
                    ) {
                        if source_arrangement.element_bits != arrangement.element_bits {
                            return Err(self.Malformed(instruction));
                        }
                        ReadLane(
                            &self.cpu.v[source_index],
                            source_arrangement,
                            source_lane as u8,
                        )?
                    } else {
                        self.cpu.ReadRegister(source.register)?
                    };
                WriteLane(
                    &mut self.cpu.v[destination_index],
                    arrangement,
                    lane as u8,
                    value,
                )?;
                return Ok(());
            }
            if let (Some(source_index), Some(lane), Some(arrangement)) = (
                source.register.VectorIndex(),
                source.lane,
                source.arrangement,
            ) {
                let value = ReadLane(&self.cpu.v[source_index], arrangement, lane as u8)?;
                self.cpu.WriteRegister(destination.register, value)?;
                return Ok(());
            }
            return Err(self.Malformed(instruction));
        }
        if register_operands.len() >= 2
            && register_operands[0].register.VectorIndex().is_some()
            && register_operands[1].register.VectorIndex().is_some()
        {
            let destination = register_operands[0];
            let source = register_operands[1];
            let arrangement = destination
                .arrangement
                .ok_or_else(|| self.Malformed(instruction))?;
            if source.arrangement != Some(arrangement) {
                return Err(self.Malformed(instruction));
            }
            let destination_index = destination.register.VectorIndex().unwrap();
            let source_index = source.register.VectorIndex().unwrap();
            let bytes = usize::from(arrangement.element_bits) * usize::from(arrangement.lanes) / 8;
            let mut output = [0; 16];
            output[..bytes].copy_from_slice(&self.cpu.v[source_index][..bytes]);
            self.cpu.v[destination_index] = output;
            return Ok(());
        }
        let destination = Self::Register(instruction, 0)?;
        let value = match instruction.mnemonic {
            Mnemonic::Mov => Self::Value(&mut self.cpu, instruction, 1)?,
            Mnemonic::Movz => Self::Immediate(instruction, 1)? as u64,
            Mnemonic::Movn => !(Self::Immediate(instruction, 1)? as u64),
            Mnemonic::Movk => {
                let old = self.cpu.ReadRegister(destination)?;
                let immediate = Self::Immediate(instruction, 1)? as u64;
                let shift = ((instruction.word >> 21) & 3) * 16;
                (old & !(0xffff << shift)) | ((immediate & 0xffff) << shift)
            }
            _ => unreachable!(),
        };
        self.cpu
            .WriteRegister(destination, value)
            .map_err(ExecutionError::from)
    }

    fn ExecuteBitfield(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let value = if matches!(instruction.mnemonic, Mnemonic::Sxtw) {
            let source = Self::Value(&mut self.cpu, instruction, 1)?;
            (source as u32 as i32 as i64) as u64
        } else {
            let width = if instruction.word & 0x8000_0000 != 0 {
                64
            } else {
                32
            };
            let source = self
                .cpu
                .ReadRegister(BitfieldRegister((instruction.word >> 5) & 0x1f, width))?;
            let mut wmask = 0;
            let mut tmask = 0;
            if !DecodeBitMasks(instruction.word, width, &mut wmask, &mut tmask) {
                return Err(self.Malformed(instruction));
            }
            let rotate = (instruction.word >> 16) & 0x3f;
            let source_bit = (instruction.word >> 10) & (u32::from(width) - 1);
            let rotated = RotateRight(source, rotate, width);
            match instruction.mnemonic {
                Mnemonic::Ubfm | Mnemonic::Ubfiz | Mnemonic::Ubfx => (rotated & wmask) & tmask,
                Mnemonic::Sbfm | Mnemonic::Sbfx | Mnemonic::Sbfiz => {
                    let top = if (source >> source_bit) & 1 != 0 {
                        Mask(width)
                    } else {
                        0
                    };
                    (top & !tmask) | ((rotated & wmask) & tmask)
                }
                Mnemonic::Bfm | Mnemonic::Bfi | Mnemonic::Bfxil | Mnemonic::Bfc => {
                    let old = self.cpu.ReadRegister(destination)?;
                    let bottom = (old & !wmask) | (rotated & wmask);
                    (old & !tmask) | (bottom & tmask)
                }
                _ => unreachable!(),
            }
        };
        self.cpu.WriteRegister(destination, value)?;
        Ok(())
    }

    fn ExecuteAddSub(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let left = Self::Value(&mut self.cpu, instruction, 1)?;
        let mut right = Self::Value(&mut self.cpu, instruction, 2)?;
        if matches!(instruction.operands.get(2), Some(Operand::Immediate(_)))
            && instruction.word & (1 << 22) != 0
        {
            right <<= 12;
        }
        let width = destination.Width();
        let mask = if width == 32 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let carry_in = u64::from(self.cpu.nzcv & C != 0);
        let subtract = matches!(
            instruction.mnemonic,
            Mnemonic::Sub | Mnemonic::Subs | Mnemonic::Sbc | Mnemonic::Sbcs
        );
        let with_carry = matches!(
            instruction.mnemonic,
            Mnemonic::Adc | Mnemonic::Adcs | Mnemonic::Sbc | Mnemonic::Sbcs
        );
        let (value, carry, overflow) = if subtract {
            let borrow = if with_carry { 1 - carry_in } else { 0 };
            let result = left.wrapping_sub(right).wrapping_sub(borrow) & mask;
            let full_subtrahend = u128::from(right & mask) + u128::from(borrow);
            let signed_left = SignExtend(left & mask, width);
            let signed_right = SignExtend(right & mask, width);
            let signed_result = SignExtend(result, width);
            (
                result,
                u128::from(left & mask) >= full_subtrahend,
                (signed_left < 0) != (signed_right < 0) && (signed_result < 0) != (signed_left < 0),
            )
        } else {
            let addend = if with_carry { carry_in } else { 0 };
            let full_sum = u128::from(left & mask) + u128::from(right & mask) + u128::from(addend);
            let result = (full_sum as u64) & mask;
            let signed_left = SignExtend(left & mask, width);
            let signed_right = SignExtend(right & mask, width);
            let signed_result = SignExtend(result, width);
            (
                result,
                full_sum > u128::from(mask),
                (signed_left >= 0) == (signed_right >= 0)
                    && (signed_result >= 0) != (signed_left >= 0),
            )
        };
        self.cpu.WriteRegister(destination, value)?;
        if matches!(
            instruction.mnemonic,
            Mnemonic::Adds | Mnemonic::Subs | Mnemonic::Adcs | Mnemonic::Sbcs
        ) {
            let mut flags = 0;
            if SignExtend(value, width) < 0 {
                flags |= N;
            }
            if value == 0 {
                flags |= Z;
            }
            if carry {
                flags |= C;
            }
            if overflow {
                flags |= V;
            }
            self.cpu.nzcv = flags;
        }
        Ok(())
    }

    fn ExecuteLogical(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let left = Self::Value(&mut self.cpu, instruction, 1)?;
        let right = Self::Value(&mut self.cpu, instruction, 2)?;
        let value = match instruction.mnemonic {
            Mnemonic::And | Mnemonic::Ands => left & right,
            Mnemonic::Bic | Mnemonic::Bics => left & !right,
            Mnemonic::Orr => left | right,
            Mnemonic::Orn => left | !right,
            Mnemonic::Eor => left ^ right,
            Mnemonic::Eon => left ^ !right,
            _ => unreachable!(),
        };
        self.cpu.WriteRegister(destination, value)?;
        if matches!(instruction.mnemonic, Mnemonic::Ands | Mnemonic::Bics) {
            self.cpu.nzcv = if value == 0 {
                Z
            } else if SignExtend(value, destination.Width()) < 0 {
                N
            } else {
                0
            };
        }
        Ok(())
    }

    fn ExecuteShift(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let value = Self::Value(&mut self.cpu, instruction, 1)?;
        let amount =
            Self::Value(&mut self.cpu, instruction, 2)? & u64::from(destination.Width() - 1);
        let width = destination.Width();
        let result = match instruction.mnemonic {
            Mnemonic::Lsl => value << amount,
            Mnemonic::Lsr => value >> amount,
            Mnemonic::Asr => (SignExtend(value, width) >> amount) as u64,
            Mnemonic::Ror if width == 32 => (value as u32).rotate_right(amount as u32) as u64,
            Mnemonic::Ror => value.rotate_right(amount as u32),
            _ => unreachable!(),
        };
        self.cpu.WriteRegister(destination, result)?;
        Ok(())
    }

    fn ExecuteBitOperation(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let source = Self::Value(&mut self.cpu, instruction, 1)?;
        let width = destination.Width();
        let value = match instruction.mnemonic {
            Mnemonic::Clz => CountLeadingZeros(source, width),
            Mnemonic::Rbit => ReverseBits(source, width),
            Mnemonic::Rev => ReverseBytes(source, width),
            Mnemonic::Rev16 => ReverseBytesInHalfwords(source, width),
            Mnemonic::Rev32 => ReverseBytesInWords(source, width),
            _ => unreachable!(),
        };
        self.cpu.WriteRegister(destination, value)?;
        Ok(())
    }

    fn ExecuteExtract(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let left = Self::Value(&mut self.cpu, instruction, 1)?;
        let right = Self::Value(&mut self.cpu, instruction, 2)?;
        let amount = Self::Immediate(instruction, 0)? as u32;
        let width = destination.Width();
        let width_bits = u32::from(width);
        let shift = amount & (width_bits - 1);
        let value = if shift == 0 {
            right & Mask(width)
        } else {
            ((right >> shift) | (left << (width_bits - shift))) & Mask(width)
        };
        self.cpu.WriteRegister(destination, value)?;
        Ok(())
    }

    fn ExecuteMultiplyHigh(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let left = Self::Value(&mut self.cpu, instruction, 1)?;
        let right = Self::Value(&mut self.cpu, instruction, 2)?;
        let value = if matches!(instruction.mnemonic, Mnemonic::Smulh) {
            SignedMultiplyHigh(left, right)
        } else {
            UnsignedMultiplyHigh(left, right)
        };
        self.cpu.WriteRegister(destination, value)?;
        Ok(())
    }

    fn ExecuteMultiply(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let lhs = Self::Value(&mut self.cpu, instruction, 1)?;
        let rhs = Self::Value(&mut self.cpu, instruction, 2)?;
        let accumulator = if matches!(
            instruction.mnemonic,
            Mnemonic::Madd
                | Mnemonic::Msub
                | Mnemonic::Umaddl
                | Mnemonic::Umsubl
                | Mnemonic::Smaddl
                | Mnemonic::Smsubl
        ) {
            Self::Value(&mut self.cpu, instruction, 3)?
        } else {
            0
        };
        let signed = matches!(
            instruction.mnemonic,
            Mnemonic::Smaddl | Mnemonic::Smull | Mnemonic::Smsubl
        );
        let product = if signed {
            ((i128::from(lhs as u32 as i32)) * i128::from(rhs as u32 as i32)) as u128
        } else {
            (lhs as u128) * (rhs as u128)
        };
        let value = match instruction.mnemonic {
            Mnemonic::Msub | Mnemonic::Umsubl | Mnemonic::Smsubl => {
                accumulator.wrapping_sub(product as u64)
            }
            _ => accumulator.wrapping_add(product as u64),
        };
        self.cpu
            .WriteRegister(destination, value)
            .map_err(ExecutionError::from)
    }

    fn ExecuteCompare(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let left = Self::Value(&mut self.cpu, instruction, 0)?;
        let right = Self::Value(&mut self.cpu, instruction, 1)?;
        let width = match instruction.operands.first() {
            Some(Operand::Register(register)) => register.register.Width(),
            _ => 64,
        };
        if matches!(instruction.mnemonic, Mnemonic::Tst) {
            let value = left & right;
            self.cpu.nzcv = if value == 0 {
                Z
            } else if SignExtend(value, width) < 0 {
                N
            } else {
                0
            };
        } else if matches!(instruction.mnemonic, Mnemonic::Cmn) {
            let result = left.wrapping_add(right);
            self.cpu.nzcv = FlagsForAdd(result, left, right, width);
        } else {
            let result = left.wrapping_sub(right);
            self.cpu.nzcv = FlagsForResult(result, left, right, true, width);
        }
        Ok(())
    }

    fn ExecuteConditionalCompare(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let condition = instruction.condition;
        if condition.Holds(self.cpu.nzcv) {
            let left = Self::Value(&mut self.cpu, instruction, 0)?;
            let right = Self::Value(&mut self.cpu, instruction, 1)?;
            let width = match instruction.operands.first() {
                Some(Operand::Register(register)) => register.register.Width(),
                _ => return Err(self.Malformed(instruction)),
            };
            if matches!(instruction.mnemonic, Mnemonic::Ccmn) {
                let result = left.wrapping_add(right);
                self.cpu.nzcv = FlagsForAdd(result, left, right, width);
            } else {
                let result = left.wrapping_sub(right);
                self.cpu.nzcv = FlagsForResult(result, left, right, true, width);
            }
        } else if let Some(Operand::Immediate(value)) = instruction.operands.get(2) {
            self.cpu.nzcv = ((*value as u32) & 0xf) << 28;
        }
        Ok(())
    }

    fn ExecuteConditionalSelect(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let condition = instruction.condition.Holds(self.cpu.nzcv);
        let value = match instruction.mnemonic {
            Mnemonic::Cset => u64::from(condition),
            Mnemonic::Csinc if instruction.mnemonic_text == "cinc" => {
                let source = Self::Value(&mut self.cpu, instruction, 1)?;
                if condition {
                    source.wrapping_add(1)
                } else {
                    source
                }
            }
            Mnemonic::Csinc => {
                if condition {
                    Self::Value(&mut self.cpu, instruction, 1)?
                } else {
                    Self::Value(&mut self.cpu, instruction, 2)?.wrapping_add(1)
                }
            }
            Mnemonic::Csinv => {
                if condition {
                    Self::Value(&mut self.cpu, instruction, 1)?
                } else {
                    !Self::Value(&mut self.cpu, instruction, 2)?
                }
            }
            Mnemonic::Csneg if instruction.mnemonic_text == "cneg" => {
                let source = Self::Value(&mut self.cpu, instruction, 1)?;
                if condition {
                    0_u64.wrapping_sub(source)
                } else {
                    source
                }
            }
            Mnemonic::Csneg => {
                if condition {
                    Self::Value(&mut self.cpu, instruction, 1)?
                } else {
                    0_u64.wrapping_sub(Self::Value(&mut self.cpu, instruction, 2)?)
                }
            }
            Mnemonic::Csel => {
                Self::Value(&mut self.cpu, instruction, if condition { 1 } else { 2 })?
            }
            _ => unreachable!(),
        };
        self.cpu
            .WriteRegister(destination, value)
            .map_err(ExecutionError::from)
    }

    fn ExecuteLoadStore(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory_index = instruction
            .operands
            .iter()
            .position(|operand| matches!(operand, Operand::Memory(_)))
            .ok_or_else(|| self.Malformed(instruction))?;
        let memory_operand = match instruction.operands[memory_index] {
            Operand::Memory(value) => value,
            _ => unreachable!(),
        };
        let base = self.cpu.ReadRegister(memory_operand.base)?;
        let index = memory_operand
            .index
            .map(|value| self.cpu.ReadRegister(value))
            .transpose()?;
        let mut address = base.wrapping_add(memory_operand.displacement as u64);
        if let Some(value) = index {
            address = address.wrapping_add(ApplyExtend(
                value,
                memory_operand.extend,
                memory_operand.shift,
                memory_operand.index.map(Register::Width).unwrap_or(64),
            ));
        }
        if instruction.address_mode == AddressMode::PreIndex {
            self.cpu.WriteRegister(memory_operand.base, address)?;
        }
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        let pair = matches!(
            instruction.mnemonic,
            Mnemonic::Ldp | Mnemonic::Stp | Mnemonic::Ldpsw
        );
        let scalar_size = match instruction.mnemonic {
            Mnemonic::Ldrb
            | Mnemonic::Ldurb
            | Mnemonic::Ldrsb
            | Mnemonic::Strb
            | Mnemonic::Sturb => 1,
            Mnemonic::Ldrh
            | Mnemonic::Ldrsh
            | Mnemonic::Ldurh
            | Mnemonic::Ldursh
            | Mnemonic::Strh
            | Mnemonic::Sturh => 2,
            Mnemonic::Ldrsw | Mnemonic::Ldursw | Mnemonic::Ldpsw => 4,
            _ => registers
                .first()
                .map(|register| usize::from(register.Width() / 8))
                .unwrap_or(8),
        };
        let count = if pair { 2 } else { 1 };
        let total_size = scalar_size * count;
        let load = matches!(
            instruction.mnemonic,
            Mnemonic::Ldr
                | Mnemonic::Ldur
                | Mnemonic::Ldurb
                | Mnemonic::Ldrb
                | Mnemonic::Ldrh
                | Mnemonic::Ldurh
                | Mnemonic::Ldursb
                | Mnemonic::Ldursh
                | Mnemonic::Ldursw
                | Mnemonic::Ldrsb
                | Mnemonic::Ldrsh
                | Mnemonic::Ldrsw
                | Mnemonic::Ldpsw
                | Mnemonic::Ldp
        );
        if load {
            let bytes = self.memory.ReadVec(address, total_size)?;
            for (position, register) in registers.iter().take(count).enumerate() {
                let source = &bytes[position * scalar_size..(position + 1) * scalar_size];
                if scalar_size == 16 {
                    let vector = register
                        .VectorIndex()
                        .ok_or_else(|| self.Malformed(instruction))?;
                    self.cpu.SetV(vector, source)?;
                    continue;
                }
                let mut value = [0; 8];
                let size = scalar_size.min(8);
                value[..size].copy_from_slice(&source[..size]);
                let mut raw = u64::from_le_bytes(value);
                if matches!(instruction.mnemonic, Mnemonic::Ldrsb | Mnemonic::Ldursb)
                    && raw & 0x80 != 0
                {
                    raw |= u64::MAX << 8;
                }
                if matches!(instruction.mnemonic, Mnemonic::Ldrsh | Mnemonic::Ldursh)
                    && raw & 0x8000 != 0
                {
                    raw |= u64::MAX << 16;
                }
                if matches!(
                    instruction.mnemonic,
                    Mnemonic::Ldrsw | Mnemonic::Ldursw | Mnemonic::Ldpsw
                ) && raw & 0x8000_0000 != 0
                {
                    raw |= u64::MAX << 32;
                }
                self.cpu.WriteRegister(*register, raw)?;
            }
        } else {
            let mut bytes = vec![0; total_size];
            for (position, register) in registers.iter().take(count).enumerate() {
                let target = &mut bytes[position * scalar_size..(position + 1) * scalar_size];
                if scalar_size == 16 {
                    let vector = register
                        .VectorIndex()
                        .ok_or_else(|| self.Malformed(instruction))?;
                    target.copy_from_slice(self.cpu.V(vector)?);
                } else {
                    target.copy_from_slice(
                        &self.cpu.ReadRegister(*register)?.to_le_bytes()[..scalar_size],
                    );
                }
            }
            self.memory.Write(address, &bytes, instruction.pc)?;
            if self
                .exclusive
                .is_some_and(|(reserved, size)| Overlaps(address, total_size, reserved, size))
            {
                self.exclusive = None;
            }
        }
        if instruction.address_mode == AddressMode::PostIndex {
            let writeback = instruction
                .operands
                .iter()
                .skip(memory_index + 1)
                .find_map(|operand| match operand {
                    Operand::Immediate(value) => Some(*value),
                    _ => None,
                })
                .ok_or_else(|| self.Malformed(instruction))?;
            self.cpu
                .WriteRegister(memory_operand.base, base.wrapping_add(writeback as u64))?;
        }
        Ok(())
    }

    fn ExecuteLd1(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory_index = instruction
            .operands
            .iter()
            .position(|operand| matches!(operand, Operand::Memory(_)))
            .ok_or_else(|| self.Malformed(instruction))?;
        let memory_operand = match instruction.operands[memory_index] {
            Operand::Memory(value) => value,
            _ => unreachable!(),
        };
        if memory_operand.index.is_some() {
            return Err(self.Unsupported(instruction));
        }
        let base = self.cpu.ReadRegister(memory_operand.base)?;
        let address = base.wrapping_add(memory_operand.displacement as u64);
        if instruction.address_mode == AddressMode::PreIndex {
            self.cpu.WriteRegister(memory_operand.base, address)?;
        }

        let registers: Vec<RegisterOperand> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(*value),
                _ => None,
            })
            .collect();
        let full_q_pair = registers.len() == 2
            && registers.iter().all(|operand| {
                matches!(operand.register, Register::Vector { width: 128, .. })
                    && operand.lane.is_none()
                    && matches!(
                        operand.arrangement,
                        Some(VectorArrangement {
                            element_bits: 8,
                            lanes: 16
                        })
                    )
            });
        let single_lane = registers.len() == 1
            && matches!(
                instruction.address_mode,
                AddressMode::Offset | AddressMode::PreIndex
            )
            && registers[0].lane.is_some()
            && registers[0].arrangement.is_some();
        if full_q_pair {
            if instruction.address_mode != AddressMode::PostIndex {
                return Err(self.Unsupported(instruction));
            }
            let writeback = instruction
                .operands
                .iter()
                .skip(memory_index + 1)
                .find_map(|operand| match operand {
                    Operand::Immediate(value) => Some(*value),
                    _ => None,
                })
                .ok_or_else(|| self.Malformed(instruction))?;
            if writeback != 32 {
                return Err(self.Unsupported(instruction));
            }
            let bytes = self.memory.ReadVec(address, 32)?;
            for (position, register) in registers.iter().enumerate() {
                let vector = register
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                self.cpu
                    .SetV(vector, &bytes[position * 16..(position + 1) * 16])?;
            }
            self.cpu
                .WriteRegister(memory_operand.base, base.wrapping_add(32))?;
            return Ok(());
        }
        if !single_lane {
            return Err(self.Unsupported(instruction));
        }

        let register = registers[0];
        let arrangement = register
            .arrangement
            .ok_or_else(|| self.Malformed(instruction))?;
        let lane = register.lane.ok_or_else(|| self.Malformed(instruction))? as u8;
        let size = usize::from(arrangement.element_bits / 8);
        if size == 0 || size > 8 {
            return Err(self.Unsupported(instruction));
        }
        let mut vector = *self.cpu.V(register
            .register
            .VectorIndex()
            .ok_or_else(|| self.Malformed(instruction))?)?;
        let bytes = self.memory.ReadVec(address, size)?;
        let mut lane_value = [0_u8; 8];
        lane_value[..size].copy_from_slice(&bytes);
        WriteLane(
            &mut vector,
            arrangement,
            lane,
            u64::from_le_bytes(lane_value),
        )?;
        self.cpu.SetV(
            register
                .register
                .VectorIndex()
                .ok_or_else(|| self.Malformed(instruction))?,
            &vector,
        )?;
        Ok(())
    }

    fn ExecuteCompareAndSwap(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        let address = self
            .cpu
            .ReadRegister(memory.base)?
            .wrapping_add(memory.displacement as u64);
        let pair = matches!(instruction.mnemonic, Mnemonic::Casp);
        let (element_size, expected_count) = if pair {
            if registers.len() < 4 {
                return Err(self.Malformed(instruction));
            }
            let width = registers[0].Width();
            if width != 32 && width != 64 || registers[1].Width() != width {
                return Err(self.Malformed(instruction));
            }
            (usize::from(width / 8), 2)
        } else {
            if registers.len() < 2 {
                return Err(self.Malformed(instruction));
            }
            let suffix_size = match instruction.mnemonic_text.as_str() {
                text if text.ends_with('b') => Some(1),
                text if text.ends_with('h') => Some(2),
                _ => None,
            };
            (
                suffix_size.unwrap_or(usize::from(registers[0].Width() / 8)),
                1,
            )
        };
        let total_size = element_size * if pair { 2 } else { 1 };
        if element_size == 0 || total_size > 16 {
            return Err(self.Malformed(instruction));
        }
        let mut old_bytes = [0_u8; 16];
        self.memory.Read(address, &mut old_bytes[..total_size])?;
        let mut old = [0_u64; 2];
        for index in 0..expected_count {
            let mut value = [0_u8; 8];
            value[..element_size]
                .copy_from_slice(&old_bytes[index * element_size..(index + 1) * element_size]);
            old[index] = u64::from_le_bytes(value);
        }
        let mut compare = true;
        for index in 0..expected_count {
            let expected =
                self.cpu.ReadRegister(registers[index])? & Mask((element_size * 8) as u8);
            compare &= expected == old[index];
        }
        if compare {
            let mut replacement = [0_u8; 16];
            for index in 0..expected_count {
                let value = self.cpu.ReadRegister(registers[expected_count + index])?;
                replacement[index * element_size..(index + 1) * element_size]
                    .copy_from_slice(&value.to_le_bytes()[..element_size]);
            }
            self.memory
                .Write(address, &replacement[..total_size], instruction.pc)?;
            if self
                .exclusive
                .is_some_and(|(reserved, size)| Overlaps(address, total_size, reserved, size))
            {
                self.exclusive = None;
            }
        }
        for index in 0..expected_count {
            self.cpu.WriteRegister(registers[index], old[index])?;
        }
        Ok(())
    }

    fn ExecuteExclusive(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory_index = instruction
            .operands
            .iter()
            .position(|operand| matches!(operand, Operand::Memory(_)))
            .ok_or_else(|| self.Malformed(instruction))?;
        let memory_operand = match instruction.operands[memory_index] {
            Operand::Memory(value) => value,
            _ => unreachable!(),
        };
        let address = self
            .cpu
            .ReadRegister(memory_operand.base)?
            .wrapping_add(memory_operand.displacement as u64);
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        if registers.is_empty() {
            return Err(self.Malformed(instruction));
        }
        let pair = instruction.mnemonic_text.ends_with("xp");
        let data_register = if matches!(instruction.mnemonic, Mnemonic::Ldxr | Mnemonic::Ldaxr) {
            registers[0]
        } else {
            registers[1]
        };
        let size = usize::from(data_register.Width() / 8);
        let total_size = if pair { size * 2 } else { size };
        if matches!(instruction.mnemonic, Mnemonic::Ldxr | Mnemonic::Ldaxr) {
            let bytes = match self.memory.ReadVec(address, total_size) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.exclusive = None;
                    return Err(error.into());
                }
            };
            for (position, register) in registers.iter().take(if pair { 2 } else { 1 }).enumerate()
            {
                let mut value = [0; 8];
                value[..size].copy_from_slice(&bytes[position * size..position * size + size]);
                self.cpu
                    .WriteRegister(*register, u64::from_le_bytes(value))?;
            }
            self.exclusive = Some((address, total_size));
        } else {
            let status = registers[0];
            let matched = self.exclusive == Some((address, total_size));
            if matched {
                let mut bytes = vec![0; total_size];
                for (position, register) in registers
                    .iter()
                    .skip(1)
                    .take(if pair { 2 } else { 1 })
                    .enumerate()
                {
                    bytes[position * size..position * size + size]
                        .copy_from_slice(&self.cpu.ReadRegister(*register)?.to_le_bytes()[..size]);
                }
                let result = self.memory.Write(address, &bytes, instruction.pc);
                self.exclusive = None;
                result?;
            } else {
                self.exclusive = None;
            }
            self.cpu
                .WriteRegister(status, if matched { 0 } else { 1 })?;
        }
        Ok(())
    }

    fn ExecuteSystemRegister(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let raw = instruction.word;
        let op0 = (raw >> 19) & 3;
        let op1 = (raw >> 16) & 7;
        let crn = (raw >> 12) & 0xf;
        let crm = (raw >> 8) & 0xf;
        let op2 = (raw >> 5) & 7;
        let target = Self::Register(instruction, 0)?;
        let is_nzcv = op0 == 3 && op1 == 3 && crn == 4 && crm == 2 && op2 == 0;
        let is_fpcr = op0 == 3 && op1 == 3 && crn == 4 && crm == 4 && op2 == 0;
        let is_fpsr = op0 == 3 && op1 == 3 && crn == 4 && crm == 4 && op2 == 1;
        if is_nzcv || is_fpcr || is_fpsr {
            if matches!(instruction.mnemonic, Mnemonic::Mrs) {
                let value = if is_nzcv {
                    u64::from(self.cpu.nzcv)
                } else if is_fpcr {
                    u64::from(self.cpu.fpcr)
                } else {
                    u64::from(self.cpu.fpsr)
                };
                self.cpu.WriteRegister(target, value)?;
            } else {
                let value = self.cpu.ReadRegister(target)? as u32;
                if is_nzcv {
                    self.cpu.nzcv = value & 0xf000_0000;
                } else if is_fpcr {
                    self.cpu.fpcr = value;
                } else {
                    self.cpu.fpsr = value & 0xf800_009f;
                }
            }
            return Ok(());
        }

        let register = match (op0, op1, crn, crm, op2) {
            (3, 3, 0, 0, 1) => SystemRegister::CtrEl0,
            (3, 3, 14, 0, 2) => SystemRegister::CntvctEl0,
            (3, 3, 13, 0, 2) => SystemRegister::TpidrEl0,
            (3, 3, 14, 0, 0) => SystemRegister::CntfrqEl0,
            _ => return Err(self.Unsupported(instruction)),
        };
        let service_error = |message: String| ExecutionError::SystemRegister {
            pc: instruction.pc,
            mnemonic: instruction.mnemonic_text.clone(),
            message,
        };
        if matches!(instruction.mnemonic, Mnemonic::Mrs) {
            let value = self
                .system_registers
                .Read(self.tid, register)
                .map_err(|error| service_error(error.to_string()))?;
            self.cpu.WriteRegister(target, value)?;
        } else {
            let value = self.cpu.ReadRegister(target)?;
            self.system_registers
                .Write(self.tid, register, value)
                .map_err(|error| service_error(error.to_string()))?;
        }
        Ok(())
    }

    fn ExecutePAuth(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let destination = Self::Register(instruction, 0)?;
        let generic = matches!(instruction.mnemonic, Mnemonic::Pacga);
        let strips_auth = matches!(instruction.mnemonic, Mnemonic::Xpaci | Mnemonic::Xpacd);
        let value = self.cpu.ReadRegister(if generic {
            Self::Register(instruction, 1)?
        } else {
            destination
        })?;
        let modifier = if strips_auth {
            0
        } else {
            self.cpu.ReadRegister(if generic {
                Self::Register(instruction, 2)?
            } else {
                Self::Register(instruction, 1)?
            })?
        };
        let operation = match instruction.mnemonic {
            Mnemonic::Pacga => PAuthOperation::Pacga,
            Mnemonic::Pacia => PAuthOperation::Pacia,
            Mnemonic::Pacib => PAuthOperation::Pacib,
            Mnemonic::Pacda => PAuthOperation::Pacda,
            Mnemonic::Pacdb => PAuthOperation::Pacdb,
            Mnemonic::Autia => PAuthOperation::Autia,
            Mnemonic::Autib => PAuthOperation::Autib,
            Mnemonic::Autda => PAuthOperation::Autda,
            Mnemonic::Autdb => PAuthOperation::Autdb,
            Mnemonic::Xpaci => PAuthOperation::Xpaci,
            Mnemonic::Xpacd => PAuthOperation::Xpacd,
            _ => unreachable!(),
        };
        let result = self
            .pauth
            .Process(self.tid, operation, value, modifier)
            .map_err(|error| ExecutionError::PAuth {
                pc: instruction.pc,
                message: error.to_string(),
            })?;
        self.cpu.WriteRegister(destination, result.value)?;
        Ok(())
    }

    fn ExecutePAuthSp(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let operation = match instruction.mnemonic {
            Mnemonic::PaciaSp => PAuthOperation::Pacia,
            Mnemonic::PacibSp => PAuthOperation::Pacib,
            Mnemonic::AutiaSp => PAuthOperation::Autia,
            Mnemonic::AutibSp => PAuthOperation::Autib,
            _ => unreachable!(),
        };
        let value = self.cpu.X(30)?;
        let result = self
            .pauth
            .Process(self.tid, operation, value, self.cpu.sp)
            .map_err(|error| ExecutionError::PAuth {
                pc: instruction.pc,
                message: error.to_string(),
            })?;
        self.cpu.SetX(30, result.value)?;
        Ok(())
    }

    fn ExecuteAuthenticatedBranch(
        &mut self,
        instruction: &DecodedInstruction,
        call: bool,
    ) -> Result<u64, ExecutionError> {
        let return_form = matches!(instruction.mnemonic, Mnemonic::Retaa | Mnemonic::Retab);
        let key_b = matches!(
            instruction.mnemonic,
            Mnemonic::Brab | Mnemonic::Blrab | Mnemonic::Retab
        ) || instruction.mnemonic_text.ends_with('z')
            && matches!(instruction.mnemonic, Mnemonic::Brab | Mnemonic::Blrab);
        let operation = if key_b {
            PAuthOperation::Autib
        } else {
            PAuthOperation::Autia
        };
        let target = if return_form {
            self.cpu.X(30)?
        } else {
            self.cpu.ReadRegister(Self::Register(instruction, 0)?)?
        };
        let modifier = if return_form {
            self.cpu.sp
        } else if instruction.mnemonic_text.ends_with('z') {
            0
        } else {
            let modifier = Self::Register(instruction, 1)?;
            self.cpu.ReadRegister(modifier)?
        };
        let result = self
            .pauth
            .Process(self.tid, operation, target, modifier)
            .map_err(|error| ExecutionError::PAuth {
                pc: instruction.pc,
                message: error.to_string(),
            })?;
        if call {
            self.cpu.SetX(30, instruction.pc.wrapping_add(4))?;
        }
        Ok((self.address_normalizer)(result.value))
    }

    fn ExecuteTaggedArithmetic(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        const LOGICAL_TAG_MASK: u64 = 0x0F00_0000_0000_0000;

        let destination = Self::Register(instruction, 0)?;
        let left = Self::Register(instruction, 1)?;
        let left_value = self.cpu.ReadRegister(left)?;
        let result = match instruction.mnemonic {
            Mnemonic::Addg | Mnemonic::Subg => {
                let offset = Self::Immediate(instruction, 0)? as u64;
                let tag_offset = (Self::Immediate(instruction, 1)? as u64) & 0xf;
                let subtract = matches!(instruction.mnemonic, Mnemonic::Subg);
                let address = if subtract {
                    left_value.wrapping_sub(offset)
                } else {
                    left_value.wrapping_add(offset)
                };
                let old_tag = (left_value >> 56) & 0xf;
                let tag = if subtract {
                    old_tag.wrapping_sub(tag_offset) & 0xf
                } else {
                    old_tag.wrapping_add(tag_offset) & 0xf
                };
                (address & !LOGICAL_TAG_MASK) | (tag << 56)
            }
            Mnemonic::Gmi => {
                let right = self.cpu.ReadRegister(Self::Register(instruction, 2)?)?;
                right | (1_u64 << ((left_value >> 56) & 0xf))
            }
            Mnemonic::Irg => {
                let excluded = self.cpu.ReadRegister(Self::Register(instruction, 2)?)? as u16;
                let mut tag = 0_u64;
                while tag < 16 && excluded & (1 << tag) != 0 {
                    tag += 1;
                }
                if tag == 16 {
                    tag = 0;
                }
                (left_value & !LOGICAL_TAG_MASK) | (tag << 56)
            }
            Mnemonic::Subp | Mnemonic::Subps => {
                let right_value = self.cpu.ReadRegister(Self::Register(instruction, 2)?)?;
                let lhs = SignExtend(left_value, 56) as i64 as u64;
                let rhs = SignExtend(right_value, 56) as i64 as u64;
                let result = lhs.wrapping_sub(rhs);
                if matches!(instruction.mnemonic, Mnemonic::Subps) {
                    self.cpu.nzcv = FlagsForResult(result, lhs, rhs, true, 64);
                }
                result
            }
            _ => unreachable!(),
        };
        self.cpu.WriteRegister(destination, result)?;
        Ok(())
    }

    fn ExecuteAuthenticatedLoad(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let target = Self::Register(instruction, 0)?;
        let base = self.cpu.ReadRegister(memory.base)?;
        let index = memory
            .index
            .map(|value| self.cpu.ReadRegister(value))
            .transpose()?;
        let mut address = base.wrapping_add(memory.displacement as u64);
        if let Some(value) = index {
            address = address.wrapping_add(ApplyExtend(
                value,
                memory.extend,
                memory.shift,
                memory.index.map(Register::Width).unwrap_or(64),
            ));
        }
        let signed_pointer = u64::from_le_bytes(
            self.memory
                .ReadVec(address, 8)?
                .try_into()
                .map_err(|_| self.Malformed(instruction))?,
        );
        let operation = if matches!(instruction.mnemonic, Mnemonic::Ldraa) {
            PAuthOperation::Autda
        } else {
            PAuthOperation::Autdb
        };
        let result = self
            .pauth
            .Process(self.tid, operation, signed_pointer, address)
            .map_err(|error| ExecutionError::PAuth {
                pc: instruction.pc,
                message: error.to_string(),
            })?;
        self.cpu.WriteRegister(target, result.value)?;
        if instruction.address_mode == AddressMode::PreIndex {
            self.cpu.WriteRegister(memory.base, address)?;
        }
        Ok(())
    }

    fn ExecuteAtomicRmw(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        if registers.len() < 2 {
            return Err(self.Malformed(instruction));
        }
        let source = registers[0];
        let target = registers[1];
        let base = self.cpu.ReadRegister(memory.base)?;
        let index = memory
            .index
            .map(|value| self.cpu.ReadRegister(value))
            .transpose()?;
        let mut address = base.wrapping_add(memory.displacement as u64);
        if let Some(value) = index {
            address = address.wrapping_add(ApplyExtend(
                value,
                memory.extend,
                memory.shift,
                memory.index.map(Register::Width).unwrap_or(64),
            ));
        }
        let size = match instruction.mnemonic_text.as_str() {
            text if text.ends_with('b') => 1,
            text if text.ends_with('h') => 2,
            _ => usize::from(target.Width() / 8),
        };
        if size == 0 || size > 8 {
            return Err(self.Malformed(instruction));
        }
        let mut old_value = u64::from_le_bytes({
            let mut bytes = [0_u8; 8];
            let read = self.memory.ReadVec(address, size)?;
            bytes[..size].copy_from_slice(&read);
            bytes
        });
        let value_bits = (size * 8) as u8;
        let source_value = self.cpu.ReadRegister(source)? & Mask(value_bits);
        old_value &= Mask(value_bits);
        let replacement = match instruction.mnemonic {
            Mnemonic::Ldadd => old_value.wrapping_add(source_value),
            Mnemonic::Ldclr => old_value & !source_value,
            Mnemonic::Ldeor => old_value ^ source_value,
            Mnemonic::Ldset => old_value | source_value,
            Mnemonic::Ldsmax => {
                if SignExtend(old_value, value_bits) < SignExtend(source_value, value_bits) {
                    source_value
                } else {
                    old_value
                }
            }
            Mnemonic::Ldsmin => {
                if SignExtend(old_value, value_bits) < SignExtend(source_value, value_bits) {
                    old_value
                } else {
                    source_value
                }
            }
            Mnemonic::Ldumax => old_value.max(source_value),
            Mnemonic::Ldumin => old_value.min(source_value),
            Mnemonic::Swp => source_value,
            _ => unreachable!(),
        } & Mask(value_bits);
        self.memory
            .Write(address, &replacement.to_le_bytes()[..size], instruction.pc)?;
        if self.exclusive.is_some_and(|(reserved, reserved_size)| {
            Overlaps(address, size, reserved, reserved_size)
        }) {
            self.exclusive = None;
        }
        self.cpu.WriteRegister(target, old_value)?;
        Ok(())
    }

    fn ExecuteAtomicRmwPair(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let first = Self::Register(instruction, 0)?;
        let second = Self::Register(instruction, 1)?;
        if first.Width() != 64 || second.Width() != 64 {
            return Err(self.Malformed(instruction));
        }
        let address = self
            .cpu
            .ReadRegister(memory.base)?
            .wrapping_add(memory.displacement as u64);
        let bytes = self.memory.ReadVec(address, 16)?;
        let old_low = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let old_high = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let source_low = self.cpu.ReadRegister(first)?;
        let source_high = self.cpu.ReadRegister(second)?;
        let (replacement_low, replacement_high) = match instruction.mnemonic {
            Mnemonic::Ldclrp => (old_low & !source_low, old_high & !source_high),
            Mnemonic::Ldsetp => (old_low | source_low, old_high | source_high),
            Mnemonic::Swpp => (source_low, source_high),
            _ => unreachable!(),
        };
        let replacement = [
            replacement_low.to_le_bytes().as_slice(),
            replacement_high.to_le_bytes().as_slice(),
        ]
        .concat();
        self.memory.Write(address, &replacement, instruction.pc)?;
        if self
            .exclusive
            .is_some_and(|(reserved, reserved_size)| Overlaps(address, 16, reserved, reserved_size))
        {
            self.exclusive = None;
        }
        self.cpu.WriteRegister(first, old_low)?;
        self.cpu.WriteRegister(second, old_high)?;
        Ok(())
    }

    fn ExecuteAtomicRcw(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        let compare_swap = matches!(
            instruction.mnemonic,
            Mnemonic::Rcwcas | Mnemonic::Rcwscas | Mnemonic::Rcwcasp | Mnemonic::Rcwscasp
        );
        let pair = matches!(
            instruction.mnemonic,
            Mnemonic::Rcwcasp
                | Mnemonic::Rcwscasp
                | Mnemonic::Rcwclrp
                | Mnemonic::Rcwsclrp
                | Mnemonic::Rcwsetp
                | Mnemonic::Rcwssetp
                | Mnemonic::Rcwswpp
                | Mnemonic::Rcwsswpp
        );
        let expected_registers = if compare_swap {
            if pair {
                4
            } else {
                2
            }
        } else {
            2
        };
        if registers.len() != expected_registers {
            return Err(self.Malformed(instruction));
        }
        let software_checks = matches!(
            instruction.mnemonic,
            Mnemonic::Rcwscas | Mnemonic::Rcwsclr | Mnemonic::Rcwsset | Mnemonic::Rcwsswp
        );
        let operation = match instruction.mnemonic {
            Mnemonic::Rcwcas | Mnemonic::Rcwscas | Mnemonic::Rcwcasp | Mnemonic::Rcwscasp => {
                AtomicRcwOperation::CompareSwap
            }
            Mnemonic::Rcwclr | Mnemonic::Rcwsclr | Mnemonic::Rcwclrp | Mnemonic::Rcwsclrp => {
                AtomicRcwOperation::Clear
            }
            Mnemonic::Rcwset | Mnemonic::Rcwsset | Mnemonic::Rcwsetp | Mnemonic::Rcwssetp => {
                AtomicRcwOperation::Set
            }
            Mnemonic::Rcwswp | Mnemonic::Rcwsswp | Mnemonic::Rcwswpp | Mnemonic::Rcwsswpp => {
                AtomicRcwOperation::Swap
            }
            _ => unreachable!(),
        };
        let address = self
            .cpu
            .ReadRegister(memory.base)?
            .wrapping_add(memory.displacement as u64);

        let mut info = AtomicRcwInfo {
            pc: instruction.pc,
            address,
            operation,
            software_checks,
            element_count: if pair { 2 } else { 1 },
            compare: [0; 2],
            operand: [0; 2],
        };
        if compare_swap {
            info.compare[0] = self.cpu.ReadRegister(registers[0])?;
            info.operand[0] = self.cpu.ReadRegister(registers[if pair { 2 } else { 1 }])?;
            if pair {
                info.compare[1] = self.cpu.ReadRegister(registers[1])?;
                info.operand[1] = self.cpu.ReadRegister(registers[3])?;
            }
        } else {
            info.operand[0] = self.cpu.ReadRegister(registers[0])?;
            if pair {
                info.operand[1] = self.cpu.ReadRegister(registers[1])?;
            }
        }

        let handled = match self.atomic_rcw.Process(self.tid, info) {
            Ok(result) => Some(result),
            Err(AdvancedServiceError::AtomicRcwUnavailable(_)) => None,
            Err(error) => {
                return Err(ExecutionError::AdvancedService {
                    pc: instruction.pc,
                    mnemonic: instruction.mnemonic_text.clone(),
                    message: error.to_string(),
                });
            }
        };

        let mut old = [0_u64; 2];
        let mut nzcv = C;
        if let Some(result) = handled {
            old = result.old_value;
            nzcv = result.nzcv;
        } else {
            let total_size = if pair { 16 } else { 8 };
            let bytes = self.memory.ReadVec(address, total_size)?;
            old[0] = u64::from_le_bytes(
                bytes[..8]
                    .try_into()
                    .map_err(|_| self.Malformed(instruction))?,
            );
            if pair {
                old[1] = u64::from_le_bytes(
                    bytes[8..16]
                        .try_into()
                        .map_err(|_| self.Malformed(instruction))?,
                );
            }
            let replacement = if compare_swap {
                if old[0] == info.compare[0] && (!pair || old[1] == info.compare[1]) {
                    info.operand
                } else {
                    nzcv = N | C;
                    old
                }
            } else {
                let mut replacement = old;
                for index in 0..usize::from(info.element_count) {
                    replacement[index] = match operation {
                        AtomicRcwOperation::Clear => old[index] & !info.operand[index],
                        AtomicRcwOperation::Set => old[index] | info.operand[index],
                        AtomicRcwOperation::Swap => info.operand[index],
                        AtomicRcwOperation::CompareSwap => unreachable!(),
                    };
                }
                replacement
            };
            if !compare_swap || nzcv == C {
                let mut replacement_bytes = replacement[0].to_le_bytes().to_vec();
                if pair {
                    replacement_bytes.extend_from_slice(&replacement[1].to_le_bytes());
                }
                self.memory
                    .Write(address, &replacement_bytes, instruction.pc)?;
            }
        }

        self.cpu.nzcv = nzcv & (N | Z | C | V);
        if compare_swap {
            self.cpu.WriteRegister(registers[0], old[0])?;
            if pair {
                self.cpu.WriteRegister(registers[1], old[1])?;
            }
        } else if pair {
            self.cpu.WriteRegister(registers[0], old[0])?;
            self.cpu.WriteRegister(registers[1], old[1])?;
        } else {
            self.cpu.WriteRegister(registers[1], old[0])?;
        }
        if self.exclusive.is_some_and(|(reserved, reserved_size)| {
            Overlaps(address, if pair { 16 } else { 8 }, reserved, reserved_size)
        }) {
            self.exclusive = None;
        }
        Ok(())
    }

    fn ExecuteLsfe(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        if !(registers.len() == 1 || registers.len() == 2) {
            return Err(self.Malformed(instruction));
        }

        let source = registers[0];
        let target = registers.get(1).copied();
        let width = source.Width();
        let bfloat = matches!(
            instruction.mnemonic,
            Mnemonic::Ldbfadd
                | Mnemonic::Ldbfmax
                | Mnemonic::Ldbfmin
                | Mnemonic::Ldbfmaxnm
                | Mnemonic::Ldbfminnm
        );
        if !matches!(width, 16 | 32 | 64) || (bfloat && width != 16) {
            return Err(self.Malformed(instruction));
        }

        let address = self
            .cpu
            .ReadRegister(memory.base)?
            .wrapping_add(memory.displacement as u64);
        let size = usize::from(width / 8);
        let source_bits = self.cpu.ReadRegister(source)?;
        let old_bits = {
            let bytes = self.memory.ReadVec(address, size)?;
            let mut raw = [0_u8; 8];
            raw[..size].copy_from_slice(&bytes);
            u64::from_le_bytes(raw)
        };

        let old_value = if bfloat {
            f64::from(BFloat16ToFloat(old_bits as u16))
        } else {
            FloatingBitsToDouble(old_bits, width).ok_or_else(|| self.Malformed(instruction))?
        };
        let source_value = if bfloat {
            f64::from(BFloat16ToFloat(source_bits as u16))
        } else {
            FloatingBitsToDouble(source_bits, width).ok_or_else(|| self.Malformed(instruction))?
        };

        let add = matches!(instruction.mnemonic, Mnemonic::Ldfadd | Mnemonic::Ldbfadd);
        let maximum = matches!(
            instruction.mnemonic,
            Mnemonic::Ldfmax | Mnemonic::Ldfmaxnm | Mnemonic::Ldbfmax | Mnemonic::Ldbfmaxnm
        );
        let numeric = matches!(
            instruction.mnemonic,
            Mnemonic::Ldfmaxnm | Mnemonic::Ldfminnm | Mnemonic::Ldbfmaxnm | Mnemonic::Ldbfminnm
        );
        let result_value = if add {
            old_value + source_value
        } else {
            FloatingMinMax(old_value, source_value, maximum, numeric)
        };
        let result_bits = if bfloat {
            u64::from(FloatToBFloat16(result_value as f32))
        } else {
            DoubleToFloatingBits(result_value, width).ok_or_else(|| self.Malformed(instruction))?
        };

        self.memory
            .Write(address, &result_bits.to_le_bytes()[..size], instruction.pc)?;
        if self.exclusive.is_some_and(|(reserved, reserved_size)| {
            Overlaps(address, size, reserved, reserved_size)
        }) {
            self.exclusive = None;
        }
        if let Some(target) = target {
            self.cpu.WriteRegister(target, old_bits)?;
        }
        Ok(())
    }

    fn ExecuteStore64(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        if registers.is_empty() {
            return Err(self.Malformed(instruction));
        }
        let load = matches!(instruction.mnemonic, Mnemonic::Ld64b);
        let with_status = matches!(instruction.mnemonic, Mnemonic::St64bv | Mnemonic::St64bv0);
        let group = registers[0];
        let group_index = RegisterNumber(group).ok_or_else(|| self.Malformed(instruction))?;
        if group.Width() != 64 || (group_index & 1) != 0 || group_index > 22 {
            return Err(self.Malformed(instruction));
        }
        let base = self.cpu.ReadRegister(memory.base)?;
        let address = base.wrapping_add(memory.displacement as u64);
        if load {
            let bytes = self.memory.ReadVec(address, 64)?;
            for index in 0..8 {
                let mut value = [0_u8; 8];
                value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
                self.cpu
                    .SetX(usize::from(group_index) + index, u64::from_le_bytes(value))?;
            }
            return Ok(());
        }

        let mut data = [0_u64; 8];
        for (index, value) in data.iter_mut().enumerate() {
            *value = self.cpu.X(usize::from(group_index) + index)?;
        }
        let operation = if with_status {
            if matches!(instruction.mnemonic, Mnemonic::St64bv0) {
                Store64Operation::StoreWithStatusAndAccdata
            } else {
                Store64Operation::StoreWithStatus
            }
        } else {
            Store64Operation::Store
        };
        let info = Store64Info {
            pc: instruction.pc,
            address,
            operation,
            data,
        };
        let result = self.store64.Process(self.tid, info);
        let mut status = 0_u64;
        match result {
            Ok(value) => status = value.status,
            Err(AdvancedServiceError::Store64Unavailable(_)) => {
                let mut bytes = [0_u8; 64];
                for index in 0..8 {
                    let mut value = data[index];
                    if matches!(instruction.mnemonic, Mnemonic::St64bv0) && index == 0 {
                        value &= 0xFFFF_FFFF_0000_0000;
                    }
                    bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
                }
                self.memory.Write(address, &bytes, instruction.pc)?;
            }
            Err(error) => {
                return Err(ExecutionError::AdvancedService {
                    pc: instruction.pc,
                    mnemonic: instruction.mnemonic_text.clone(),
                    message: error.to_string(),
                });
            }
        }
        if with_status {
            self.cpu.WriteRegister(registers[1], status)?;
        }
        Ok(())
    }

    fn ExecuteMemoryTag(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let memory = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Memory(value) => Some(*value),
                _ => None,
            })
            .ok_or_else(|| self.Malformed(instruction))?;
        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        if registers.is_empty() {
            return Err(self.Malformed(instruction));
        }
        let base = self.cpu.ReadRegister(memory.base)?;
        let address = base.wrapping_add(memory.displacement as u64);
        let normalized = (self.address_normalizer)(address) & !0xF;
        let mut info = MemoryTagInfo {
            pc: instruction.pc,
            address: normalized,
            operation: MemoryTagOperation::Store,
            value: 0,
            granule_count: 1,
            zero_data: matches!(
                instruction.mnemonic,
                Mnemonic::Stzg | Mnemonic::Stzgm | Mnemonic::Stz2g
            ),
        };
        match instruction.mnemonic {
            Mnemonic::Ldg => info.operation = MemoryTagOperation::Load,
            Mnemonic::Ldgm => info.operation = MemoryTagOperation::LoadMultiple,
            Mnemonic::Stg | Mnemonic::Stgp | Mnemonic::Stzg | Mnemonic::St2g | Mnemonic::Stz2g => {
                info.operation = MemoryTagOperation::Store
            }
            Mnemonic::Stgm | Mnemonic::Stzgm => info.operation = MemoryTagOperation::StoreMultiple,
            _ => {}
        }
        if matches!(instruction.mnemonic, Mnemonic::St2g | Mnemonic::Stz2g) {
            info.granule_count = 2;
        }
        if matches!(
            instruction.mnemonic,
            Mnemonic::Ldgm | Mnemonic::Stgm | Mnemonic::Stzgm
        ) {
            info.granule_count = 0;
        }
        if matches!(instruction.mnemonic, Mnemonic::Stgp) {
            info.value = (address >> 56) & 0xf;
        } else if matches!(instruction.mnemonic, Mnemonic::Stgm | Mnemonic::Stzgm) {
            info.value = self.cpu.ReadRegister(registers[0])?;
        } else if !matches!(instruction.mnemonic, Mnemonic::Ldg | Mnemonic::Ldgm) {
            info.value = (self.cpu.ReadRegister(registers[0])? >> 56) & 0xf;
        }
        let result = self.memory_tags.Process(self.tid, info);
        match result {
            Ok(tagged) => {
                if matches!(instruction.mnemonic, Mnemonic::Ldg) {
                    let old = self.cpu.ReadRegister(registers[0])?;
                    self.cpu.WriteRegister(
                        registers[0],
                        (old & 0x00FF_FFFF_FFFF_FFFF) | ((tagged.value & 0xF) << 56),
                    )?;
                } else if matches!(instruction.mnemonic, Mnemonic::Ldgm) {
                    self.cpu.WriteRegister(registers[0], tagged.value)?;
                }
            }
            Err(AdvancedServiceError::MemoryTagUnavailable(_)) => {
                return Err(self.Unsupported(instruction))
            }
            Err(error) => {
                return Err(ExecutionError::AdvancedService {
                    pc: instruction.pc,
                    mnemonic: instruction.mnemonic_text.clone(),
                    message: error.to_string(),
                });
            }
        }
        if matches!(instruction.mnemonic, Mnemonic::Stgp) {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&self.cpu.ReadRegister(registers[0])?.to_le_bytes());
            bytes[8..].copy_from_slice(&self.cpu.ReadRegister(registers[1])?.to_le_bytes());
            self.memory.Write(address, &bytes, instruction.pc)?;
        } else if info.zero_data {
            let size = info.granule_count.max(1) * 16;
            self.memory
                .Write(address, &vec![0_u8; size], instruction.pc)?;
        }
        Ok(())
    }

    fn ExecuteGcs(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let operand = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            });
        let mut info = GcsInfo {
            pc: instruction.pc,
            operation: match instruction.mnemonic {
                Mnemonic::Gcspopcx => GcsOperation::PopExceptionChecked,
                Mnemonic::Gcspopm => GcsOperation::Pop,
                Mnemonic::Gcspopx => GcsOperation::PopException,
                Mnemonic::Gcspushm => GcsOperation::Push,
                Mnemonic::Gcspushx => GcsOperation::PushException,
                Mnemonic::Gcsss1 => GcsOperation::SwitchStackPhase1,
                Mnemonic::Gcsss2 => GcsOperation::SwitchStackPhase2,
                _ => unreachable!(),
            },
            reg: operand.and_then(RegisterNumber).unwrap_or(0),
            value: 0,
        };
        if matches!(
            instruction.mnemonic,
            Mnemonic::Gcspushm | Mnemonic::Gcspushx | Mnemonic::Gcsss1
        ) {
            if let Some(reg) = operand {
                info.value = self.cpu.ReadRegister(reg)?;
            }
        }
        let result = self.gcs.Process(self.tid, info);
        match result {
            Ok(value) => {
                if matches!(
                    instruction.mnemonic,
                    Mnemonic::Gcspopm | Mnemonic::Gcspopx | Mnemonic::Gcsss2
                ) {
                    if let Some(reg) = operand {
                        self.cpu.WriteRegister(reg, value.value)?;
                    }
                }
            }
            Err(AdvancedServiceError::GcsUnavailable(_)) => {
                return Err(self.Unsupported(instruction))
            }
            Err(error) => {
                return Err(ExecutionError::AdvancedService {
                    pc: instruction.pc,
                    mnemonic: instruction.mnemonic_text.clone(),
                    message: error.to_string(),
                });
            }
        }
        Ok(())
    }

    fn ExecuteMops(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        const MAX_MOPS_BYTES: u64 = 16 * 1024 * 1024;
        const MOPS_CHUNK: usize = 4096;

        let registers: Vec<Register> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .collect();
        let copy = matches!(instruction.mnemonic, Mnemonic::MopsCopy);
        let granule_only = matches!(instruction.mnemonic, Mnemonic::MopsSetgo);
        let set_tags = matches!(
            instruction.mnemonic,
            Mnemonic::MopsSetg | Mnemonic::MopsSetgo
        );
        let expected_registers = if granule_only { 2 } else { 3 };
        if registers.len() != expected_registers {
            return Err(self.Malformed(instruction));
        }

        let mut destination_address = self.cpu.ReadRegister(registers[0])?;
        let mut remaining = self.cpu.ReadRegister(registers[1])?;
        let mut source_address = if copy {
            self.cpu.ReadRegister(registers[2])?
        } else {
            0
        };
        let fill_byte = if copy || granule_only {
            0
        } else {
            self.cpu.ReadRegister(registers[2])? as u8
        };
        if remaining > MAX_MOPS_BYTES
            || destination_address.checked_add(remaining).is_none()
            || (copy && source_address.checked_add(remaining).is_none())
        {
            return Err(self.Unsupported(instruction));
        }
        let backwards = copy
            && destination_address > source_address
            && destination_address < source_address + remaining;

        let info = MopsInfo {
            pc: instruction.pc,
            operation: match instruction.mnemonic {
                Mnemonic::MopsCopy => MopsOperation::Copy,
                Mnemonic::MopsSet => MopsOperation::Set,
                Mnemonic::MopsSetg => MopsOperation::SetTags,
                Mnemonic::MopsSetgo => MopsOperation::SetTagsOnly,
                _ => unreachable!(),
            },
            destination_address,
            source_address,
            count: remaining,
            fill_byte,
            backwards,
        };
        match self.mops.Process(self.tid, info) {
            Ok(_) | Err(AdvancedServiceError::MopsUnavailable(_)) => {}
            Err(error) => {
                return Err(ExecutionError::AdvancedService {
                    pc: instruction.pc,
                    mnemonic: instruction.mnemonic_text.clone(),
                    message: error.to_string(),
                });
            }
        }

        if set_tags && remaining != 0 {
            let tag_info = MemoryTagInfo {
                pc: instruction.pc,
                address: (self.address_normalizer)(destination_address) & !0xF,
                operation: MemoryTagOperation::StoreMultiple,
                value: (destination_address >> 56) & 0xF,
                granule_count: remaining.div_ceil(16) as usize,
                zero_data: false,
            };
            self.memory_tags
                .Process(self.tid, tag_info)
                .map_err(|error| match error {
                    AdvancedServiceError::MemoryTagUnavailable(_) => self.Unsupported(instruction),
                    error => ExecutionError::AdvancedService {
                        pc: instruction.pc,
                        mnemonic: instruction.mnemonic_text.clone(),
                        message: error.to_string(),
                    },
                })?;
        }

        if granule_only {
            if remaining != 0
                && self.exclusive.is_some_and(|(reserved, size)| {
                    Overlaps(destination_address, remaining as usize, reserved, size)
                })
            {
                self.exclusive = None;
            }
            destination_address += remaining;
            self.cpu.WriteRegister(registers[0], destination_address)?;
            self.cpu.WriteRegister(registers[1], 0)?;
            return Ok(());
        }

        let original_count = remaining;
        if copy {
            if backwards {
                while remaining != 0 {
                    let chunk = remaining.min(MOPS_CHUNK as u64) as usize;
                    let offset = remaining - chunk as u64;
                    let bytes = self.memory.ReadVec(source_address + offset, chunk)?;
                    self.memory
                        .Write(destination_address + offset, &bytes, instruction.pc)?;
                    if self.exclusive.is_some_and(|(reserved, size)| {
                        Overlaps(destination_address + offset, chunk, reserved, size)
                    }) {
                        self.exclusive = None;
                    }
                    remaining -= chunk as u64;
                }
                destination_address += original_count;
                source_address += original_count;
            } else {
                while remaining != 0 {
                    let chunk = remaining.min(MOPS_CHUNK as u64) as usize;
                    let bytes = self.memory.ReadVec(source_address, chunk)?;
                    self.memory
                        .Write(destination_address, &bytes, instruction.pc)?;
                    if self.exclusive.is_some_and(|(reserved, size)| {
                        Overlaps(destination_address, chunk, reserved, size)
                    }) {
                        self.exclusive = None;
                    }
                    destination_address += chunk as u64;
                    source_address += chunk as u64;
                    remaining -= chunk as u64;
                    self.cpu.WriteRegister(registers[0], destination_address)?;
                    self.cpu.WriteRegister(registers[1], remaining)?;
                    self.cpu.WriteRegister(registers[2], source_address)?;
                }
            }
            self.cpu.WriteRegister(registers[2], source_address)?;
        } else {
            let bytes = [fill_byte; MOPS_CHUNK];
            while remaining != 0 {
                let chunk = remaining.min(MOPS_CHUNK as u64) as usize;
                self.memory
                    .Write(destination_address, &bytes[..chunk], instruction.pc)?;
                if self.exclusive.is_some_and(|(reserved, size)| {
                    Overlaps(destination_address, chunk, reserved, size)
                }) {
                    self.exclusive = None;
                }
                destination_address += chunk as u64;
                remaining -= chunk as u64;
                self.cpu.WriteRegister(registers[0], destination_address)?;
                self.cpu.WriteRegister(registers[1], remaining)?;
            }
        }
        self.cpu.WriteRegister(registers[0], destination_address)?;
        self.cpu.WriteRegister(registers[1], 0)?;
        Ok(())
    }

    fn ExecuteExceptionReturn(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<u64, ExecutionError> {
        let info = ExceptionReturnInfo {
            pc: instruction.pc,
            key_b: matches!(instruction.mnemonic, Mnemonic::Eretab),
        };
        let result =
            self.exception_return
                .Process(self.tid, info)
                .map_err(|error| match error {
                    AdvancedServiceError::ExceptionReturnUnavailable => {
                        self.Unsupported(instruction)
                    }
                    error => ExecutionError::AdvancedService {
                        pc: instruction.pc,
                        mnemonic: instruction.mnemonic_text.clone(),
                        message: error.to_string(),
                    },
                })?;
        Ok((self.address_normalizer)(result.target))
    }

    fn ExecuteFloating(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        #[cfg(target_arch = "aarch64")]
        let host_state = BeginFloatingStatus(&self.cpu);

        let result = if HasVectorArrangement(instruction) {
            self.ExecuteVector(instruction)
        } else {
            self.ExecuteScalarFloating(instruction)
        };

        #[cfg(target_arch = "aarch64")]
        EndFloatingStatus(&mut self.cpu, host_state);
        result
    }

    fn ExecuteScalarFloating(
        &mut self,
        instruction: &DecodedInstruction,
    ) -> Result<(), ExecutionError> {
        match instruction.mnemonic {
            Mnemonic::Fcmp | Mnemonic::Fcmpe => {
                let left = FloatingOperandValue(&self.cpu, instruction, 0)?;
                let right = FloatingOperandValue(&self.cpu, instruction, 1)?;
                self.cpu.nzcv = FloatingCompareFlags(left, right);
                return Ok(());
            }
            Mnemonic::Fcsel => {
                let destination = Self::Register(instruction, 0)?;
                let left = Self::Register(instruction, 1)?;
                let right = Self::Register(instruction, 2)?;
                if destination.Width() != left.Width() || destination.Width() != right.Width() {
                    return Err(self.Unsupported(instruction));
                }
                let source = if instruction.condition.Holds(self.cpu.nzcv) {
                    left
                } else {
                    right
                };
                let bits = self.cpu.ReadRegister(source)?;
                self.cpu.WriteRegister(destination, bits)?;
                return Ok(());
            }
            _ => {}
        }

        let destination = Self::Register(instruction, 0)?;
        if !matches!(destination.Width(), 16 | 32 | 64)
            || destination.Width() == 16
                && !matches!(
                    instruction.mnemonic,
                    Mnemonic::Fmadd
                        | Mnemonic::Fmsub
                        | Mnemonic::Fnmadd
                        | Mnemonic::Fnmsub
                        | Mnemonic::Fmla
                        | Mnemonic::Fmls
                        | Mnemonic::Fabs
                        | Mnemonic::Fneg
                        | Mnemonic::Fsqrt
                        | Mnemonic::Fmax
                        | Mnemonic::Fmin
                        | Mnemonic::Fmaxnm
                        | Mnemonic::Fminnm
                        | Mnemonic::Fnmul
                )
        {
            return Err(self.Unsupported(instruction));
        }
        match instruction.mnemonic {
            Mnemonic::Fmov => {
                let source = instruction
                    .operands
                    .iter()
                    .filter(|operand| {
                        matches!(
                            operand,
                            Operand::Register(_) | Operand::FloatingImmediate(_)
                        )
                    })
                    .nth(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let bits = match source {
                    Operand::Register(register) => self.cpu.ReadRegister(register.register)?,
                    Operand::FloatingImmediate(value) if destination.Width() == 32 => {
                        (*value as f32).to_bits() as u64
                    }
                    Operand::FloatingImmediate(value) => value.to_bits(),
                    _ => return Err(self.Malformed(instruction)),
                };
                self.cpu.WriteRegister(destination, bits)?;
            }
            Mnemonic::Ucvtf | Mnemonic::Scvtf => {
                let source = Self::Register(instruction, 1)?;
                let raw = self.cpu.ReadRegister(source)?;
                let unsigned = matches!(instruction.mnemonic, Mnemonic::Ucvtf);
                AccumulateIntegerToFloatStatus(
                    &mut self.cpu,
                    raw,
                    source.Width(),
                    destination.Width(),
                    unsigned,
                );
                let bits = if destination.Width() == 32 {
                    let value = match (unsigned, source.Width()) {
                        (true, 32) => (raw as u32) as f32,
                        (true, 64) => raw as f32,
                        (false, 32) => (raw as i32) as f32,
                        (false, 64) => (raw as i64) as f32,
                        _ => return Err(self.Unsupported(instruction)),
                    };
                    u64::from(value.to_bits())
                } else {
                    let value = match (unsigned, source.Width()) {
                        (true, 32) => f64::from(raw as u32),
                        (true, 64) => raw as f64,
                        (false, 32) => f64::from(raw as i32),
                        (false, 64) => (raw as i64) as f64,
                        _ => return Err(self.Unsupported(instruction)),
                    };
                    value.to_bits()
                };
                self.cpu.WriteRegister(destination, bits)?;
            }
            Mnemonic::Fcvtzu | Mnemonic::Fcvtzs => {
                let source = Self::Register(instruction, 1)?;
                let bits = self.cpu.ReadRegister(source)?;
                let value = if source.Width() == 32 {
                    f32::from_bits(bits as u32) as f64
                } else {
                    f64::from_bits(bits)
                };
                AccumulateFloatToIntegerStatus(
                    &mut self.cpu,
                    value,
                    destination.Width(),
                    matches!(instruction.mnemonic, Mnemonic::Fcvtzu),
                );
                let converted = if matches!(instruction.mnemonic, Mnemonic::Fcvtzu) {
                    FloatToUnsignedSaturating(value, destination.Width())
                } else {
                    FloatToSignedSaturating(value, destination.Width())
                };
                self.cpu.WriteRegister(destination, converted)?;
            }
            Mnemonic::Fabs | Mnemonic::Fneg | Mnemonic::Fsqrt => {
                let source = FloatingOperandValue(&self.cpu, instruction, 1)?;
                let value = match instruction.mnemonic {
                    Mnemonic::Fabs => source.abs(),
                    Mnemonic::Fneg => -source,
                    Mnemonic::Fsqrt => source.sqrt(),
                    _ => unreachable!(),
                };
                WriteScalarFloatingValue(&mut self.cpu, destination, value)?;
            }
            Mnemonic::Fmax
            | Mnemonic::Fmin
            | Mnemonic::Fmaxnm
            | Mnemonic::Fminnm
            | Mnemonic::Fnmul => {
                let left = FloatingOperandValue(&self.cpu, instruction, 1)?;
                let right = FloatingOperandValue(&self.cpu, instruction, 2)?;
                let value = match instruction.mnemonic {
                    Mnemonic::Fmax => FloatingMinMax(left, right, true, false),
                    Mnemonic::Fmin => FloatingMinMax(left, right, false, false),
                    Mnemonic::Fmaxnm => FloatingMinMax(left, right, true, true),
                    Mnemonic::Fminnm => FloatingMinMax(left, right, false, true),
                    Mnemonic::Fnmul => -(left * right),
                    _ => unreachable!(),
                };
                WriteScalarFloatingValue(&mut self.cpu, destination, value)?;
            }
            Mnemonic::Fadd | Mnemonic::Fsub | Mnemonic::Fmul | Mnemonic::Fdiv => {
                let left = Self::Register(instruction, 1)?;
                let right = Self::Register(instruction, 2)?;
                if destination.Width() == 32 {
                    let left = f32::from_bits(self.cpu.ReadRegister(left)? as u32);
                    let right = f32::from_bits(self.cpu.ReadRegister(right)? as u32);
                    let value = match instruction.mnemonic {
                        Mnemonic::Fadd => left + right,
                        Mnemonic::Fsub => left - right,
                        Mnemonic::Fmul => left * right,
                        Mnemonic::Fdiv => left / right,
                        _ => unreachable!(),
                    };
                    self.cpu
                        .WriteRegister(destination, value.to_bits() as u64)?;
                } else {
                    let left = f64::from_bits(self.cpu.ReadRegister(left)?);
                    let right = f64::from_bits(self.cpu.ReadRegister(right)?);
                    let value = match instruction.mnemonic {
                        Mnemonic::Fadd => left + right,
                        Mnemonic::Fsub => left - right,
                        Mnemonic::Fmul => left * right,
                        Mnemonic::Fdiv => left / right,
                        _ => unreachable!(),
                    };
                    self.cpu.WriteRegister(destination, value.to_bits())?;
                }
            }
            Mnemonic::Fmadd | Mnemonic::Fmsub | Mnemonic::Fnmadd | Mnemonic::Fnmsub => {
                let left = Self::Register(instruction, 1)?;
                let right = Self::Register(instruction, 2)?;
                let accumulator = Self::Register(instruction, 3)?;
                if destination.Width() == 16 {
                    let left = HalfToFloat(self.cpu.ReadRegister(left)? as u16) as f64;
                    let right = HalfToFloat(self.cpu.ReadRegister(right)? as u16) as f64;
                    let accumulator =
                        HalfToFloat(self.cpu.ReadRegister(accumulator)? as u16) as f64;
                    let value = match instruction.mnemonic {
                        Mnemonic::Fmadd => left.mul_add(right, accumulator),
                        Mnemonic::Fmsub => (-left).mul_add(right, accumulator),
                        Mnemonic::Fnmadd => -left.mul_add(right, accumulator),
                        Mnemonic::Fnmsub => left.mul_add(right, -accumulator),
                        _ => unreachable!(),
                    };
                    self.cpu
                        .WriteRegister(destination, u64::from(FloatToHalf(value as f32)))?;
                } else if destination.Width() == 32 {
                    let left = f32::from_bits(self.cpu.ReadRegister(left)? as u32);
                    let right = f32::from_bits(self.cpu.ReadRegister(right)? as u32);
                    let accumulator = f32::from_bits(self.cpu.ReadRegister(accumulator)? as u32);
                    let value = match instruction.mnemonic {
                        Mnemonic::Fmadd => left.mul_add(right, accumulator),
                        Mnemonic::Fmsub => (-left).mul_add(right, accumulator),
                        Mnemonic::Fnmadd => -left.mul_add(right, accumulator),
                        Mnemonic::Fnmsub => left.mul_add(right, -accumulator),
                        _ => unreachable!(),
                    };
                    self.cpu
                        .WriteRegister(destination, value.to_bits() as u64)?;
                } else {
                    let left = f64::from_bits(self.cpu.ReadRegister(left)?);
                    let right = f64::from_bits(self.cpu.ReadRegister(right)?);
                    let accumulator = f64::from_bits(self.cpu.ReadRegister(accumulator)?);
                    let value = match instruction.mnemonic {
                        Mnemonic::Fmadd => left.mul_add(right, accumulator),
                        Mnemonic::Fmsub => (-left).mul_add(right, accumulator),
                        Mnemonic::Fnmadd => -left.mul_add(right, accumulator),
                        Mnemonic::Fnmsub => left.mul_add(right, -accumulator),
                        _ => unreachable!(),
                    };
                    self.cpu.WriteRegister(destination, value.to_bits())?;
                }
            }
            Mnemonic::Fmla | Mnemonic::Fmls => {
                let left = Self::Register(instruction, 1)?;
                let right = instruction
                    .operands
                    .iter()
                    .filter_map(|operand| match operand {
                        Operand::Register(value) => Some(*value),
                        _ => None,
                    })
                    .nth(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_arrangement = right
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_lane = right.lane.ok_or_else(|| self.Malformed(instruction))?;
                let right_value = ReadLane(
                    &self.cpu.v[right_index],
                    right_arrangement,
                    right_lane as u8,
                )?;
                let accumulator = self.cpu.ReadRegister(destination)?;
                if destination.Width() == 16 {
                    let left = HalfToFloat(self.cpu.ReadRegister(left)? as u16) as f64;
                    let accumulator = HalfToFloat(accumulator as u16) as f64;
                    let right = HalfToFloat(right_value as u16) as f64;
                    let value = if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                        (-left).mul_add(right, accumulator)
                    } else {
                        left.mul_add(right, accumulator)
                    };
                    self.cpu
                        .WriteRegister(destination, u64::from(FloatToHalf(value as f32)))?;
                } else if destination.Width() == 32 {
                    let left = f32::from_bits(self.cpu.ReadRegister(left)? as u32);
                    let accumulator = f32::from_bits(accumulator as u32);
                    let right = f32::from_bits(right_value as u32);
                    let value = if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                        (-left).mul_add(right, accumulator)
                    } else {
                        left.mul_add(right, accumulator)
                    };
                    self.cpu
                        .WriteRegister(destination, value.to_bits() as u64)?;
                } else {
                    let left = f64::from_bits(self.cpu.ReadRegister(left)?);
                    let accumulator = f64::from_bits(accumulator);
                    let right = f64::from_bits(right_value);
                    let value = if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                        (-left).mul_add(right, accumulator)
                    } else {
                        left.mul_add(right, accumulator)
                    };
                    self.cpu.WriteRegister(destination, value.to_bits())?;
                }
            }
            _ => return Err(self.Unsupported(instruction)),
        }
        Ok(())
    }

    fn ExecuteVector(&mut self, instruction: &DecodedInstruction) -> Result<(), ExecutionError> {
        let registers: Vec<RegisterOperand> = instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(register) => Some(*register),
                _ => None,
            })
            .collect();
        let destination = *registers
            .first()
            .ok_or_else(|| self.Malformed(instruction))?;
        let destination_index = destination
            .register
            .VectorIndex()
            .ok_or_else(|| self.Malformed(instruction))?;

        match instruction.mnemonic {
            Mnemonic::Mvn => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if source.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let bytes =
                    usize::from(arrangement.element_bits) * usize::from(arrangement.lanes) / 8;
                let mut output = [0; 16];
                for (target, value) in output[..bytes]
                    .iter_mut()
                    .zip(&self.cpu.v[source_index][..bytes])
                {
                    *target = !*value;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Bit | Mnemonic::Bif | Mnemonic::Bsl => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if left.arrangement != Some(arrangement) || right.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let bytes =
                    usize::from(arrangement.element_bits) * usize::from(arrangement.lanes) / 8;
                let mut output = [0; 16];
                for (position, output_byte) in output.iter_mut().enumerate().take(bytes) {
                    let old_destination = self.cpu.v[destination_index][position];
                    let left = self.cpu.v[left_index][position];
                    let right = self.cpu.v[right_index][position];
                    *output_byte = match instruction.mnemonic {
                        Mnemonic::Bit => (old_destination & !right) | (left & right),
                        Mnemonic::Bif => (old_destination & right) | (left & !right),
                        Mnemonic::Bsl => (left & old_destination) | (right & !old_destination),
                        _ => unreachable!(),
                    };
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::And | Mnemonic::Bic | Mnemonic::Orr | Mnemonic::Orn | Mnemonic::Eor => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if left.arrangement != Some(arrangement) || right.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let bytes =
                    usize::from(arrangement.element_bits) * usize::from(arrangement.lanes) / 8;
                let mut output = [0; 16];
                for (position, target) in output[..bytes].iter_mut().enumerate() {
                    let left = self.cpu.v[left_index][position];
                    let right = self.cpu.v[right_index][position];
                    *target = match instruction.mnemonic {
                        Mnemonic::And => left & right,
                        Mnemonic::Bic => left & !right,
                        Mnemonic::Orr => left | right,
                        Mnemonic::Orn => left | !right,
                        Mnemonic::Eor => left ^ right,
                        _ => unreachable!(),
                    };
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Add | Mnemonic::Sub => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if left.arrangement != Some(arrangement) || right.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    let left = ReadLane(&self.cpu.v[left_index], arrangement, lane)?;
                    let right = ReadLane(&self.cpu.v[right_index], arrangement, lane)?;
                    let value = if matches!(instruction.mnemonic, Mnemonic::Sub) {
                        left.wrapping_sub(right)
                    } else {
                        left.wrapping_add(right)
                    };
                    WriteLane(&mut output, arrangement, lane, value)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Clz | Mnemonic::Rbit => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if source.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    let value = ReadLane(&self.cpu.v[source_index], arrangement, lane)?;
                    let result = if matches!(instruction.mnemonic, Mnemonic::Clz) {
                        CountLeadingZeros(value, arrangement.element_bits)
                    } else {
                        ReverseBits(value, arrangement.element_bits)
                    };
                    WriteLane(&mut output, arrangement, lane, result)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Rev | Mnemonic::Rev16 | Mnemonic::Rev32 => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if source.arrangement != Some(arrangement) {
                    return Err(self.Malformed(instruction));
                }
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let group = match instruction.mnemonic {
                    Mnemonic::Rev16 => 2,
                    Mnemonic::Rev32 => 4,
                    Mnemonic::Rev => 8,
                    _ => unreachable!(),
                };
                let bytes =
                    usize::from(arrangement.element_bits) * usize::from(arrangement.lanes) / 8;
                if group > bytes || bytes % group != 0 {
                    return Err(self.Malformed(instruction));
                }
                let mut output = [0; 16];
                for base in (0..bytes).step_by(group) {
                    for offset in 0..group {
                        output[base + offset] = self.cpu.v[source_index][base + group - 1 - offset];
                    }
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Movi => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let immediate = Self::Immediate(instruction, 0)? as u64;
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    WriteLane(&mut output, arrangement, lane, immediate)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Dup => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let value = if let Some(index) = source.register.VectorIndex() {
                    let source_arrangement = source.arrangement.unwrap_or(VectorArrangement {
                        element_bits: arrangement.element_bits,
                        lanes: arrangement.lanes,
                    });
                    ReadLane(
                        &self.cpu.v[index],
                        source_arrangement,
                        source.lane.unwrap_or(0) as u8,
                    )?
                } else {
                    self.cpu.ReadRegister(source.register)?
                };
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    WriteLane(&mut output, arrangement, lane, value)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Ucvtf | Mnemonic::Fcvtzu | Mnemonic::Fcvtzs => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source_arrangement = source.arrangement.unwrap_or(arrangement);
                if source_arrangement != arrangement
                    || !matches!(arrangement.element_bits, 16 | 32 | 64)
                {
                    return Err(self.Unsupported(instruction));
                }
                let scale = instruction
                    .operands
                    .iter()
                    .find_map(|operand| match operand {
                        Operand::Immediate(value) => Some(*value as i32),
                        _ => None,
                    })
                    .unwrap_or(0);
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    let raw = ReadLane(&self.cpu.v[source_index], source_arrangement, lane)?;
                    let value = if matches!(instruction.mnemonic, Mnemonic::Ucvtf) {
                        AccumulateIntegerToFloatStatus(
                            &mut self.cpu,
                            raw,
                            source_arrangement.element_bits,
                            arrangement.element_bits,
                            true,
                        );
                        if arrangement.element_bits == 64 {
                            (raw as f64).to_bits()
                        } else if arrangement.element_bits == 16 {
                            u64::from(FloatToHalf(raw as f32))
                        } else {
                            (raw as f32).to_bits() as u64
                        }
                    } else {
                        let floating = FloatingBitsToDouble(raw, arrangement.element_bits)
                            .ok_or_else(|| self.Malformed(instruction))?
                            * 2.0_f64.powi(scale);
                        let unsigned_result = matches!(instruction.mnemonic, Mnemonic::Fcvtzu);
                        AccumulateFloatToIntegerStatus(
                            &mut self.cpu,
                            floating,
                            arrangement.element_bits,
                            unsigned_result,
                        );
                        if unsigned_result {
                            FloatToUnsignedSaturating(floating, arrangement.element_bits)
                        } else {
                            FloatToSignedSaturating(floating, arrangement.element_bits)
                        }
                    };
                    WriteLane(&mut output, arrangement, lane, value)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Fmla | Mnemonic::Fmls => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let mut output = self.cpu.v[destination_index];
                let right_lane_value = if let Some(lane) = right.lane {
                    let right_arrangement = right
                        .arrangement
                        .ok_or_else(|| self.Malformed(instruction))?;
                    Some(ReadLane(
                        &self.cpu.v[right_index],
                        right_arrangement,
                        lane as u8,
                    )?)
                } else {
                    None
                };
                for lane in 0..arrangement.lanes {
                    let accumulator = ReadLane(&output, arrangement, lane)?;
                    let left = ReadLane(&self.cpu.v[left_index], arrangement, lane)?;
                    let right = match right_lane_value {
                        Some(value) => value,
                        None => ReadLane(&self.cpu.v[right_index], arrangement, lane)?,
                    };
                    let value = if arrangement.element_bits == 64 {
                        let accumulator = f64::from_bits(accumulator);
                        let left = f64::from_bits(left);
                        let right = f64::from_bits(right);
                        if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                            (-left).mul_add(right, accumulator).to_bits()
                        } else {
                            left.mul_add(right, accumulator).to_bits()
                        }
                    } else if arrangement.element_bits == 32 {
                        let accumulator = f32::from_bits(accumulator as u32);
                        let left = f32::from_bits(left as u32);
                        let right = f32::from_bits(right as u32);
                        if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                            (-left).mul_add(right, accumulator).to_bits() as u64
                        } else {
                            left.mul_add(right, accumulator).to_bits() as u64
                        }
                    } else if arrangement.element_bits == 16 {
                        let accumulator = HalfToFloat(accumulator as u16) as f64;
                        let left = HalfToFloat(left as u16) as f64;
                        let right = HalfToFloat(right as u16) as f64;
                        let value = if matches!(instruction.mnemonic, Mnemonic::Fmls) {
                            (-left).mul_add(right, accumulator)
                        } else {
                            left.mul_add(right, accumulator)
                        };
                        u64::from(FloatToHalf(value as f32))
                    } else {
                        return Err(self.Unsupported(instruction));
                    };
                    WriteLane(&mut output, arrangement, lane, value)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Cmeq | Mnemonic::Cmhs => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let lane_mask = Mask(arrangement.element_bits);
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    let left = ReadLane(&self.cpu.v[left_index], arrangement, lane)?;
                    let right = ReadLane(&self.cpu.v[right_index], arrangement, lane)?;
                    let matches = if matches!(instruction.mnemonic, Mnemonic::Cmeq) {
                        left == right
                    } else {
                        left >= right
                    };
                    WriteLane(
                        &mut output,
                        arrangement,
                        lane,
                        if matches { lane_mask } else { 0 },
                    )?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Addv => {
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let arrangement = source
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let mut sum = 0_u64;
                for lane in 0..arrangement.lanes {
                    sum = sum.wrapping_add(ReadLane(&self.cpu.v[source_index], arrangement, lane)?);
                }
                let destination_arrangement = VectorArrangement {
                    element_bits: destination.register.Width(),
                    lanes: 1,
                };
                let mut output = [0; 16];
                WriteLane(&mut output, destination_arrangement, 0, sum)?;
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Addp | Mnemonic::Umaxp => {
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left_arrangement = left
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                if left_arrangement.element_bits != destination.register.Width()
                    && left_arrangement.element_bits
                        != destination
                            .arrangement
                            .ok_or_else(|| self.Malformed(instruction))?
                            .element_bits
                {
                    return Err(self.Malformed(instruction));
                }
                if left_arrangement.lanes % 2 != 0 {
                    return Err(self.Malformed(instruction));
                }

                let mut output = [0; 16];
                if registers.len() < 3 {
                    if !matches!(instruction.mnemonic, Mnemonic::Addp) {
                        return Err(self.Unsupported(instruction));
                    }
                    let destination_arrangement = destination
                        .arrangement
                        .ok_or_else(|| self.Malformed(instruction))?;
                    if destination_arrangement.lanes != 1 || left_arrangement.lanes != 2 {
                        return Err(self.Unsupported(instruction));
                    }
                    let first = ReadLane(&self.cpu.v[left_index], left_arrangement, 0)?;
                    let second = ReadLane(&self.cpu.v[left_index], left_arrangement, 1)?;
                    WriteLane(
                        &mut output,
                        destination_arrangement,
                        0,
                        first.wrapping_add(second),
                    )?;
                } else {
                    let destination_arrangement = destination
                        .arrangement
                        .ok_or_else(|| self.Malformed(instruction))?;
                    let right = *registers
                        .get(2)
                        .ok_or_else(|| self.Malformed(instruction))?;
                    let right_index = right
                        .register
                        .VectorIndex()
                        .ok_or_else(|| self.Malformed(instruction))?;
                    let right_arrangement = right
                        .arrangement
                        .ok_or_else(|| self.Malformed(instruction))?;
                    if right_arrangement != left_arrangement
                        || destination_arrangement.lanes != left_arrangement.lanes
                    {
                        return Err(self.Malformed(instruction));
                    }
                    let pairs = left_arrangement.lanes / 2;
                    for source in 0..2 {
                        let (register, arrangement) = if source == 0 {
                            (&self.cpu.v[left_index], left_arrangement)
                        } else {
                            (&self.cpu.v[right_index], right_arrangement)
                        };
                        for pair in 0..pairs {
                            let first = ReadLane(register, arrangement, pair * 2)?;
                            let second = ReadLane(register, arrangement, pair * 2 + 1)?;
                            let value = if matches!(instruction.mnemonic, Mnemonic::Umaxp) {
                                first.max(second)
                            } else {
                                first.wrapping_add(second)
                            };
                            WriteLane(
                                &mut output,
                                destination_arrangement,
                                source * pairs + pair,
                                value,
                            )?;
                        }
                    }
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Uzp1 | Mnemonic::Uzp2 => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let left_index = left
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let right_index = right
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let half = arrangement.lanes / 2;
                let parity = if matches!(instruction.mnemonic, Mnemonic::Uzp2) {
                    1
                } else {
                    0
                };
                let mut output = [0; 16];
                for lane in 0..half {
                    WriteLane(
                        &mut output,
                        arrangement,
                        lane,
                        ReadLane(&self.cpu.v[left_index], arrangement, lane * 2 + parity)?,
                    )?;
                    WriteLane(
                        &mut output,
                        arrangement,
                        half + lane,
                        ReadLane(&self.cpu.v[right_index], arrangement, lane * 2 + parity)?,
                    )?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Ushl => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let value = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let shift = *registers
                    .get(2)
                    .ok_or_else(|| self.Malformed(instruction))?;
                if value.arrangement != Some(arrangement) || shift.arrangement != Some(arrangement)
                {
                    return Err(self.Malformed(instruction));
                }
                let value_index = value
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let shift_index = shift
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                let element_mask = Mask(arrangement.element_bits);
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    let value = ReadLane(&self.cpu.v[value_index], arrangement, lane)?;
                    let encoded_shift = ReadLane(&self.cpu.v[shift_index], arrangement, lane)?;
                    let low_byte = (encoded_shift & 0xff) as u8;
                    let shift = i8::from_ne_bytes([low_byte]);
                    let shifted = if shift >= 0 {
                        let amount = shift as u32;
                        if amount < u32::from(arrangement.element_bits) {
                            value.wrapping_shl(amount) & element_mask
                        } else {
                            0
                        }
                    } else {
                        let amount = u32::from((-shift) as u8);
                        if amount < u32::from(arrangement.element_bits) {
                            value >> amount
                        } else {
                            0
                        }
                    };
                    WriteLane(&mut output, arrangement, lane, shifted)?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Xtn | Mnemonic::Xtn2 => {
                let destination_arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source = *registers
                    .get(1)
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source_arrangement = source
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let source_index = source
                    .register
                    .VectorIndex()
                    .ok_or_else(|| self.Malformed(instruction))?;
                if source_arrangement.element_bits != destination_arrangement.element_bits * 2
                    || source_arrangement.lanes > destination_arrangement.lanes
                {
                    return Err(self.Unsupported(instruction));
                }
                let first_lane = if matches!(instruction.mnemonic, Mnemonic::Xtn2) {
                    destination_arrangement.lanes - source_arrangement.lanes
                } else {
                    0
                };
                let mut output = if matches!(instruction.mnemonic, Mnemonic::Xtn2) {
                    self.cpu.v[destination_index]
                } else {
                    [0; 16]
                };
                for lane in 0..source_arrangement.lanes {
                    WriteLane(
                        &mut output,
                        destination_arrangement,
                        first_lane + lane,
                        ReadLane(&self.cpu.v[source_index], source_arrangement, lane)?,
                    )?;
                }
                self.cpu.v[destination_index] = output;
            }
            Mnemonic::Fmov => {
                let arrangement = destination
                    .arrangement
                    .ok_or_else(|| self.Malformed(instruction))?;
                let immediate = instruction
                    .operands
                    .iter()
                    .find_map(|operand| match operand {
                        Operand::FloatingImmediate(value) => Some(*value),
                        _ => None,
                    })
                    .ok_or_else(|| self.Malformed(instruction))?;
                let bits = if arrangement.element_bits == 64 {
                    immediate.to_bits()
                } else {
                    (immediate as f32).to_bits() as u64
                };
                let mut output = [0; 16];
                for lane in 0..arrangement.lanes {
                    WriteLane(&mut output, arrangement, lane, bits)?;
                }
                self.cpu.v[destination_index] = output;
            }
            _ => return Err(self.Unsupported(instruction)),
        }
        Ok(())
    }

    fn Register(
        instruction: &DecodedInstruction,
        index: usize,
    ) -> Result<Register, ExecutionError> {
        instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(value.register),
                _ => None,
            })
            .nth(index)
            .ok_or_else(|| ExecutionError::Malformed {
                pc: instruction.pc,
                mnemonic: instruction.mnemonic_text.clone(),
            })
    }

    fn Immediate(instruction: &DecodedInstruction, index: usize) -> Result<i64, ExecutionError> {
        instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Immediate(value) => Some(*value),
                _ => None,
            })
            .nth(index)
            .ok_or_else(|| ExecutionError::Malformed {
                pc: instruction.pc,
                mnemonic: instruction.mnemonic_text.clone(),
            })
    }

    fn Value(
        cpu: &mut CpuState,
        instruction: &DecodedInstruction,
        index: usize,
    ) -> Result<u64, ExecutionError> {
        instruction
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(value) => Some(cpu.ReadRegister(value.register).map(|raw| {
                    ApplyExtend(raw, value.extend, value.shift, value.register.Width())
                })),
                Operand::Immediate(value) => Some(Ok(*value as u64)),
                _ => None,
            })
            .nth(index)
            .ok_or_else(|| ExecutionError::Malformed {
                pc: instruction.pc,
                mnemonic: instruction.mnemonic_text.clone(),
            })?
            .map_err(ExecutionError::from)
    }

    fn Unsupported(&self, instruction: &DecodedInstruction) -> ExecutionError {
        ExecutionError::Unsupported {
            pc: instruction.pc,
            word: instruction.word,
            mnemonic: instruction.mnemonic_text.clone(),
        }
    }

    fn Malformed(&self, instruction: &DecodedInstruction) -> ExecutionError {
        ExecutionError::Malformed {
            pc: instruction.pc,
            mnemonic: instruction.mnemonic_text.clone(),
        }
    }
}

fn SignExtend(value: u64, width: u8) -> i128 {
    let bits = u32::from(width);
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    let value = value & mask;
    let sign = 1_u64 << (bits - 1);
    if value & sign != 0 {
        i128::from(value) - (1_i128 << bits)
    } else {
        i128::from(value)
    }
}

fn FlagsForResult(result: u64, left: u64, right: u64, subtract: bool, width: u8) -> u32 {
    let mask = if width == 64 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let mut flags = 0;
    if SignExtend(result, width) < 0 {
        flags |= N;
    }
    if result & mask == 0 {
        flags |= Z;
    }
    if subtract {
        if left & mask >= right & mask {
            flags |= C;
        }
        let l = SignExtend(left, width);
        let r = SignExtend(right, width);
        let out = SignExtend(result, width);
        if (l < 0) != (r < 0) && (out < 0) != (l < 0) {
            flags |= V;
        }
    }
    flags
}

fn FlagsForAdd(result: u64, left: u64, right: u64, width: u8) -> u32 {
    let mask = if width == 64 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let mut flags = 0;
    if SignExtend(result, width) < 0 {
        flags |= N;
    }
    if result & mask == 0 {
        flags |= Z;
    }
    if u128::from(left & mask) + u128::from(right & mask) > u128::from(mask) {
        flags |= C;
    }
    let l = SignExtend(left, width);
    let r = SignExtend(right, width);
    let out = SignExtend(result, width);
    if (l < 0) == (r < 0) && (out < 0) != (l < 0) {
        flags |= V;
    }
    flags
}

fn AccumulateFloatToIntegerStatus(
    cpu: &mut CpuState,
    value: f64,
    width: u8,
    unsigned_result: bool,
) {
    if !value.is_finite() {
        cpu.fpsr = (cpu.fpsr | FPSR_IOC) & FPSR_ARCHITECTED_MASK;
        return;
    }
    let truncated = value.trunc();
    let out_of_range = if unsigned_result {
        truncated < 0.0 || truncated >= 2.0_f64.powi(i32::from(width))
    } else {
        let bound = 2.0_f64.powi(i32::from(width - 1));
        truncated < -bound || truncated >= bound
    };
    if out_of_range {
        cpu.fpsr = (cpu.fpsr | FPSR_IOC) & FPSR_ARCHITECTED_MASK;
    } else if truncated != value {
        cpu.fpsr = (cpu.fpsr | FPSR_IXC) & FPSR_ARCHITECTED_MASK;
    }
}

fn FloatingBitsToDouble(bits: u64, width: u8) -> Option<f64> {
    match width {
        16 => Some(f64::from(HalfToFloat(bits as u16))),
        32 => Some(f64::from(f32::from_bits(bits as u32))),
        64 => Some(f64::from_bits(bits)),
        _ => None,
    }
}

fn DoubleToFloatingBits(value: f64, width: u8) -> Option<u64> {
    match width {
        16 => Some(u64::from(FloatToHalf(value as f32))),
        32 => Some(u64::from((value as f32).to_bits())),
        64 => Some(value.to_bits()),
        _ => None,
    }
}

fn HalfToFloat(half: u16) -> f32 {
    let sign = u32::from(half & 0x8000) << 16;
    let mut exponent = u32::from((half >> 10) & 0x1f);
    let mut fraction = u32::from(half & 0x03ff);
    let mut bits = sign;
    if exponent == 0 {
        if fraction != 0 {
            let mut shift = 0;
            while fraction & 0x0400 == 0 {
                fraction <<= 1;
                shift += 1;
            }
            fraction &= 0x03ff;
            bits |= ((113 - shift) << 23) | (fraction << 13);
        }
    } else if exponent == 0x1f {
        bits |= 0x7f80_0000 | (fraction << 13);
        if fraction != 0 {
            bits |= 0x0040_0000;
        }
    } else {
        exponent += 112;
        bits |= (exponent << 23) | (fraction << 13);
    }
    f32::from_bits(bits)
}

fn FloatToHalf(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let source_exponent = (bits >> 23) & 0xff;
    let source_fraction = bits & 0x007f_ffff;
    if source_exponent == 0xff {
        if source_fraction == 0 {
            return sign | 0x7c00;
        }
        let payload = (((source_fraction >> 13) as u16) | 0x0200) & 0x03ff;
        return sign | 0x7c00 | payload;
    }

    let mut exponent = source_exponent as i32 - 127 + 15;
    if exponent >= 31 {
        return sign | 0x7c00;
    }
    if exponent <= 0 {
        if exponent < -10 {
            return sign;
        }
        let significand = source_fraction | 0x0080_0000;
        let shift = (14 - exponent) as u32;
        let mut rounded = significand >> shift;
        let remainder = significand & ((1_u32 << shift) - 1);
        let halfway = 1_u32 << (shift - 1);
        if remainder > halfway || remainder == halfway && rounded & 1 != 0 {
            rounded += 1;
        }
        return sign | rounded as u16;
    }

    let mut rounded_fraction = source_fraction + 0x0fff + ((source_fraction >> 13) & 1);
    if rounded_fraction & 0x0080_0000 != 0 {
        rounded_fraction = 0;
        exponent += 1;
        if exponent >= 31 {
            return sign | 0x7c00;
        }
    }
    sign | ((exponent as u16) << 10) | (rounded_fraction >> 13) as u16
}

fn BFloat16ToFloat(value: u16) -> f32 {
    f32::from_bits(u32::from(value) << 16)
}

fn FloatToBFloat16(value: f32) -> u16 {
    let mut bits = value.to_bits();
    if (bits & 0x7F80_0000) == 0x7F80_0000 && (bits & 0x007F_FFFF) != 0 {
        return ((bits >> 16) as u16) | 0x0040;
    }
    bits = bits.wrapping_add(0x0000_7FFF + ((bits >> 16) & 1));
    (bits >> 16) as u16
}

fn FloatToUnsignedSaturating(value: f64, width: u8) -> u64 {
    if value.is_nan() || value <= 0.0 {
        return 0;
    }
    let truncated = value.trunc();
    if truncated >= 2.0_f64.powi(i32::from(width)) {
        Mask(width)
    } else {
        (truncated as u64) & Mask(width)
    }
}

fn FloatToSignedSaturating(value: f64, width: u8) -> u64 {
    if value.is_nan() {
        return 0;
    }
    let truncated = value.trunc();
    let bound = 2.0_f64.powi(i32::from(width - 1));
    if truncated <= -bound {
        1_u64 << (width - 1)
    } else if truncated >= bound {
        (1_u64 << (width - 1)) - 1
    } else {
        (truncated as i64 as u64) & Mask(width)
    }
}

fn ScalarFloatingValue(cpu: &CpuState, register: Register) -> Result<f64, ExecutionError> {
    let raw = cpu.ReadRegister(register)?;
    Ok(match register.Width() {
        16 => f64::from(HalfToFloat(raw as u16)),
        32 => f64::from(f32::from_bits(raw as u32)),
        64 => f64::from_bits(raw),
        _ => unreachable!(),
    })
}

fn FloatingOperandValue(
    cpu: &CpuState,
    instruction: &DecodedInstruction,
    index: usize,
) -> Result<f64, ExecutionError> {
    instruction
        .operands
        .iter()
        .filter_map(|operand| match operand {
            Operand::Register(value) => Some(ScalarFloatingValue(cpu, value.register)),
            Operand::FloatingImmediate(value) => Some(Ok(*value)),
            _ => None,
        })
        .nth(index)
        .ok_or_else(|| ExecutionError::Malformed {
            pc: instruction.pc,
            mnemonic: instruction.mnemonic_text.clone(),
        })?
}

fn WriteScalarFloatingValue(
    cpu: &mut CpuState,
    register: Register,
    value: f64,
) -> Result<(), ExecutionError> {
    match register.Width() {
        16 => cpu.WriteRegister(register, u64::from(FloatToHalf(value as f32)))?,
        32 => cpu.WriteRegister(register, u64::from((value as f32).to_bits()))?,
        64 => cpu.WriteRegister(register, value.to_bits())?,
        _ => unreachable!(),
    }
    Ok(())
}

fn FloatingCompareFlags(left: f64, right: f64) -> u32 {
    if left.is_nan() || right.is_nan() {
        C | V
    } else if left == right {
        Z | C
    } else if left < right {
        N
    } else {
        C
    }
}

fn FloatingMinMax(left: f64, right: f64, maximum: bool, numeric: bool) -> f64 {
    let left_nan = left.is_nan();
    let right_nan = right.is_nan();
    if left_nan || right_nan {
        if numeric && left_nan != right_nan {
            return if left_nan { right } else { left };
        }
        return f64::NAN;
    }
    if left == 0.0 && right == 0.0 {
        let negative = if maximum {
            left.is_sign_negative() && right.is_sign_negative()
        } else {
            left.is_sign_negative() || right.is_sign_negative()
        };
        return if negative { -0.0 } else { 0.0 };
    }
    if maximum {
        left.max(right)
    } else {
        left.min(right)
    }
}

fn CountLeadingZeros(value: u64, width: u8) -> u64 {
    match width {
        8 => u64::from((value as u8).leading_zeros()),
        16 => u64::from((value as u16).leading_zeros()),
        32 => u64::from((value as u32).leading_zeros()),
        64 => u64::from(value.leading_zeros()),
        _ => unreachable!(),
    }
}

fn ReverseBits(value: u64, width: u8) -> u64 {
    match width {
        8 => u64::from((value as u8).reverse_bits()),
        16 => u64::from((value as u16).reverse_bits()),
        32 => u64::from((value as u32).reverse_bits()),
        64 => value.reverse_bits(),
        _ => unreachable!(),
    }
}

fn ReverseBytes(value: u64, width: u8) -> u64 {
    let mut bytes = value.to_le_bytes();
    let size = usize::from(width / 8);
    bytes[..size].reverse();
    u64::from_le_bytes(bytes)
}

fn ReverseBytesInHalfwords(value: u64, width: u8) -> u64 {
    let mut bytes = value.to_le_bytes();
    let size = usize::from(width / 8);
    for chunk in bytes[..size].chunks_exact_mut(2) {
        chunk.reverse();
    }
    u64::from_le_bytes(bytes)
}

fn ReverseBytesInWords(value: u64, width: u8) -> u64 {
    let mut bytes = value.to_le_bytes();
    let size = usize::from(width / 8);
    for chunk in bytes[..size].chunks_exact_mut(4) {
        chunk.reverse();
    }
    u64::from_le_bytes(bytes)
}

fn SignedMultiplyHigh(left: u64, right: u64) -> u64 {
    ((SignExtend(left, 64) * SignExtend(right, 64)) >> 64) as u64
}

fn UnsignedMultiplyHigh(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) >> 64) as u64
}

fn AccumulateIntegerToFloatStatus(
    cpu: &mut CpuState,
    raw: u64,
    source_width: u8,
    destination_width: u8,
    unsigned_source: bool,
) {
    let magnitude = if unsigned_source {
        raw & Mask(source_width)
    } else if source_width == 32 {
        u64::from((raw as u32 as i32).unsigned_abs())
    } else {
        (raw as i64).unsigned_abs()
    };
    let precision = match destination_width {
        16 => 11,
        32 => 24,
        _ => 53,
    };
    let significant_bits = 64 - magnitude.leading_zeros();
    let exactly_representable = magnitude == 0
        || significant_bits <= precision
        || magnitude.trailing_zeros() >= significant_bits - precision;
    if !exactly_representable {
        cpu.fpsr = (cpu.fpsr | FPSR_IXC) & FPSR_ARCHITECTED_MASK;
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct HostFloatingStatus {
    fpcr: u64,
    fpsr: u64,
}

#[cfg(target_arch = "aarch64")]
fn BeginFloatingStatus(cpu: &CpuState) -> HostFloatingStatus {
    use core::arch::asm;

    let saved_fpcr: u64;
    let saved_fpsr: u64;
    let guest_fpcr = u64::from(cpu.fpcr & !FPCR_EXCEPTION_ENABLE_MASK);
    let guest_fpsr = u64::from(cpu.fpsr & FPSR_ARCHITECTED_MASK);
    unsafe {
        asm!("mrs {saved}, fpcr", saved = out(reg) saved_fpcr, options(nostack, preserves_flags));
        asm!("mrs {saved}, fpsr", saved = out(reg) saved_fpsr, options(nostack, preserves_flags));
        asm!(
            "msr fpcr, {guest_fpcr}",
            "msr fpsr, {guest_fpsr}",
            "isb",
            guest_fpcr = in(reg) guest_fpcr,
            guest_fpsr = in(reg) guest_fpsr,
            options(nostack, preserves_flags)
        );
    }
    HostFloatingStatus {
        fpcr: saved_fpcr,
        fpsr: saved_fpsr,
    }
}

#[cfg(target_arch = "aarch64")]
fn EndFloatingStatus(cpu: &mut CpuState, host: HostFloatingStatus) {
    use core::arch::asm;

    let raised_fpsr: u64;
    unsafe {
        asm!("mrs {raised}, fpsr", raised = out(reg) raised_fpsr, options(nostack, preserves_flags));
        asm!(
            "msr fpsr, {saved_fpsr}",
            "msr fpcr, {saved_fpcr}",
            "isb",
            saved_fpsr = in(reg) host.fpsr,
            saved_fpcr = in(reg) host.fpcr,
            options(nostack, preserves_flags)
        );
    }
    cpu.fpsr = (cpu.fpsr | raised_fpsr as u32) & FPSR_ARCHITECTED_MASK;
}

fn ApplyExtend(value: u64, extend: Extend, shift: Shift, operand_width: u8) -> u64 {
    let value = match extend {
        Extend::None | Extend::Uxtx | Extend::Sxtx => value,
        Extend::Uxtb => value & 0xff,
        Extend::Uxth => value & 0xffff,
        Extend::Uxtw => value & u64::from(u32::MAX),
        Extend::Sxtb => (value as i8 as i64) as u64,
        Extend::Sxth => (value as i16 as i64) as u64,
        Extend::Sxtw => (value as i32 as i64) as u64,
    };
    let shift_width = if extend == Extend::None {
        operand_width
    } else {
        64
    };
    let amount_mask = u32::from(shift_width - 1);
    match shift {
        Shift::None => value,
        Shift::Lsl(amount) => value.wrapping_shl(amount) & Mask(shift_width),
        Shift::Lsr(amount) => (value & Mask(shift_width)) >> amount,
        Shift::Asr(amount) => (SignExtend(value, shift_width) >> amount) as u64,
        Shift::Ror(amount) if shift_width == 32 => {
            u64::from((value as u32).rotate_right(amount & amount_mask))
        }
        Shift::Ror(amount) => value.rotate_right(amount & amount_mask),
        Shift::Msl(amount) => (value.wrapping_shl(amount) | Mask(amount as u8)) & Mask(shift_width),
    }
}

fn BitfieldRegister(raw: u32, width: u8) -> Register {
    match (width, raw) {
        (32, 31) => Register::Wzr,
        (32, value) => Register::W(value as u8),
        (_, 31) => Register::Xzr,
        (_, value) => Register::X(value as u8),
    }
}

fn RotateRight(value: u64, amount: u32, width: u8) -> u64 {
    let width = if width == 32 { 32 } else { 64 };
    let amount = amount % u32::from(width);
    let value = value & Mask(width);
    if amount == 0 {
        value
    } else {
        ((value >> amount) | (value << (u32::from(width) - amount))) & Mask(width)
    }
}

fn DecodeBitMasks(raw: u32, width: u8, wmask: &mut u64, tmask: &mut u64) -> bool {
    let n = (raw >> 22) & 1;
    let immr = (raw >> 16) & 0x3f;
    let imms = (raw >> 10) & 0x3f;
    let combined = (n << 6) | ((!imms) & 0x3f);
    let Some(len) = (1..=6).rev().find(|bit| combined & (1 << bit) != 0) else {
        return false;
    };
    let levels = (1_u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    let element_bits = 1_u8 << len;
    if element_bits > width {
        return false;
    }
    let d = s.wrapping_sub(r) & levels;
    let welem = Mask((s + 1) as u8);
    let telem = Mask((d + 1) as u8);
    let rotated = RotateRight(welem, r, element_bits);
    *wmask = 0;
    *tmask = 0;
    let mut offset = 0_u8;
    while offset < width {
        *wmask |= rotated << offset;
        *tmask |= telem << offset;
        offset += element_bits;
    }
    *wmask &= Mask(width);
    *tmask &= Mask(width);
    true
}

fn HasVectorArrangement(instruction: &DecodedInstruction) -> bool {
    instruction.operands.iter().any(|operand| {
        matches!(
            operand,
            Operand::Register(RegisterOperand {
                arrangement: Some(VectorArrangement { lanes, .. }),
                ..
            }) if *lanes > 1
        )
    })
}

fn HasVectorOperand(instruction: &DecodedInstruction) -> bool {
    instruction.operands.iter().any(|operand| {
        matches!(
            operand,
            Operand::Register(RegisterOperand {
                register: Register::Vector { .. },
                ..
            })
        )
    })
}

fn RegisterNumber(register: Register) -> Option<u8> {
    match register {
        Register::X(index) | Register::W(index) | Register::Vector { index, .. } => Some(index),
        _ => None,
    }
}

fn Mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    }
}

fn ReadLane(
    register: &[u8; 16],
    arrangement: VectorArrangement,
    lane: u8,
) -> Result<u64, ExecutionError> {
    let size = usize::from(arrangement.element_bits / 8);
    if size > 8 {
        return Err(RegisterError::InvalidVectorWidth(size).into());
    }
    let offset = usize::from(lane) * size;
    let source = register
        .get(offset..offset + size)
        .ok_or_else(|| RegisterError::InvalidVectorWidth(offset + size))?;
    let mut bytes = [0; 8];
    bytes[..size].copy_from_slice(source);
    Ok(u64::from_le_bytes(bytes))
}

fn WriteLane(
    register: &mut [u8; 16],
    arrangement: VectorArrangement,
    lane: u8,
    value: u64,
) -> Result<(), ExecutionError> {
    let size = usize::from(arrangement.element_bits / 8);
    if size > 8 {
        return Err(RegisterError::InvalidVectorWidth(size).into());
    }
    let offset = usize::from(lane) * size;
    let target = register
        .get_mut(offset..offset + size)
        .ok_or_else(|| RegisterError::InvalidVectorWidth(offset + size))?;
    target.copy_from_slice(&value.to_le_bytes()[..size]);
    Ok(())
}

fn Overlaps(left: u64, left_size: usize, right: u64, right_size: usize) -> bool {
    let left_end = left.saturating_add(left_size as u64);
    let right_end = right.saturating_add(right_size as u64);
    left < right_end && right < left_end
}

fn IdentityAddress(value: u64) -> u64 {
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monarch::memory::{GuestMemory, MemoryError, TargetMemory};

    #[derive(Clone, Default)]
    struct RejectingTarget;

    impl TargetMemory for RejectingTarget {
        fn Read(
            &self,
            _pid: i32,
            _address: u64,
            _output: &mut [u8],
            _cached: bool,
        ) -> Result<(), MemoryError> {
            Err(MemoryError::Unmapped)
        }
    }

    #[derive(Clone, Default)]
    struct NoopPAuth;

    impl super::PAuthService for NoopPAuth {
        fn Process(
            &self,
            _tid: i32,
            _operation: super::PAuthOperation,
            value: u64,
            _modifier: u64,
        ) -> Result<
            crate::monarch::arm64::pauth::PAuthResult,
            crate::monarch::arm64::pauth::ServiceError,
        > {
            Ok(crate::monarch::arm64::pauth::PAuthResult {
                value,
                ioctl_result: 0,
            })
        }
    }

    #[test]
    fn FaultingStxpClearsExclusiveMonitor() {
        let mut cpu = CpuState {
            pc: 0x3000,
            ..Default::default()
        };
        cpu.SetX(0, 0x1ff8).unwrap();
        cpu.SetX(4, 11).unwrap();
        cpu.SetX(5, 22).unwrap();
        let mut memory = GuestMemory::New(RejectingTarget, 1);
        memory
            .MapBytes(0x3000, &0xC823_1404_u32.to_le_bytes())
            .unwrap();
        memory.MapBytes(0x1ff0, &[0; 16]).unwrap();
        let mut executor = Executor::New(cpu, memory, NoopPAuth, 1).unwrap();
        executor.exclusive = Some((0x1ff8, 16));

        assert!(matches!(executor.Step(), Err(ExecutionError::Memory(_))));
        assert_eq!(executor.exclusive, None);

        executor.MemoryMut().MapBytes(0x2000, &[0; 16]).unwrap();
        assert!(matches!(executor.Step(), Ok(StepOutcome::Continue)));
        assert_eq!(executor.Cpu().X(3).unwrap(), 1);
        assert!(executor.Memory().Writes().is_empty());
    }

    #[test]
    fn FaultingStxrClearsExclusiveMonitor() {
        let mut cpu = CpuState {
            pc: 0x3100,
            ..Default::default()
        };
        cpu.SetX(0, 0x1ffc).unwrap();
        cpu.SetX(1, 11).unwrap();
        let mut memory = GuestMemory::New(RejectingTarget, 1);
        memory
            .MapBytes(0x3100, &0xC802_7C01_u32.to_le_bytes())
            .unwrap();
        memory.MapBytes(0x1ff0, &[0; 16]).unwrap();
        let mut executor = Executor::New(cpu, memory, NoopPAuth, 1).unwrap();
        executor.exclusive = Some((0x1ffc, 8));

        assert!(matches!(executor.Step(), Err(ExecutionError::Memory(_))));
        assert_eq!(executor.exclusive, None);

        executor.MemoryMut().MapBytes(0x2000, &[0; 8]).unwrap();
        assert!(matches!(executor.Step(), Ok(StepOutcome::Continue)));
        assert_eq!(executor.Cpu().X(2).unwrap(), 1);
        assert!(executor.Memory().Writes().is_empty());
    }
}
