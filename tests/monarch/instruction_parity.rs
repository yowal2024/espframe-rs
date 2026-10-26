#![allow(non_snake_case)]

use std::collections::BTreeMap;

use espframe::monarch::advanced_services::{
    AdvancedServiceError, AtomicRcwInfo, AtomicRcwOperation, AtomicRcwResult, AtomicRcwService,
    ExceptionReturnInfo, ExceptionReturnResult, ExceptionReturnService, GcsInfo, GcsOperation,
    GcsResult, GcsService, MemoryTagInfo, MemoryTagOperation, MemoryTagResult, MemoryTagService,
    MopsInfo, MopsOperation, MopsResult, MopsService, RejectAtomicRcwService,
    RejectExceptionReturnService, RejectGcsService, RejectMemoryTagService, RejectMopsService,
    RejectStore64Service, Store64Info, Store64Operation, Store64Result, Store64Service,
};
use espframe::monarch::arm64::{
    CpuState, ExecutionError, Executor, PAuthOperation, PAuthResult, PAuthService,
    RejectSystemRegisterService, ServiceError, StepOutcome, SystemRegister, SystemRegisterError,
    SystemRegisterService,
};
use espframe::monarch::memory::{GuestMemory, MemoryError, TargetMemory};
use serde::Deserialize;

#[derive(Clone, Default)]
struct FixtureTarget;

impl TargetMemory for FixtureTarget {
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
struct FixturePAuth {
    result: u64,
}

impl PAuthService for FixturePAuth {
    fn Process(
        &self,
        _tid: i32,
        _operation: PAuthOperation,
        _value: u64,
        _modifier: u64,
    ) -> Result<PAuthResult, ServiceError> {
        Ok(PAuthResult {
            value: self.result,
            ioctl_result: 0,
        })
    }
}

#[derive(Clone)]
struct ExpectedPAuthCall {
    operation: PAuthOperation,
    value: u64,
    modifier: u64,
    result: u64,
}

#[derive(Clone)]
struct RejectPAuthCall;

impl PAuthService for RejectPAuthCall {
    fn Process(
        &self,
        _tid: i32,
        _operation: PAuthOperation,
        _value: u64,
        _modifier: u64,
    ) -> Result<PAuthResult, ServiceError> {
        Err(ServiceError::PAuth("rejected by test service".to_owned()))
    }
}

impl PAuthService for ExpectedPAuthCall {
    fn Process(
        &self,
        _tid: i32,
        operation: PAuthOperation,
        value: u64,
        modifier: u64,
    ) -> Result<PAuthResult, ServiceError> {
        assert_eq!(operation, self.operation);
        assert_eq!(value, self.value);
        assert_eq!(modifier, self.modifier);
        Ok(PAuthResult {
            value: self.result,
            ioctl_result: 0,
        })
    }
}

#[derive(Clone)]
struct ExpectedSystemRegister {
    register: SystemRegister,
    value: u64,
    write: bool,
}

impl SystemRegisterService for ExpectedSystemRegister {
    fn Read(&self, tid: i32, register: SystemRegister) -> Result<u64, SystemRegisterError> {
        assert!(!self.write);
        assert_eq!(tid, 77);
        assert_eq!(register, self.register);
        Ok(self.value)
    }

    fn Write(
        &self,
        tid: i32,
        register: SystemRegister,
        value: u64,
    ) -> Result<(), SystemRegisterError> {
        assert!(self.write);
        assert_eq!(tid, 77);
        assert_eq!(register, self.register);
        assert_eq!(value, self.value);
        Ok(())
    }
}

#[derive(Clone)]
struct ExpectedAtomicRcw {
    expected: AtomicRcwInfo,
    result: AtomicRcwResult,
}

impl AtomicRcwService for ExpectedAtomicRcw {
    fn Process(
        &self,
        tid: i32,
        info: AtomicRcwInfo,
    ) -> Result<AtomicRcwResult, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone)]
struct ExpectedStore64 {
    expected: Store64Info,
    result: Store64Result,
}

impl Store64Service for ExpectedStore64 {
    fn Process(&self, tid: i32, info: Store64Info) -> Result<Store64Result, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone)]
struct ExpectedMemoryTag {
    expected: MemoryTagInfo,
    result: MemoryTagResult,
}

impl MemoryTagService for ExpectedMemoryTag {
    fn Process(
        &self,
        tid: i32,
        info: MemoryTagInfo,
    ) -> Result<MemoryTagResult, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone)]
struct ExpectedGcs {
    expected: GcsInfo,
    result: GcsResult,
}

impl GcsService for ExpectedGcs {
    fn Process(&self, tid: i32, info: GcsInfo) -> Result<GcsResult, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone)]
struct ExpectedExceptionReturn {
    expected: ExceptionReturnInfo,
    result: ExceptionReturnResult,
}

impl ExceptionReturnService for ExpectedExceptionReturn {
    fn Process(
        &self,
        tid: i32,
        info: ExceptionReturnInfo,
    ) -> Result<ExceptionReturnResult, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone)]
struct ExpectedMops {
    expected: MopsInfo,
    result: MopsResult,
}

impl MopsService for ExpectedMops {
    fn Process(&self, tid: i32, info: MopsInfo) -> Result<MopsResult, AdvancedServiceError> {
        assert_eq!(tid, 77);
        assert_eq!(info, self.expected);
        Ok(self.result)
    }
}

#[derive(Clone, Copy)]
struct FailingMopsService;

impl MopsService for FailingMopsService {
    fn Process(&self, _tid: i32, _info: MopsInfo) -> Result<MopsResult, AdvancedServiceError> {
        Err(AdvancedServiceError::Service("mops boom".to_owned()))
    }
}

#[derive(Debug, Deserialize)]
struct InstructionFixture {
    cases: Vec<InstructionCase>,
}

#[derive(Debug, Deserialize)]
struct InstructionCase {
    name: String,
    pc: u64,
    word: String,
    #[serde(default)]
    before_x: BTreeMap<usize, u64>,
    #[serde(default)]
    before_v: BTreeMap<usize, String>,
    #[serde(default)]
    before_nzcv: u32,
    #[serde(default)]
    before_sp: u64,
    #[serde(default)]
    before_fpcr: u32,
    #[serde(default)]
    before_fpsr: u32,
    #[serde(default)]
    memory: Vec<MemoryBytes>,
    #[serde(default)]
    after_x: BTreeMap<usize, u64>,
    #[serde(default)]
    after_v: BTreeMap<usize, String>,
    after_pc: u64,
    #[serde(default)]
    after_nzcv: u32,
    #[serde(default)]
    after_sp: Option<u64>,
    #[serde(default)]
    after_fpcr: Option<u32>,
    #[serde(default)]
    after_fpsr: Option<u32>,
    #[serde(default)]
    writes: Vec<ExpectedWrite>,
    outcome: String,
    #[serde(default)]
    error_contains: String,
    #[serde(default)]
    pauth_result: u64,
}

#[derive(Debug, Deserialize)]
struct MemoryBytes {
    address: u64,
    bytes: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedWrite {
    address: u64,
    bytes: String,
}

fn HexBytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex must be valid")
}

fn HalfBytes(values: &[u16]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    for (index, value) in values.iter().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn InstructionFixtureMatchesRegistersFlagsPcAndWrites() {
    let fixture: InstructionFixture =
        serde_json::from_slice(include_bytes!("../fixtures/monarch/instructions-v1.json"))
            .expect("instruction fixture must parse");

    for case in fixture.cases {
        let mut cpu = CpuState {
            pc: case.pc,
            nzcv: case.before_nzcv,
            sp: case.before_sp,
            fpcr: case.before_fpcr,
            fpsr: case.before_fpsr,
            ..Default::default()
        };
        for (register, value) in &case.before_x {
            cpu.SetX(*register, *value).expect("valid fixture register");
        }
        for (register, value) in &case.before_v {
            cpu.SetV(*register, &HexBytes(value))
                .expect("valid fixture vector register");
        }

        let mut memory = GuestMemory::New(FixtureTarget, 1);
        let word = u32::from_str_radix(case.word.trim_start_matches("0x"), 16)
            .expect("fixture instruction word");
        memory.MapBytes(case.pc, &word.to_le_bytes()).unwrap();
        for region in &case.memory {
            memory
                .MapBytes(region.address, &HexBytes(&region.bytes))
                .unwrap();
        }

        let mut executor = Executor::New(
            cpu,
            memory,
            FixturePAuth {
                result: case.pauth_result,
            },
            42,
        )
        .expect("construct fixture executor");
        if case.outcome == "unsupported" {
            let error = executor.Step().unwrap_err().to_string();
            assert!(
                error.contains(&case.error_contains),
                "{} error: {error}",
                case.name
            );
            assert_eq!(executor.Cpu().pc, case.pc, "{} rejected pc", case.name);
            assert!(
                executor.Memory().Writes().is_empty(),
                "{} rejected writes",
                case.name
            );
            continue;
        }
        let outcome = executor
            .Step()
            .unwrap_or_else(|error| panic!("{} failed unexpectedly: {error}", case.name));
        assert_eq!(outcome.Name(), case.outcome, "{} outcome", case.name);
        assert_eq!(executor.Cpu().pc, case.after_pc, "{} pc", case.name);
        assert_eq!(executor.Cpu().nzcv, case.after_nzcv, "{} nzcv", case.name);
        if let Some(sp) = case.after_sp {
            assert_eq!(executor.Cpu().sp, sp, "{} sp", case.name);
        }
        if let Some(fpcr) = case.after_fpcr {
            assert_eq!(executor.Cpu().fpcr, fpcr, "{} fpcr", case.name);
        }
        if let Some(fpsr) = case.after_fpsr {
            assert_eq!(executor.Cpu().fpsr, fpsr, "{} fpsr", case.name);
        }
        for (register, value) in &case.after_x {
            assert_eq!(
                executor.Cpu().X(*register).unwrap(),
                *value,
                "{} x{}",
                case.name,
                register
            );
        }
        for (register, value) in &case.after_v {
            assert_eq!(
                executor.Cpu().V(*register).unwrap(),
                HexBytes(value).as_slice(),
                "{} v{}",
                case.name,
                register
            );
        }
        let actual_writes = executor.Memory().Writes();
        assert_eq!(
            actual_writes.len(),
            case.writes.len(),
            "{} writes",
            case.name
        );
        for (actual, expected) in actual_writes.iter().zip(&case.writes) {
            assert_eq!(
                actual.address, expected.address,
                "{} write address",
                case.name
            );
            assert_eq!(
                actual.bytes,
                HexBytes(&expected.bytes),
                "{} write bytes",
                case.name
            );
            assert_eq!(actual.pc, case.pc, "{} write pc", case.name);
        }
    }
}

#[test]
fn PacgaUsesRnAndRmAndWritesRd() {
    #[derive(Clone)]
    struct CheckingPAuth;

    impl PAuthService for CheckingPAuth {
        fn Process(
            &self,
            tid: i32,
            operation: PAuthOperation,
            value: u64,
            modifier: u64,
        ) -> Result<PAuthResult, ServiceError> {
            assert_eq!(tid, 77);
            assert_eq!(operation, PAuthOperation::Pacga);
            assert_eq!(value, 0x1020_3040_5060_7080);
            assert_eq!(modifier, 0x8877_6655_4433_2211);
            Ok(PAuthResult {
                value: 0xA5A5_A5A5_0000_0000,
                ioctl_result: 0,
            })
        }
    }

    let mut cpu = CpuState {
        pc: 0x1000,
        ..Default::default()
    };
    cpu.SetX(1, 0xDEAD_BEEF).unwrap();
    cpu.SetX(2, 0x1020_3040_5060_7080).unwrap();
    cpu.SetX(3, 0x8877_6655_4433_2211).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0x1000, &0x9AC3_3041_u32.to_le_bytes())
        .unwrap();
    let mut executor = Executor::New(cpu, memory, CheckingPAuth, 77).unwrap();

    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0xA5A5_A5A5_0000_0000);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0x1020_3040_5060_7080);
    assert_eq!(executor.Cpu().X(3).unwrap(), 0x8877_6655_4433_2211);
}

#[test]
fn RegisterPauthOpcodesUseTheExpectedOperationAndOperands() {
    #[derive(Clone)]
    struct ExpectedPAuth {
        operation: PAuthOperation,
        value: u64,
        modifier: u64,
    }

    impl PAuthService for ExpectedPAuth {
        fn Process(
            &self,
            _tid: i32,
            operation: PAuthOperation,
            value: u64,
            modifier: u64,
        ) -> Result<PAuthResult, ServiceError> {
            assert_eq!(operation, self.operation);
            assert_eq!(value, self.value);
            assert_eq!(modifier, self.modifier);
            Ok(PAuthResult {
                value: 0xA5A5_A5A5_0000_0000,
                ioctl_result: 0,
            })
        }
    }

    let pointer = 0x1020_3040_5060_7080;
    let modifier = 0x8877_6655_4433_2211;
    let cases: [(u32, PAuthOperation, u64, u64); 11] = [
        (0x9AC3_3041, PAuthOperation::Pacga, pointer, modifier),
        (0xDAC1_0041, PAuthOperation::Pacia, pointer, modifier),
        (0xDAC1_0441, PAuthOperation::Pacib, pointer, modifier),
        (0xDAC1_0841, PAuthOperation::Pacda, pointer, modifier),
        (0xDAC1_0C41, PAuthOperation::Pacdb, pointer, modifier),
        (0xDAC1_1041, PAuthOperation::Autia, pointer, modifier),
        (0xDAC1_1441, PAuthOperation::Autib, pointer, modifier),
        (0xDAC1_1841, PAuthOperation::Autda, pointer, modifier),
        (0xDAC1_1C41, PAuthOperation::Autdb, pointer, modifier),
        (0xDAC1_43E1, PAuthOperation::Xpaci, pointer, 0),
        (0xDAC1_47E1, PAuthOperation::Xpacd, pointer, 0),
    ];

    for (word, operation, value, expected_modifier) in cases {
        let mut cpu = CpuState {
            pc: 0x3000,
            ..Default::default()
        };
        cpu.SetX(1, pointer).unwrap();
        cpu.SetX(
            2,
            if operation == PAuthOperation::Pacga {
                pointer
            } else {
                modifier
            },
        )
        .unwrap();
        cpu.SetX(3, modifier).unwrap();
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(0x3000, &word.to_le_bytes()).unwrap();
        let service = ExpectedPAuth {
            operation,
            value,
            modifier: expected_modifier,
        };
        let mut executor = Executor::New(cpu, memory, service, 1).unwrap();

        executor.Step().unwrap();
        assert_eq!(executor.Cpu().X(1).unwrap(), 0xA5A5_A5A5_0000_0000);
    }
}

#[test]
fn UnsupportedInstructionIsAnExplicitError() {
    let cpu = CpuState {
        pc: 0x4000,
        ..Default::default()
    };
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory.MapBytes(0x4000, &[0, 0, 0, 0]).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    let error = executor.Step().unwrap_err();
    let text = error.to_string();
    assert!(text.contains("0x00000000"), "{text}");
    assert!(text.contains("0x4000"), "{text}");
    assert_eq!(executor.Cpu().pc, 0x4000);
}

#[test]
fn ExclusiveMonitorAllowsOneMatchingStore() {
    let mut cpu = CpuState {
        pc: 0x5000,
        ..Default::default()
    };
    cpu.SetX(0, 0x6000).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0x5000, &0xC85F_7C01_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0x5004, &0xC802_7C01_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0x5008, &0xC803_7C01_u32.to_le_bytes())
        .unwrap();
    memory.MapBytes(0x6000, &41_u64.to_le_bytes()).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(1).unwrap(), 41);
    executor.CpuMut().SetX(1, 42).unwrap();
    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    assert_eq!(
        executor.MemoryMut().ReadVec(0x6000, 8).unwrap(),
        42_u64.to_le_bytes()
    );
    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(3).unwrap(), 1);
}

#[test]
fn ArchitecturalNzcvSystemRegisterDoesNotNeedAServiceCallback() {
    let cpu = CpuState {
        pc: 0x7000,
        nzcv: 0x6000_0000,
        ..Default::default()
    };
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0x7000, &0xD53B_4202_u32.to_le_bytes())
        .unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0x6000_0000);
}

#[test]
fn ArchitecturalMsrWritesNzcvFromItsOnlyGeneralRegister() {
    let mut cpu = CpuState {
        pc: 0x7100,
        ..Default::default()
    };
    cpu.SetX(1, 0xA000_0000).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0x7100, &0xD51B_4201_u32.to_le_bytes())
        .unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().nzcv, 0xA000_0000);
}

#[test]
fn ClrexClearsExclusiveReservation() {
    let mut cpu = CpuState {
        pc: 0x8000,
        ..Default::default()
    };
    cpu.SetX(0, 0x9000).unwrap();
    cpu.SetX(1, 99).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0x8000, &0xC85F_7C01_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0x8004, &0xD503_3F5F_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0x8008, &0xC802_7C01_u32.to_le_bytes())
        .unwrap();
    memory.MapBytes(0x9000, &41_u64.to_le_bytes()).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    executor.Step().unwrap();
    executor.CpuMut().SetX(1, 99).unwrap();
    executor.Step().unwrap();
    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(2).unwrap(), 1);
    assert_eq!(
        executor.MemoryMut().ReadVec(0x9000, 8).unwrap(),
        41_u64.to_le_bytes()
    );
}

#[test]
fn AddsWRegisterSetsCarryAt32BitBoundary() {
    let mut cpu = CpuState {
        pc: 0xA000,
        ..Default::default()
    };
    cpu.SetX(0, u64::from(u32::MAX)).unwrap();
    cpu.SetX(1, 1).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0xA000, &0x2B01_0002_u32.to_le_bytes())
        .unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    assert_eq!(executor.Cpu().nzcv, 0x6000_0000);
}

#[test]
fn ExclusivePairLoadsAndStoresBothWords() {
    let mut cpu = CpuState {
        pc: 0xB000,
        ..Default::default()
    };
    cpu.SetX(0, 0xC000).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0xB000, &0xC87F_0801_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0xB004, &0xC823_1404_u32.to_le_bytes())
        .unwrap(); // stxp w3, x4, x5, [x0]
    memory.MapBytes(0xC000, &[0; 16]).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    executor.CpuMut().SetX(4, 11).unwrap();
    executor.CpuMut().SetX(5, 22).unwrap();
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(3).unwrap(), 0);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xC000, 16).unwrap(),
        [11_u64.to_le_bytes(), 22_u64.to_le_bytes()].concat()
    );
}

#[test]
fn AcquireReleaseExclusivePairMismatchClearsTheMonitor() {
    let mut cpu = CpuState {
        pc: 0xB100,
        ..Default::default()
    };
    cpu.SetX(0, 0xC000).unwrap();
    cpu.SetX(6, 0xC010).unwrap();
    cpu.SetX(4, 11).unwrap();
    cpu.SetX(5, 22).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0xB100, &0xC87F_8801_u32.to_le_bytes())
        .unwrap(); // ldaxp x1, x2, [x0]
    memory
        .MapBytes(0xB104, &0xC823_94C4_u32.to_le_bytes())
        .unwrap(); // stlxp w3, x4, x5, [x6]
    memory
        .MapBytes(0xB108, &0xC827_9404_u32.to_le_bytes())
        .unwrap(); // stlxp w7, x4, x5, [x0]
    memory.MapBytes(0xC000, &[0; 32]).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    executor.Step().unwrap();
    executor.Step().unwrap();
    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(3).unwrap(), 1);
    assert_eq!(executor.Cpu().X(7).unwrap(), 1);
    assert!(executor.Memory().Writes().is_empty());
}

#[test]
fn FaultingExclusivePairLoadClearsAnOlderReservation() {
    let mut cpu = CpuState {
        pc: 0xB200,
        ..Default::default()
    };
    cpu.SetX(0, 0xC000).unwrap();
    cpu.SetX(6, 0xD000).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0xB200, &0xC85F_7C01_u32.to_le_bytes())
        .unwrap(); // ldxr x1, [x0]
    memory
        .MapBytes(0xB204, &0xC87F_0CC2_u32.to_le_bytes())
        .unwrap(); // ldxp x2, x3, [x6]
    memory
        .MapBytes(0xB208, &0xC804_7C01_u32.to_le_bytes())
        .unwrap(); // stxr w4, x1, [x0]
    memory.MapBytes(0xC000, &7_u64.to_le_bytes()).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();

    executor.Step().unwrap();
    assert!(matches!(executor.Step(), Err(ExecutionError::Memory(_))));
    executor.CpuMut().pc = 0xB208;
    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(4).unwrap(), 1);
    assert!(executor.Memory().Writes().is_empty());
}

fn RunWord(
    word: u32,
    cpu: CpuState,
    memory_regions: &[(u64, &[u8])],
) -> Executor<FixtureTarget, FixturePAuth> {
    let pc = cpu.pc;
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory.MapBytes(pc, &word.to_le_bytes()).unwrap();
    for (address, bytes) in memory_regions {
        memory.MapBytes(*address, bytes).unwrap();
    }
    Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap()
}

#[test]
fn QRegisterLoadStoreAndPairUseAllSixteenBytes() {
    let mut cpu = CpuState {
        pc: 0xC000,
        ..Default::default()
    };
    cpu.SetX(9, 0xD000).unwrap();
    let input = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let mut executor = RunWord(0x3DC10920, cpu, &[(0xD420, &input)]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().V(0).unwrap(), &input);

    let mut cpu = CpuState {
        pc: 0xC100,
        sp: 0xD000,
        ..Default::default()
    };
    cpu.SetV(0, &input).unwrap();
    let zero_q = [0; 16];
    let mut executor = RunWord(0x3D8007E0, cpu, &[(0xD010, &zero_q)]);
    executor.Step().unwrap();
    assert_eq!(executor.MemoryMut().ReadVec(0xD010, 16).unwrap(), input);

    let first = [0x10; 16];
    let second = [0x20; 16];
    let mut cpu = CpuState {
        pc: 0xC200,
        ..Default::default()
    };
    cpu.SetX(10, 0xD000).unwrap();
    let mut executor = RunWord(0xAD400540, cpu, &[(0xD000, &first), (0xD010, &second)]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().V(0).unwrap(), &first);
    assert_eq!(executor.Cpu().V(1).unwrap(), &second);

    let mut cpu = CpuState {
        pc: 0xC300,
        ..Default::default()
    };
    cpu.SetX(9, 0xD000).unwrap();
    cpu.SetV(0, &first).unwrap();
    cpu.SetV(1, &second).unwrap();
    let zero_pair = [0; 32];
    let mut executor = RunWord(0xAD000520, cpu, &[(0xD000, &zero_pair)]);
    executor.Step().unwrap();
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD000, 32).unwrap(),
        [first, second].concat()
    );
}

#[test]
fn PostIndexUsesOldBaseForAccessThenWritesBack() {
    let cpu = CpuState {
        pc: 0xC400,
        sp: 0xD000,
        ..Default::default()
    };
    let value = 0x1122_3344_5566_7788_u64.to_le_bytes();
    let mut executor = RunWord(0xF84107FD, cpu, &[(0xD000, &value)]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(29).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(executor.Cpu().sp, 0xD010);
}

#[test]
fn RegisterExtendShiftSupportsLsrAndAsrAtOperandWidth() {
    let mut cpu = CpuState {
        pc: 0xC500,
        ..Default::default()
    };
    cpu.SetX(12, u64::from(u32::MAX)).unwrap();
    cpu.SetX(9, 0x0002_0000).unwrap();
    let mut executor = RunWord(0x0A69458B, cpu, &[]); // bic w11, w12, w9, lsr #17
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(11).unwrap(), 0xFFFF_FFFE);

    let mut cpu = CpuState {
        pc: 0xC504,
        ..Default::default()
    };
    cpu.SetX(9, 1).unwrap();
    cpu.SetX(10, 0xFFFF_FFFE).unwrap();
    let mut executor = RunWord(0x0B8A0528, cpu, &[]); // add w8, w9, w10, asr #1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), 0);

    let mut cpu = CpuState {
        pc: 0xC508,
        ..Default::default()
    };
    cpu.SetX(1, 0).unwrap();
    cpu.SetX(2, 0x0123_4567_89AB_CDEF).unwrap();
    let mut executor = RunWord(0xAAC2_2020, cpu, &[]); // orr x0, x1, x2, ror #8
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 0xEF01_2345_6789_ABCD);
}

#[test]
fn LongMultiplySignExtendsWOperands() {
    let mut cpu = CpuState {
        pc: 0xC600,
        ..Default::default()
    };
    cpu.SetX(8, u64::from(u32::MAX)).unwrap();
    cpu.SetX(11, 2).unwrap();
    let mut executor = RunWord(0x9B2B7D08, cpu, &[]); // smaddl x8, w8, w11, xzr（原始指令由测试解码结果替换）
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), u64::MAX - 1);
}

#[test]
fn ConditionalCompareUsesOperandWidthAndCcmnAdds() {
    let mut cpu = CpuState {
        pc: 0xC680,
        nzcv: 0x4000_0000,
        ..Default::default()
    };
    cpu.SetX(8, 0x8000_0000).unwrap();
    let mut executor = RunWord(0x7A400904, cpu, &[]); // ccmp w8, #0, #4, eq
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().nzcv, 0xA000_0000);

    let mut cpu = CpuState {
        pc: 0xC684,
        nzcv: 0x2000_0000,
        ..Default::default()
    };
    cpu.SetX(8, 0xFFFF_FFFF).unwrap();
    cpu.SetX(11, 1).unwrap();
    let mut executor = RunWord(0x3A4B8100, cpu, &[]); // ccmn w8, w11, #0, hi
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().nzcv, 0x6000_0000);
}

#[test]
fn BitfieldAliasesAndSxtwExecuteWithArchitecturalSemantics() {
    let mut cpu = CpuState {
        pc: 0xC700,
        ..Default::default()
    };
    cpu.SetX(0, 0xFFFF_FFFF).unwrap();
    let mut executor = RunWord(0x93407C01, cpu, &[]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), u64::MAX);

    let mut cpu = CpuState {
        pc: 0xC800,
        ..Default::default()
    };
    cpu.SetX(8, 0x1234_5678).unwrap();
    let mut executor = RunWord(0xD37C6D09, cpu, &[]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(9).unwrap(), 0x2345_6780);

    let mut cpu = CpuState {
        pc: 0xC804,
        ..Default::default()
    };
    cpu.SetX(8, 0x1234_5678_9ABC_DEF0).unwrap();
    let mut executor = RunWord(0xD35CED08, cpu, &[]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), 0x2345_6789);

    let mut cpu = CpuState {
        pc: 0xC808,
        ..Default::default()
    };
    cpu.SetX(10, 0xAABB_CCDD_EEFF_0011).unwrap();
    cpu.SetX(11, 0x1111_1111_2222_2222).unwrap();
    let mut executor = RunWord(0xB3607D4B, cpu, &[]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(11).unwrap(), 0xEEFF_0011_2222_2222);
}

#[test]
fn FmsubUsesFusedMultiplySubtract() {
    let left = f64::from_bits(0x3FF0_0000_0000_0001);
    let accumulator = f64::from_bits(0x3FF0_0000_0000_0002);
    let mut cpu = CpuState {
        pc: 0xC900,
        ..Default::default()
    };
    cpu.SetV(0, &left.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(1, &left.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(2, &left.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(3, &accumulator.to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1F428C20, cpu, &[]);
    executor.Step().unwrap();
    let expected = (-left).mul_add(left, accumulator).to_bits();
    assert_eq!(executor.Cpu().V(0).unwrap()[..8], expected.to_le_bytes());
}

#[test]
fn BitfieldAliasFamiliesMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCE20,
        ..Default::default()
    };
    cpu.SetX(2, 0x10).unwrap();
    let mut executor = RunWord(0x9343_1041, cpu, &[]); // sbfx x1, x2, #3, #2
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), u64::MAX - 1);

    let mut cpu = CpuState {
        pc: 0xCE24,
        ..Default::default()
    };
    cpu.SetX(5, 0xFEDC_BA98_7654_3210).unwrap();
    cpu.SetX(6, 0x8877_6655_4433_2211).unwrap();
    let mut executor = RunWord(0xB34C_FCC5, cpu, &[]); // bfxil x5, x6, #12, #52
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(5).unwrap(), 0xFED8_8776_6554_4332);

    let mut cpu = CpuState {
        pc: 0xCE28,
        ..Default::default()
    };
    cpu.SetX(4, 0xFF).unwrap();
    let mut executor = RunWord(0xB37F_17E4, cpu, &[]); // bfc x4, #1, #6
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(4).unwrap(), 0x81);
}

#[test]
fn CurrentDumpVectorAliasesUseLaneAndFullVectorSemantics() {
    let mut cpu = CpuState {
        pc: 0xCA00,
        ..Default::default()
    };
    cpu.SetX(8, 0xAABB_CCDD_EEFF_0011).unwrap();
    cpu.SetV(0, &hex::decode("88776655443322110000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4E181D00, cpu, &[]); // mov v0.d[1], x8
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        hex::decode("88776655443322111100ffeeddccbbaa")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCA04,
        ..Default::default()
    };
    cpu.SetV(0, &hex::decode("88776655443322111100ffeeddccbbaa").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4E183C09, cpu, &[]); // mov x9, v0.d[1]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(9).unwrap(), 0xAABB_CCDD_EEFF_0011);

    let mut cpu = CpuState {
        pc: 0xCA08,
        ..Default::default()
    };
    cpu.SetV(0, &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
        .unwrap();
    let mut executor = RunWord(0x6E205800, cpu, &[]); // mvn v0.16b, v0.16b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCA0C,
        ..Default::default()
    };
    cpu.SetV(0, &hex::decode("01000000020000000300000004000000").unwrap())
        .unwrap();
    cpu.SetV(1, &hex::decode("05000000060000000700000008000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x6EA08420, cpu, &[]); // sub v0.4s, v1.4s, v0.4s
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        hex::decode("04000000040000000400000004000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCA10,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("ff00ff00ff00ff00ff00ff00ff00ff00").unwrap())
        .unwrap();
    cpu.SetV(2, &hex::decode("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4E221C22, cpu, &[]); // and v2.16b, v1.16b, v2.16b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(2).unwrap(),
        hex::decode("0f000f000f000f000f000f000f000f00")
            .unwrap()
            .as_slice()
    );
}

#[test]
fn Ld1PairPostIndexLoadsTwoFullVectorsAndWritesBack() {
    let bytes: Vec<u8> = (0_u8..32).collect();
    let mut cpu = CpuState {
        pc: 0xCE2C,
        ..Default::default()
    };
    cpu.SetX(1, 0xD020).unwrap();
    let mut executor = RunWord(0x4CDF_A020, cpu, &[(0xD020, &bytes)]); // ld1 {v0.16b, v1.16b}, [x1], #32
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().V(0).unwrap().as_slice(), &bytes[..16]);
    assert_eq!(executor.Cpu().V(1).unwrap().as_slice(), &bytes[16..]);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0xD040);
}

#[test]
fn Ld1LaneLoadUpdatesOnlySelectedLane() {
    let mut cpu = CpuState {
        pc: 0xCE30,
        ..Default::default()
    };
    cpu.SetX(3, 0xD060).unwrap();
    cpu.SetV(4, &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4D40_8064, cpu, &[(0xD060, &[0x44, 0x33, 0x22, 0x11])]); // ld1 {v4.s}[2], [x3]
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(4).unwrap().as_slice(),
        hex::decode("0001020304050607443322110c0d0e0f")
            .unwrap()
            .as_slice()
    );
    assert_eq!(executor.Cpu().X(3).unwrap(), 0xD060);
}

#[test]
fn VectorBitwiseSelectFamiliesMatchMonarchCReference() {
    for (word, expected) in [
        (0x2EA1_1C40_u32, "a3a3a3a3a3a3a3a30000000000000000"),
        (0x2EE1_1C40, "3a3a3a3a3a3a3a3a0000000000000000"),
        (0x2E61_1C40, "27272727272727270000000000000000"),
    ] {
        let mut cpu = CpuState {
            pc: 0xCAA0,
            ..Default::default()
        };
        cpu.SetV(0, &hex::decode("aaaaaaaaaaaaaaaa0000000000000000").unwrap())
            .unwrap();
        cpu.SetV(1, &hex::decode("0f0f0f0f0f0f0f0f0000000000000000").unwrap())
            .unwrap();
        cpu.SetV(2, &hex::decode("33333333333333330000000000000000").unwrap())
            .unwrap();

        let mut executor = RunWord(word, cpu, &[]);
        executor.Step().unwrap();

        assert_eq!(
            executor.Cpu().V(0).unwrap(),
            hex::decode(expected).unwrap().as_slice()
        );
    }
}

#[test]
fn VectorPermutationShiftAndBitOpsMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCAB0,
        ..Default::default()
    };
    cpu.SetV(3, &hex::decode("30000000310000003200000033000000").unwrap())
        .unwrap();
    cpu.SetV(4, &hex::decode("40000000410000004200000043000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4E84_5862, cpu, &[]); // uzp2 v2.4s, v3.4s, v4.4s
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(2).unwrap(),
        hex::decode("31000000330000004100000043000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCAB4,
        ..Default::default()
    };
    cpu.SetV(
        17,
        &hex::decode("010903070802040605000b0a0c0e0f0d").unwrap(),
    )
    .unwrap();
    cpu.SetV(
        18,
        &hex::decode("1e14121610181c1a020408060a0c0e00").unwrap(),
    )
    .unwrap();
    let mut executor = RunWord(0x6E32_A633, cpu, &[]); // umaxp v19.16b, v17.16b, v18.16b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(19).unwrap(),
        hex::decode("09070806050b0e0f1e16181c04080c0e")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCAB8,
        ..Default::default()
    };
    cpu.SetV(4, &hex::decode("07000000000000000700000000000000").unwrap())
        .unwrap();
    cpu.SetV(7, &hex::decode("0100000000000000ffdebc9a78563412").unwrap())
        .unwrap();
    let mut executor = RunWord(0x6EE7_4486, cpu, &[]); // ushl v6.2d, v4.2d, v7.2d
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(6).unwrap(),
        hex::decode("0e000000000000000300000000000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCABC,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("887766554433221100ffeeddccbbaa99").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4EA1_2821, cpu, &[]); // xtn2 v1.4s, v1.2d
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(1).unwrap(),
        hex::decode("88776655443322118877665500ffeedd")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCAC0,
        ..Default::default()
    };
    cpu.SetV(3, &hex::decode("0f0f0f0f0f0f0f0f0000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x2E20_4862, cpu, &[]); // clz v2.8b, v3.8b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(2).unwrap(),
        hex::decode("04040404040404040000000000000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCAC4,
        ..Default::default()
    };
    cpu.SetV(5, &hex::decode("01010101010101010000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x2E60_58A4, cpu, &[]); // rbit v4.8b, v5.8b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(4).unwrap(),
        hex::decode("80808080808080800000000000000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCAC8,
        ..Default::default()
    };
    cpu.SetV(7, &hex::decode("00010203040506070000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x0E20_18E6, cpu, &[]); // rev16 v6.8b, v7.8b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(6).unwrap(),
        hex::decode("01000302050407060000000000000000")
            .unwrap()
            .as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCACC,
        ..Default::default()
    };
    cpu.SetV(9, &hex::decode("00010203040506070000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x2E20_0928, cpu, &[]); // rev32 v8.8b, v9.8b
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(8).unwrap(),
        hex::decode("03020100070605040000000000000000")
            .unwrap()
            .as_slice()
    );
}

#[test]
fn FloatToIntegerAccumulatesArchitectedFpsrBits() {
    let mut cpu = CpuState {
        pc: 0xCB00,
        ..Default::default()
    };
    cpu.SetV(28, &1.5_f64.to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x9E790388, cpu, &[]); // fcvtzu x8, d28
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), 1);
    assert_eq!(executor.Cpu().fpsr, 0x10);

    let mut cpu = CpuState {
        pc: 0xCB04,
        fpsr: 0x10,
        ..Default::default()
    };
    cpu.SetV(28, &(-1.0_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x9E790388, cpu, &[]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), 0);
    assert_eq!(executor.Cpu().fpsr, 0x11);
}

#[test]
fn NegativeFusedMultiplyAddVariantsMatchOldExecutorAndHalfFusedSubtract() {
    let mut cpu = CpuState {
        pc: 0xCC00,
        ..Default::default()
    };
    cpu.SetV(1, &2.0_f64.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(2, &3.0_f64.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(3, &4.0_f64.to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1F620C20, cpu, &[]); // fnmadd d0, d1, d2, d3
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..8],
        &(-10.0_f64).to_bits().to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCC04,
        ..Default::default()
    };
    cpu.SetV(1, &2.0_f64.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(2, &3.0_f64.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(3, &4.0_f64.to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1F628C20, cpu, &[]); // fnmsub d0, d1, d2, d3
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..8],
        &2.0_f64.to_bits().to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCC08,
        ..Default::default()
    };
    cpu.SetV(1, &0x4000_u16.to_le_bytes()).unwrap(); // 2.0
    cpu.SetV(2, &0x4200_u16.to_le_bytes()).unwrap(); // 3.0
    cpu.SetV(3, &0x4400_u16.to_le_bytes()).unwrap(); // 4.0
    let mut executor = RunWord(0x1FC28C20, cpu, &[]); // fmsub h0, h1, h2, h3
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..2],
        &0xC000_u16.to_le_bytes()
    ); // 4 - (2 * 3)
}

#[test]
fn ScalarConversionsRoundDirectlyAndSaturateAtDestinationWidth() {
    let mut cpu = CpuState {
        pc: 0xCD00,
        ..Default::default()
    };
    cpu.SetX(1, 0x8000_0080_0000_0001).unwrap();
    let mut executor = RunWord(0x9E230020, cpu, &[]); // ucvtf s0, x1
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..4],
        &0x5F00_0001_u32.to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCD04,
        ..Default::default()
    };
    cpu.SetV(0, &(2.0_f64.powi(32)).to_bits().to_le_bytes())
        .unwrap();
    let mut executor = RunWord(0x1E790000, cpu, &[]); // fcvtzu w0, d0
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), u64::from(u32::MAX));
    assert_eq!(executor.Cpu().fpsr, 1);

    let mut cpu = CpuState {
        pc: 0xCD08,
        ..Default::default()
    };
    cpu.SetV(0, &(2.0_f64.powi(31)).to_bits().to_le_bytes())
        .unwrap();
    let mut executor = RunWord(0x1E780000, cpu, &[]); // fcvtzs w0, d0
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x7FFF_FFFF);
    assert_eq!(executor.Cpu().fpsr, 1);
}

#[test]
fn OrdinarySubDoesNotConsumeAConditionalBorrow() {
    let cpu = CpuState {
        pc: 0xCE00,
        sp: 0x20_000,
        ..Default::default()
    };
    let mut executor = RunWord(0xD12F_43E9, cpu, &[]); // sub x9, sp, #0xbd0

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(9).unwrap(), 0x1_F430);
}

#[test]
fn SignedWDivisionInterpretsOperandsAsI32() {
    let mut cpu = CpuState {
        pc: 0xCE04,
        ..Default::default()
    };
    cpu.SetX(0, 0xFFFF_FFF6).unwrap();
    cpu.SetX(1, 3).unwrap();
    let mut executor = RunWord(0x1AC1_0C02, cpu, &[]); // sdiv w2, w0, w1

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(2).unwrap(), 0xFFFF_FFFD);
}

#[test]
fn UnsignedWDivisionUsesOnlyTheLowThirtyTwoBits() {
    let mut cpu = CpuState {
        pc: 0xCE06,
        ..Default::default()
    };
    cpu.SetX(0, 0xAAAA_BBBB_FFFF_FFFF).unwrap();
    cpu.SetX(1, 0xCCCC_DDDD_0000_0002).unwrap();
    let mut executor = RunWord(0x1AC1_0802, cpu, &[]); // udiv w2, w0, w1

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(2).unwrap(), 0x7FFF_FFFF);
}

#[test]
fn WDivisionHandlesZeroDivisorsAndSignedOverflow() {
    let cases: [(u32, u64, u64, u64); 3] = [
        (0x1AC1_0C02, 0x8000_0000, 0xFFFF_FFFF, 0x8000_0000),
        (0x1AC1_0C02, 123, 0, 0),
        (0x1AC1_0802, u64::from(u32::MAX), 0, 0),
    ];

    for (word, numerator, denominator, expected) in cases {
        let mut cpu = CpuState {
            pc: 0xCE06,
            ..Default::default()
        };
        cpu.SetX(0, numerator).unwrap();
        cpu.SetX(1, denominator).unwrap();
        let mut executor = RunWord(word, cpu, &[]);

        executor.Step().unwrap();

        assert_eq!(executor.Cpu().X(2).unwrap(), expected);
    }
}

#[test]
fn OrdinarySubsSetsFlagsWithoutAConditionalBorrow() {
    let mut cpu = CpuState {
        pc: 0xCE07,
        ..Default::default()
    };
    cpu.SetX(1, 5).unwrap();
    cpu.SetX(2, 5).unwrap();
    let mut executor = RunWord(0xEB02_0020, cpu, &[]); // subs x0, x1, x2

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(0).unwrap(), 0);
    assert_eq!(executor.Cpu().nzcv, 0x6000_0000);
}

#[test]
fn SubtractWithCarryUsesAnUntruncatedBorrowChain() {
    let mut cpu = CpuState {
        pc: 0xCE08,
        ..Default::default()
    };
    cpu.SetX(0, 0).unwrap();
    cpu.SetX(1, u64::MAX).unwrap();
    let mut executor = RunWord(0xFA01_0002, cpu, &[]); // sbcs x2, x0, x1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    assert_eq!(executor.Cpu().nzcv, 0x4000_0000);

    let mut cpu = CpuState {
        pc: 0xCE0C,
        nzcv: 0x2000_0000,
        ..Default::default()
    };
    cpu.SetX(0, 0).unwrap();
    cpu.SetX(1, u64::MAX).unwrap();
    let mut executor = RunWord(0xFA01_0002, cpu, &[]); // sbcs x2, x0, x1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), 1);
    assert_eq!(executor.Cpu().nzcv, 0);

    let mut cpu = CpuState {
        pc: 0xCE10,
        ..Default::default()
    };
    cpu.SetX(0, 0).unwrap();
    cpu.SetX(1, u64::from(u32::MAX)).unwrap();
    let mut executor = RunWord(0x7A01_0002, cpu, &[]); // sbcs w2, w0, w1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    assert_eq!(executor.Cpu().nzcv, 0x4000_0000);

    let mut cpu = CpuState {
        pc: 0xCE14,
        nzcv: 0x9000_0000,
        ..Default::default()
    };
    cpu.SetX(0, 0).unwrap();
    cpu.SetX(1, u64::MAX).unwrap();
    let mut executor = RunWord(0xDA01_0002, cpu, &[]); // sbc x2, x0, x1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), 0);
    assert_eq!(executor.Cpu().nzcv, 0x9000_0000);
}

#[test]
fn VectorFcvtzuSaturatesEachThirtyTwoBitLane() {
    let mut cpu = CpuState {
        pc: 0xCE08,
        ..Default::default()
    };
    cpu.SetV(0, &hex::decode("0000804f000080bf00002b420000c07f").unwrap())
        .unwrap();
    let mut executor = RunWord(0x6EA1_B800, cpu, &[]); // fcvtzu v0.4s, v0.4s

    executor.Step().unwrap();

    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        hex::decode("ffffffff000000002a00000000000000")
            .unwrap()
            .as_slice()
    );
    assert_eq!(executor.Cpu().fpsr, 0x11);
}

#[test]
fn VectorFcvtzsSaturatesEachThirtyTwoBitLane() {
    let mut cpu = CpuState {
        pc: 0xCE0C,
        ..Default::default()
    };
    cpu.SetV(0, &hex::decode("0000004f000000cf00002b420000c07f").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4EA1_B800, cpu, &[]); // fcvtzs v0.4s, v0.4s

    executor.Step().unwrap();

    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        hex::decode("ffffff7f000000802a00000000000000")
            .unwrap()
            .as_slice()
    );
    assert_eq!(executor.Cpu().fpsr, 0x11);
}

#[test]
fn ScaledVectorFcvtzFormsApplyImmediateScalePerLane() {
    let mut cpu = CpuState {
        pc: 0xCE0E,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("0000c03f0000c0bf0000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x0F3F_FC20, cpu, &[]); // fcvtzs v0.2s, v1.2s, #1
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..8],
        &hex::decode("03000000fdffffff").unwrap()
    );

    let mut cpu = CpuState {
        pc: 0xCE12,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("0000c03f0000803e0000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x2F3F_FC20, cpu, &[]); // fcvtzu v0.2s, v1.2s, #1
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..8],
        &hex::decode("0300000000000000").unwrap()
    );
    assert_eq!(executor.Cpu().fpsr, 0x10);
}

#[test]
fn ScaledVectorFcvtzSupportsHalfLanesAndMaximumScale() {
    let mut cpu = CpuState {
        pc: 0xCE18,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("003e00be003400b00000000000000000").unwrap())
        .unwrap();
    let mut executor = RunWord(0x0F1D_FC20, cpu, &[]); // fcvtzs v0.4h, v1.4h, #3
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(0).unwrap()[..8],
        &hex::decode("0c00f4ff0200ffff").unwrap()
    );

    let mut cpu = CpuState {
        pc: 0xCE1C,
        ..Default::default()
    };
    cpu.SetV(1, &hex::decode("000000000000e03f000000000000e0bf").unwrap())
        .unwrap();
    let mut executor = RunWord(0x4F40_FC20, cpu, &[]); // fcvtzs v0.2d, v1.2d, #64
    executor.Step().unwrap();
    assert_eq!(
        executor.Cpu().V(0).unwrap(),
        &hex::decode("ffffffffffffff7f0000000000000080")
            .unwrap()
            .as_slice()
    );
    assert_eq!(executor.Cpu().fpsr, 1);
}

#[test]
fn CasComparesAndConditionallyStoresWithAcquireReleaseAliases() {
    let mut cpu = CpuState {
        pc: 0xCE20,
        ..Default::default()
    };
    cpu.SetX(1, 7).unwrap();
    cpu.SetX(2, 9).unwrap();
    cpu.SetX(3, 0xD000).unwrap();
    let mut executor = RunWord(0xC8A1_7C62, cpu, &[(0xD000, &7_u64.to_le_bytes())]); // cas x1, x2, [x3]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), 7);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD000, 8).unwrap(),
        9_u64.to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCE24,
        ..Default::default()
    };
    cpu.SetX(1, 8).unwrap();
    cpu.SetX(2, 9).unwrap();
    cpu.SetX(3, 0xD000).unwrap();
    let mut executor = RunWord(0xC8A1_7C62, cpu, &[(0xD000, &7_u64.to_le_bytes())]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), 7);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD000, 8).unwrap(),
        7_u64.to_le_bytes()
    );
}

#[test]
fn CasAcquireReleaseVariantsAndCaspShareCompareExchangeSemantics() {
    for word in [0xC8A1_7C62, 0xC8E1_7C62, 0xC8A1_FC62, 0xC8E1_FC62] {
        let mut cpu = CpuState {
            pc: 0xCE28,
            ..Default::default()
        };
        cpu.SetX(1, 7).unwrap();
        cpu.SetX(2, 9).unwrap();
        cpu.SetX(3, 0xD000).unwrap();
        let mut executor = RunWord(word, cpu, &[(0xD000, &7_u64.to_le_bytes())]);
        executor.Step().unwrap();
        assert_eq!(
            executor.MemoryMut().ReadVec(0xD000, 8).unwrap(),
            9_u64.to_le_bytes()
        );
    }

    let old = [7_u64.to_le_bytes(), 8_u64.to_le_bytes()].concat();
    let mut cpu = CpuState {
        pc: 0xCE2C,
        ..Default::default()
    };
    cpu.SetX(0, 7).unwrap();
    cpu.SetX(1, 8).unwrap();
    cpu.SetX(2, 9).unwrap();
    cpu.SetX(3, 10).unwrap();
    cpu.SetX(4, 0xD000).unwrap();
    let mut executor = RunWord(0x4820_7C82, cpu, &[(0xD000, &old)]); // casp x0, x1, x2, x3, [x4]
    executor.Step().unwrap();
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD000, 16).unwrap(),
        [9_u64.to_le_bytes(), 10_u64.to_le_bytes()].concat()
    );

    let mut cpu = CpuState {
        pc: 0xCE30,
        ..Default::default()
    };
    cpu.SetX(0, 7).unwrap();
    cpu.SetX(1, 99).unwrap();
    cpu.SetX(2, 9).unwrap();
    cpu.SetX(3, 10).unwrap();
    cpu.SetX(4, 0xD000).unwrap();
    let mut executor = RunWord(0x4820_7C82, cpu, &[(0xD000, &old)]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 7);
    assert_eq!(executor.Cpu().X(1).unwrap(), 8);
    assert!(executor.Memory().Writes().is_empty());
}

#[test]
fn SuccessfulCasInvalidatesAnOverlappingExclusiveReservation() {
    let mut cpu = CpuState {
        pc: 0xCE40,
        ..Default::default()
    };
    cpu.SetX(0, 0xD000).unwrap();
    cpu.SetX(3, 7).unwrap();
    cpu.SetX(4, 8).unwrap();
    cpu.SetX(2, 99).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(0xCE40, &0xC85F_7C01_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0xCE44, &0xC8A3_7C04_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0xCE48, &0xC805_7C02_u32.to_le_bytes())
        .unwrap();
    memory.MapBytes(0xD000, &7_u64.to_le_bytes()).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth::default(), 1).unwrap();
    executor.Step().unwrap();
    executor.Step().unwrap();
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(5).unwrap(), 1);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD000, 8).unwrap(),
        8_u64.to_le_bytes()
    );
}

#[test]
fn MtePointerArithmeticMatchesMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCE48,
        ..Default::default()
    };
    cpu.SetX(1, 0x0A00_0000_0000_1000).unwrap();
    let mut executor = RunWord(0x9181_0C20, cpu, &[]); // addg x0, x1, #0x10, #3
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x0D00_0000_0000_1010);

    let mut cpu = CpuState {
        pc: 0xCE4C,
        ..Default::default()
    };
    cpu.SetX(3, 0x0700_0000_0000_2040).unwrap();
    let mut executor = RunWord(0xD182_1462, cpu, &[]); // subg x2, x3, #0x20, #5
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), 0x0200_0000_0000_2020);

    let mut cpu = CpuState {
        pc: 0xCE50,
        ..Default::default()
    };
    cpu.SetX(5, 0x0C00_0000_0000_0000).unwrap();
    cpu.SetX(6, 0x0123_4000_0000_0001).unwrap();
    let mut executor = RunWord(0x9AC6_14A4, cpu, &[]); // gmi x4, x5, x6
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(4).unwrap(), 0x0123_4000_0000_1001);

    let mut cpu = CpuState {
        pc: 0xCE54,
        ..Default::default()
    };
    cpu.SetX(8, 0x0F00_0000_0000_4000).unwrap();
    cpu.SetX(9, 0x0000_0000_0000_FFFD).unwrap();
    let mut executor = RunWord(0x9AC9_1107, cpu, &[]); // irg x7, x8, x9
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(7).unwrap(), 0x0100_0000_0000_4000);

    let mut cpu = CpuState {
        pc: 0xCE58,
        ..Default::default()
    };
    cpu.SetX(11, 0x00FF_FFFF_FFFF_FF10).unwrap();
    cpu.SetX(12, 0x0000_0000_0000_0020).unwrap();
    let mut executor = RunWord(0x9ACC_016A, cpu, &[]); // subp x10, x11, x12
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(10).unwrap(), 0xFFFF_FFFF_FFFF_FEF0);
    assert_eq!(executor.Cpu().nzcv, 0);

    let mut cpu = CpuState {
        pc: 0xCE5C,
        ..Default::default()
    };
    cpu.SetX(14, 0x10).unwrap();
    cpu.SetX(15, 0x20).unwrap();
    let mut executor = RunWord(0xBACF_01CD, cpu, &[]); // subps x13, x14, x15
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(13).unwrap(), u64::MAX - 0xF);
    assert_eq!(executor.Cpu().nzcv, 0x8000_0000);
}

#[test]
fn AuthenticatedLoadsUseDataKeysAndWriteback() {
    let mut cpu = CpuState {
        pc: 0xCE60,
        ..Default::default()
    };
    cpu.SetX(17, 0xD100).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xF820_0630_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0xD100, &0x1122_3344_5566_7788_u64.to_le_bytes())
        .unwrap();
    let service = ExpectedPAuthCall {
        operation: PAuthOperation::Autda,
        value: 0x1122_3344_5566_7788,
        modifier: 0xD100,
        result: 0x8877_6655_4433_2211,
    };
    let mut executor = Executor::New(cpu, memory, service, 1).unwrap();
    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Cpu().X(16).unwrap(), 0x8877_6655_4433_2211);
    assert_eq!(executor.Cpu().X(17).unwrap(), 0xD100);
    assert_eq!(executor.Cpu().pc, 0xCE64);

    let mut cpu = CpuState {
        pc: 0xCE64,
        ..Default::default()
    };
    cpu.SetX(19, 0xD208).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xF8FF_FE72_u32.to_le_bytes())
        .unwrap();
    memory
        .MapBytes(0xD200, &0x0102_0304_0506_0708_u64.to_le_bytes())
        .unwrap();
    let service = ExpectedPAuthCall {
        operation: PAuthOperation::Autdb,
        value: 0x0102_0304_0506_0708,
        modifier: 0xD200,
        result: 0xA0B0_C0D0_E0F0_0102,
    };
    let mut executor = Executor::New(cpu, memory, service, 1).unwrap();
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(18).unwrap(), 0xA0B0_C0D0_E0F0_0102);
    assert_eq!(executor.Cpu().X(19).unwrap(), 0xD200);
    assert_eq!(executor.Cpu().pc, 0xCE68);
}

#[test]
fn LseAtomicRmwScalarVariantsMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCE6C,
        ..Default::default()
    };
    cpu.SetX(20, 5).unwrap();
    cpu.SetX(22, 0xD300).unwrap();
    let mut executor = RunWord(0xF834_02D5, cpu, &[(0xD300, &7_u64.to_le_bytes())]); // ldadd x20, x21, [x22]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(21).unwrap(), 7);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD300, 8).unwrap(),
        12_u64.to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCE70,
        ..Default::default()
    };
    cpu.SetX(1, 0xFFFF_FFFF_FFFF_FFF0).unwrap();
    cpu.SetX(3, 0xD308).unwrap();
    let mut executor = RunWord(
        0xF821_4062,
        cpu,
        &[(0xD308, &(-5_i64 as u64).to_le_bytes())],
    ); // ldsmax x1, x2, [x3]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(2).unwrap(), -5_i64 as u64);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD308, 8).unwrap(),
        (-5_i64 as u64).to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCE74,
        ..Default::default()
    };
    cpu.SetX(4, 0x1234_5678_9ABC_DEF0).unwrap();
    cpu.SetX(6, 0xD310).unwrap();
    let mut executor = RunWord(
        0xF824_80C5,
        cpu,
        &[(0xD310, &0x0F0E_0D0C_0B0A_0908_u64.to_le_bytes())],
    ); // swp x4, x5, [x6]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(5).unwrap(), 0x0F0E_0D0C_0B0A_0908);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD310, 8).unwrap(),
        0x1234_5678_9ABC_DEF0_u64.to_le_bytes()
    );
}

#[test]
fn Lse128AtomicRmwVariantsMatchMonarchCReference() {
    let old_clear = [
        0xFF00_FF00_FF00_FF00_u64.to_le_bytes(),
        0x0F0F_0F0F_0F0F_0F0F_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE78,
        ..Default::default()
    };
    cpu.SetX(8, 0x00FF_0000_00FF_0000).unwrap();
    cpu.SetX(9, 0x000F_000F_000F_000F).unwrap();
    cpu.SetX(10, 0xD320).unwrap();
    let mut executor = RunWord(0x1929_1148, cpu, &[(0xD320, &old_clear)]); // ldclrp x8, x9, [x10]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(8).unwrap(), 0xFF00_FF00_FF00_FF00);
    assert_eq!(executor.Cpu().X(9).unwrap(), 0x0F0F_0F0F_0F0F_0F0F);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD320, 16).unwrap(),
        [
            0xFF00_FF00_FF00_FF00_u64.to_le_bytes(),
            0x0F00_0F00_0F00_0F00_u64.to_le_bytes(),
        ]
        .concat()
    );

    let old_set = [
        0x0000_F000_0000_F000_u64.to_le_bytes(),
        0x0000_0000_0000_0001_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE7C,
        ..Default::default()
    };
    cpu.SetX(11, 0x0000_0F00_0000_0F00).unwrap();
    cpu.SetX(12, 0x8000_0000_0000_0000).unwrap();
    cpu.SetX(13, 0xD330).unwrap();
    let mut executor = RunWord(0x192C_31AB, cpu, &[(0xD330, &old_set)]); // ldsetp x11, x12, [x13]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(11).unwrap(), 0x0000_F000_0000_F000);
    assert_eq!(executor.Cpu().X(12).unwrap(), 0x0000_0000_0000_0001);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD330, 16).unwrap(),
        [
            0x0000_FF00_0000_FF00_u64.to_le_bytes(),
            0x8000_0000_0000_0001_u64.to_le_bytes(),
        ]
        .concat()
    );

    let old_swap = [
        0x1111_2222_3333_4444_u64.to_le_bytes(),
        0x5555_6666_7777_8888_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE80,
        ..Default::default()
    };
    cpu.SetX(14, 0x9999_AAAA_BBBB_CCCC).unwrap();
    cpu.SetX(15, 0xDDDD_EEEE_FFFF_0000).unwrap();
    cpu.SetX(16, 0xD340).unwrap();
    let mut executor = RunWord(0x192F_820E, cpu, &[(0xD340, &old_swap)]); // swpp x14, x15, [x16]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(14).unwrap(), 0x1111_2222_3333_4444);
    assert_eq!(executor.Cpu().X(15).unwrap(), 0x5555_6666_7777_8888);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD340, 16).unwrap(),
        [
            0x9999_AAAA_BBBB_CCCC_u64.to_le_bytes(),
            0xDDDD_EEEE_FFFF_0000_u64.to_le_bytes(),
        ]
        .concat()
    );
}

#[test]
fn RcwCompareSwapSoftwareFallbackMatchesMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCE84,
        ..Default::default()
    };
    cpu.SetX(0, 7).unwrap();
    cpu.SetX(1, 9).unwrap();
    cpu.SetX(2, 0xD350).unwrap();
    let mut executor = RunWord(0x1920_0841, cpu, &[(0xD350, &7_u64.to_le_bytes())]); // rcwcas x0, x1, [x2]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 7);
    assert_eq!(executor.Cpu().nzcv, 0x2000_0000);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD350, 8).unwrap(),
        9_u64.to_le_bytes()
    );

    let mut cpu = CpuState {
        pc: 0xCE88,
        ..Default::default()
    };
    cpu.SetX(0, 8).unwrap();
    cpu.SetX(1, 9).unwrap();
    cpu.SetX(2, 0xD350).unwrap();
    let mut executor = RunWord(0x1920_0841, cpu, &[(0xD350, &7_u64.to_le_bytes())]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 7);
    assert_eq!(executor.Cpu().nzcv, 0xA000_0000);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD350, 8).unwrap(),
        7_u64.to_le_bytes()
    );
}

#[test]
fn RcwServiceReceivesTypedInfoAndCanOverrideOldValueAndFlags() {
    let mut cpu = CpuState {
        pc: 0xCE8C,
        ..Default::default()
    };
    cpu.SetX(9, 0x00FF_00FF_00FF_00FF).unwrap();
    cpu.SetX(11, 0xD358).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x7829_916A_u32.to_le_bytes())
        .unwrap(); // rcwsclr x9, x10, [x11]
    memory
        .MapBytes(0xD358, &0x1122_3344_5566_7788_u64.to_le_bytes())
        .unwrap();
    let service = ExpectedAtomicRcw {
        expected: AtomicRcwInfo {
            pc: 0xCE8C,
            address: 0xD358,
            operation: AtomicRcwOperation::Clear,
            software_checks: true,
            element_count: 1,
            compare: [0, 0],
            operand: [0x00FF_00FF_00FF_00FF, 0],
        },
        result: AtomicRcwResult {
            old_value: [0x8877_6655_4433_2211, 0],
            nzcv: 0x5000_0000,
        },
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        service,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(10).unwrap(), 0x8877_6655_4433_2211);
    assert_eq!(executor.Cpu().nzcv, 0x5000_0000);
    assert!(executor.Memory().Writes().is_empty());
}

#[test]
fn RcwPairCompareSwapFallbackMatchesMonarchCReference() {
    let success_bytes = [
        0x0000_0000_0000_0010_u64.to_le_bytes(),
        0x0000_0000_0000_0020_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE90,
        ..Default::default()
    };
    cpu.SetX(0, 0x10).unwrap();
    cpu.SetX(1, 0x20).unwrap();
    cpu.SetX(6, 0x1111_2222_3333_4444).unwrap();
    cpu.SetX(7, 0x5555_6666_7777_8888).unwrap();
    cpu.SetX(4, 0xD360).unwrap();
    let mut executor = RunWord(0x1920_0C86, cpu, &[(0xD360, &success_bytes)]); // rcwcasp x0, x1, x6, x7, [x4]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x10);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0x20);
    assert_eq!(executor.Cpu().nzcv, 0x2000_0000);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD360, 16).unwrap(),
        [
            0x1111_2222_3333_4444_u64.to_le_bytes(),
            0x5555_6666_7777_8888_u64.to_le_bytes(),
        ]
        .concat()
    );

    let fail_bytes = [
        0x0000_0000_0000_0010_u64.to_le_bytes(),
        0x0000_0000_0000_0020_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE94,
        ..Default::default()
    };
    cpu.SetX(0, 0x10).unwrap();
    cpu.SetX(1, 0x21).unwrap();
    cpu.SetX(6, 0x1111_2222_3333_4444).unwrap();
    cpu.SetX(7, 0x5555_6666_7777_8888).unwrap();
    cpu.SetX(4, 0xD368).unwrap();
    let mut executor = RunWord(0x1920_0C86, cpu, &[(0xD368, &fail_bytes)]);
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x10);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0x20);
    assert_eq!(executor.Cpu().nzcv, 0xA000_0000);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD368, 16).unwrap(),
        fail_bytes
    );
}

#[test]
fn RcwPairSetAcquireAliasFallbackMatchesMonarchCReference() {
    let old = [
        0x0000_0000_0000_0010_u64.to_le_bytes(),
        0x0000_0000_0000_0020_u64.to_le_bytes(),
    ]
    .concat();
    let mut cpu = CpuState {
        pc: 0xCE98,
        ..Default::default()
    };
    cpu.SetX(1, 1).unwrap();
    cpu.SetX(2, 2).unwrap();
    cpu.SetX(3, 0xD370).unwrap();
    let mut executor = RunWord(0x19A2_B061, cpu, &[(0xD370, &old)]); // rcwsetpa x1, x2, [x3]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(1).unwrap(), 0x10);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0x20);
    assert_eq!(executor.Cpu().nzcv, 0x2000_0000);
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD370, 16).unwrap(),
        [
            0x0000_0000_0000_0011_u64.to_le_bytes(),
            0x0000_0000_0000_0022_u64.to_le_bytes(),
        ]
        .concat()
    );
}

#[test]
fn LsfeLoadAddWritesOldFloatingValueToTargetAndStoresResult() {
    let mut cpu = CpuState {
        pc: 0xCE9C,
        ..Default::default()
    };
    cpu.SetX(2, 0xD380).unwrap();
    cpu.SetV(1, &(2.0_f32).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(3, &0xDEAD_BEEF_u32.to_le_bytes()).unwrap();
    let mut executor = RunWord(
        0x7C21_0043,
        cpu,
        &[(0xD380, &(1.0_f32).to_bits().to_le_bytes())],
    ); // ldfadd s1, s3, [x2]
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(3).unwrap()[..4].try_into().unwrap()),
        (1.0_f32).to_bits()
    );
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD380, 4).unwrap(),
        (3.0_f32).to_bits().to_le_bytes()
    );
}

#[test]
fn LsfeStoreBfloatMaxUpdatesMemoryWithoutTargetWriteback() {
    let mut cpu = CpuState {
        pc: 0xCEA0,
        ..Default::default()
    };
    cpu.SetX(7, 0xD390).unwrap();
    cpu.SetV(5, &0x4000_u16.to_le_bytes()).unwrap(); // bfloat16 格式的 2.0
    let mut executor = RunWord(0x3C25_C0FF, cpu, &[(0xD390, &0x3F80_u16.to_le_bytes())]); // stbfmax h5, [x7]
    executor.Step().unwrap();
    assert_eq!(
        &executor.Cpu().V(5).unwrap()[..2],
        0x4000_u16.to_le_bytes().as_slice()
    );
    assert_eq!(
        executor.MemoryMut().ReadVec(0xD390, 2).unwrap(),
        0x4000_u16.to_le_bytes()
    );
}

#[test]
fn Ls64LoadAndStoreFormsMatchMonarchCReference() {
    let words = (0_u64..8)
        .flat_map(|value| value.wrapping_mul(0x1111_1111_1111_1111).to_le_bytes())
        .collect::<Vec<_>>();
    let mut cpu = CpuState {
        pc: 0xCE90,
        ..Default::default()
    };
    cpu.SetX(1, 0xD400).unwrap();
    let mut executor = RunWord(0xF83F_D020, cpu, &[(0xD400, &words)]); // ld64b x0, [x1]
    executor.Step().unwrap();
    for index in 0..8 {
        let expected = u64::from_le_bytes(words[index * 8..index * 8 + 8].try_into().unwrap());
        assert_eq!(executor.Cpu().X(index).unwrap(), expected);
    }

    let mut cpu = CpuState {
        pc: 0xCE94,
        ..Default::default()
    };
    for index in 0..8 {
        cpu.SetX(6 + index, 0xA000_0000_0000_0000_u64 + index as u64)
            .unwrap();
    }
    cpu.SetX(4, 0xDEAD_BEEF).unwrap();
    cpu.SetX(7, 0xD440).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xF824_A0E6_u32.to_le_bytes())
        .unwrap(); // st64bv0 x4, x6, [x7]
    let store64 = ExpectedStore64 {
        expected: Store64Info {
            pc: 0xCE94,
            address: 0xD440,
            operation: Store64Operation::StoreWithStatusAndAccdata,
            data: [
                0xA000_0000_0000_0000,
                0xD440,
                0xA000_0000_0000_0002,
                0xA000_0000_0000_0003,
                0xA000_0000_0000_0004,
                0xA000_0000_0000_0005,
                0xA000_0000_0000_0006,
                0xA000_0000_0000_0007,
            ],
        },
        result: Store64Result { status: 3 },
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        store64,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(4).unwrap(), 3);
    assert!(executor.Memory().Writes().is_empty());
}

#[test]
fn MemoryTagInstructionsUseTypedServiceAndArchitectedDataWrites() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & !0xFF
    }

    let mut cpu = CpuState {
        pc: 0xCE98,
        ..Default::default()
    };
    cpu.SetX(7, 0x0100_0000_0000_1234).unwrap();
    cpu.SetX(8, 0xAB00_0000_0000_1073).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD960_0107_u32.to_le_bytes())
        .unwrap(); // ldg x7, [x8]
    let ldg = ExpectedMemoryTag {
        expected: MemoryTagInfo {
            pc: 0xCE98,
            address: 0xAB00_0000_0000_1000,
            operation: MemoryTagOperation::Load,
            value: 0,
            granule_count: 1,
            zero_data: false,
        },
        result: MemoryTagResult { value: 0xB },
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        ldg,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(7).unwrap(), 0x0B00_0000_0000_1234);

    let mut cpu = CpuState {
        pc: 0xCE9C,
        ..Default::default()
    };
    cpu.SetX(15, 0x1111_2222_3333_4444).unwrap();
    cpu.SetX(16, 0x5555_6666_7777_8888).unwrap();
    cpu.SetX(17, 0xC300_0000_0000_2008).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x6900_422F_u32.to_le_bytes())
        .unwrap(); // stgp x15, x16, [x17]
    memory.MapBytes(0xC300_0000_0000_2008, &[0; 16]).unwrap();
    let stgp = ExpectedMemoryTag {
        expected: MemoryTagInfo {
            pc: 0xCE9C,
            address: 0xC300_0000_0000_2000,
            operation: MemoryTagOperation::Store,
            value: 0x3,
            granule_count: 1,
            zero_data: false,
        },
        result: MemoryTagResult::default(),
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        stgp,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    executor.Step().unwrap();

    assert_eq!(
        executor
            .MemoryMut()
            .ReadVec(0xC300_0000_0000_2008, 16)
            .unwrap(),
        [
            0x1111_2222_3333_4444_u64.to_le_bytes(),
            0x5555_6666_7777_8888_u64.to_le_bytes(),
        ]
        .concat()
    );
}

#[test]
fn GcsInstructionsUseTypedServiceBoundary() {
    let mut cpu = CpuState {
        pc: 0xCEA0,
        ..Default::default()
    };
    cpu.SetX(1, 0x1234_5678_9ABC_DEF0).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD50B_7701_u32.to_le_bytes())
        .unwrap(); // gcspushm x1
    let push = ExpectedGcs {
        expected: GcsInfo {
            pc: 0xCEA0,
            operation: GcsOperation::Push,
            reg: 1,
            value: 0x1234_5678_9ABC_DEF0,
        },
        result: GcsResult::default(),
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        push,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    let mut cpu = CpuState {
        pc: 0xCEA4,
        ..Default::default()
    };
    cpu.SetX(5, 0x9999).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD52B_7765_u32.to_le_bytes())
        .unwrap(); // gcsss2 x5
    let pop = ExpectedGcs {
        expected: GcsInfo {
            pc: 0xCEA4,
            operation: GcsOperation::SwitchStackPhase2,
            reg: 5,
            value: 0,
        },
        result: GcsResult {
            value: 0xCAFE_BABE_F00D,
        },
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        pop,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(5).unwrap(), 0xCAFE_BABE_F00D);
}

#[test]
fn ExceptionReturnUsesTypedServiceBoundary() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & !0xF
    }

    let cpu = CpuState {
        pc: 0xCEA8,
        ..Default::default()
    };
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD69F_0BFF_u32.to_le_bytes())
        .unwrap(); // eretaa
    let service = ExpectedExceptionReturn {
        expected: ExceptionReturnInfo {
            pc: 0xCEA8,
            key_b: false,
        },
        result: ExceptionReturnResult { target: 0x2003 },
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        service,
        77,
    )
    .unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    assert_eq!(executor.Step().unwrap(), StepOutcome::Branch);
    assert_eq!(executor.Cpu().pc, 0x2000);
}

#[test]
fn MopsCopyForwardFallbackUsesTypedServiceAndRegisterWriteback() {
    let mut cpu = CpuState {
        pc: 0xCEAC,
        ..Default::default()
    };
    cpu.SetX(0, 0xD700).unwrap();
    cpu.SetX(1, 16).unwrap();
    cpu.SetX(2, 0xD800).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1D82_0420_u32.to_le_bytes())
        .unwrap(); // cpye [x0]!, [x1]!, x2!
    memory.MapBytes(0xD700, &[0; 16]).unwrap();
    memory
        .MapBytes(
            0xD800,
            &[
                0x1122_3344_5566_7788_u64.to_le_bytes(),
                0x99AA_BBCC_DDEE_FF00_u64.to_le_bytes(),
            ]
            .concat(),
        )
        .unwrap();
    let service = ExpectedMops {
        expected: MopsInfo {
            pc: 0xCEAC,
            operation: MopsOperation::Copy,
            destination_address: 0xD700,
            source_address: 0xD800,
            count: 16,
            fill_byte: 0,
            backwards: false,
        },
        result: MopsResult,
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        service,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(
        executor.MemoryMut().ReadVec(0xD700, 16).unwrap(),
        [
            0x1122_3344_5566_7788_u64.to_le_bytes(),
            0x99AA_BBCC_DDEE_FF00_u64.to_le_bytes(),
        ]
        .concat()
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0xD710);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0xD810);
}

#[test]
fn MopsCopyBackwardFallbackPreservesOverlappedSourceBytes() {
    let mut cpu = CpuState {
        pc: 0xCEB0,
        ..Default::default()
    };
    cpu.SetX(0, 0xD808).unwrap();
    cpu.SetX(1, 16).unwrap();
    cpu.SetX(2, 0xD800).unwrap();
    let original: Vec<u8> = (0..24).collect();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1D82_0420_u32.to_le_bytes())
        .unwrap(); // cpye [x0]!, [x1]!, x2!
    memory.MapBytes(0xD800, &original).unwrap();
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(
        executor.MemoryMut().ReadVec(0xD808, 16).unwrap(),
        original[..16]
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0xD818);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0xD810);
}

#[test]
fn MopsSetAndSetgFallbackUseFillByteAndTagServices() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & 0xFFFF
    }

    let mut cpu = CpuState {
        pc: 0xCEB4,
        ..Default::default()
    };
    cpu.SetX(0, 0xD900).unwrap();
    cpu.SetX(1, 16).unwrap();
    cpu.SetX(2, 0x5A).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x19C2_8420_u32.to_le_bytes())
        .unwrap(); // sete [x0]!, x1!, x2
    memory.MapBytes(0xD900, &[0; 16]).unwrap();
    let service = ExpectedMops {
        expected: MopsInfo {
            pc: 0xCEB4,
            operation: MopsOperation::Set,
            destination_address: 0xD900,
            source_address: 0,
            count: 16,
            fill_byte: 0x5A,
            backwards: false,
        },
        result: MopsResult,
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        service,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(
        executor.MemoryMut().ReadVec(0xD900, 16).unwrap(),
        vec![0x5A; 16]
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0xD910);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);

    let mut cpu = CpuState {
        pc: 0xCEB8,
        ..Default::default()
    };
    cpu.SetX(0, 0x0A00_0000_0000_DA00).unwrap();
    cpu.SetX(1, 16).unwrap();
    cpu.SetX(2, 0x33).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1DC2_0420_u32.to_le_bytes())
        .unwrap(); // setgp [x0]!, x1!, x2
    memory.MapBytes(0x0A00_0000_0000_DA00, &[0x11; 16]).unwrap();
    let tag_service = ExpectedMemoryTag {
        expected: MemoryTagInfo {
            pc: 0xCEB8,
            address: 0xDA00,
            operation: MemoryTagOperation::StoreMultiple,
            value: 0xA,
            granule_count: 1,
            zero_data: false,
        },
        result: MemoryTagResult::default(),
    };
    let mops_service = ExpectedMops {
        expected: MopsInfo {
            pc: 0xCEB8,
            operation: MopsOperation::SetTags,
            destination_address: 0x0A00_0000_0000_DA00,
            source_address: 0,
            count: 16,
            fill_byte: 0x33,
            backwards: false,
        },
        result: MopsResult,
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        tag_service,
        RejectStore64Service,
        RejectGcsService,
        mops_service,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    executor.Step().unwrap();

    assert_eq!(
        executor
            .MemoryMut()
            .ReadVec(0x0A00_0000_0000_DA00, 16)
            .unwrap(),
        vec![0x33; 16]
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x0A00_0000_0000_DA10);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
}

#[test]
fn MopsSetgoUsesTagServiceWithoutWritingData() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & 0xFFFF
    }

    let mut cpu = CpuState {
        pc: 0xCEBC,
        ..Default::default()
    };
    cpu.SetX(0, 0x0B00_0000_0000_DB00).unwrap();
    cpu.SetX(1, 16).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1DDF_0020_u32.to_le_bytes())
        .unwrap(); // setgo [x0]!, x1!
    let original = [
        0x1122_3344_5566_7788_u64.to_le_bytes(),
        0x99AA_BBCC_DDEE_FF00_u64.to_le_bytes(),
    ]
    .concat();
    memory.MapBytes(0x0B00_0000_0000_DB00, &original).unwrap();
    let tag_service = ExpectedMemoryTag {
        expected: MemoryTagInfo {
            pc: 0xCEBC,
            address: 0xDB00,
            operation: MemoryTagOperation::StoreMultiple,
            value: 0xB,
            granule_count: 1,
            zero_data: false,
        },
        result: MemoryTagResult::default(),
    };
    let mops_service = ExpectedMops {
        expected: MopsInfo {
            pc: 0xCEBC,
            operation: MopsOperation::SetTagsOnly,
            destination_address: 0x0B00_0000_0000_DB00,
            source_address: 0,
            count: 16,
            fill_byte: 0,
            backwards: false,
        },
        result: MopsResult,
    };
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        tag_service,
        RejectStore64Service,
        RejectGcsService,
        mops_service,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    executor.Step().unwrap();

    assert_eq!(
        executor
            .MemoryMut()
            .ReadVec(0x0B00_0000_0000_DB00, original.len())
            .unwrap(),
        original
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x0B00_0000_0000_DB10);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
}

#[test]
fn MopsSetgoZeroCountSkipsTagServiceAndLeavesMemoryUntouched() {
    let mut cpu = CpuState {
        pc: 0xCEBE,
        ..Default::default()
    };
    cpu.SetX(0, 0x0B00_0000_0000_DB20).unwrap();
    cpu.SetX(1, 0).unwrap();
    let original = [
        0x0123_4567_89AB_CDEF_u64.to_le_bytes(),
        0x0F1E_2D3C_4B5A_6978_u64.to_le_bytes(),
    ]
    .concat();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1DDF_0020_u32.to_le_bytes())
        .unwrap(); // setgo [x0]!, x1!
    memory.MapBytes(0x0B00_0000_0000_DB20, &original).unwrap();
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    executor.Step().unwrap();

    assert_eq!(
        executor
            .MemoryMut()
            .ReadVec(0x0B00_0000_0000_DB20, original.len())
            .unwrap(),
        original
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x0B00_0000_0000_DB20);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0);
}

#[test]
fn MopsServiceErrorsSurfaceBeforeFallback() {
    let mut cpu = CpuState {
        pc: 0xCEC0,
        ..Default::default()
    };
    cpu.SetX(0, 0xDC00).unwrap();
    cpu.SetX(1, 16).unwrap();
    cpu.SetX(2, 0xDD00).unwrap();
    let source = [
        0x0123_4567_89AB_CDEF_u64.to_le_bytes(),
        0x0F1E_2D3C_4B5A_6978_u64.to_le_bytes(),
    ]
    .concat();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1D82_0420_u32.to_le_bytes())
        .unwrap(); // cpye [x0]!, [x1]!, x2!
    memory.MapBytes(0xDC00, &[0; 16]).unwrap();
    memory.MapBytes(0xDD00, &source).unwrap();
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        FailingMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    let error = executor.Step().unwrap_err();

    assert!(matches!(
        error,
        ExecutionError::AdvancedService { ref message, .. } if message.contains("mops boom")
    ));
    assert_eq!(
        executor.MemoryMut().ReadVec(0xDC00, 16).unwrap(),
        vec![0; 16]
    );
    assert_eq!(executor.MemoryMut().ReadVec(0xDD00, 16).unwrap(), source);
    assert_eq!(executor.Cpu().X(0).unwrap(), 0xDC00);
    assert_eq!(executor.Cpu().X(1).unwrap(), 16);
    assert_eq!(executor.Cpu().X(2).unwrap(), 0xDD00);
}

#[test]
fn MopsSetgoWithoutMemoryTagServiceRemainsUnsupported() {
    let mut cpu = CpuState {
        pc: 0xCEC4,
        ..Default::default()
    };
    cpu.SetX(0, 0x0C00_0000_0000_DE00).unwrap();
    cpu.SetX(1, 16).unwrap();
    let original = [
        0xAABB_CCDD_EEFF_0011_u64.to_le_bytes(),
        0x2233_4455_6677_8899_u64.to_le_bytes(),
    ]
    .concat();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0x1DDF_0020_u32.to_le_bytes())
        .unwrap(); // setgo [x0]!, x1!
    memory.MapBytes(0x0C00_0000_0000_DE00, &original).unwrap();
    let mut executor = Executor::NewWithAdvancedServices(
        cpu,
        memory,
        FixturePAuth::default(),
        RejectSystemRegisterService,
        RejectAtomicRcwService,
        RejectMemoryTagService,
        RejectStore64Service,
        RejectGcsService,
        RejectMopsService,
        RejectExceptionReturnService,
        77,
    )
    .unwrap();

    let error = executor.Step().unwrap_err();

    assert!(matches!(error, ExecutionError::Unsupported { .. }));
    assert_eq!(
        executor
            .MemoryMut()
            .ReadVec(0x0C00_0000_0000_DE00, original.len())
            .unwrap(),
        original
    );
    assert_eq!(executor.Cpu().X(0).unwrap(), 0x0C00_0000_0000_DE00);
    assert_eq!(executor.Cpu().X(1).unwrap(), 16);
}

#[test]
fn AuthenticatedBranchesAndSpPauthAliasesUseThePauthService() {
    let mut cpu = CpuState {
        pc: 0xCE30,
        sp: 0x7000,
        ..Default::default()
    };
    cpu.SetX(2, 0x1111).unwrap();
    let mut executor = RunWord(0xD61F_085F, cpu, &[]); // braaz x2
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().pc, 0);

    let mut cpu = CpuState {
        pc: 0xCE34,
        sp: 0x7000,
        ..Default::default()
    };
    cpu.SetX(30, 0x2222).unwrap();
    let mut executor = RunWord(0xD503_233F, cpu, &[]); // paciasp
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(30).unwrap(), 0);
}

#[test]
fn AuthenticatedBranchFamilyUsesKeyModifierAndLinkSemantics() {
    let cases = [
        (0xD71F_0801_u32, PAuthOperation::Autia, 0x2222, false), // braa x0, x1
        (0xD71F_0C01, PAuthOperation::Autib, 0x2222, false),     // brab x0, x1
        (0xD61F_081F, PAuthOperation::Autia, 0, false),          // braaz x0
        (0xD61F_0C1F, PAuthOperation::Autib, 0, false),          // brabz x0
        (0xD73F_0801, PAuthOperation::Autia, 0x2222, true),      // blraa x0, x1
        (0xD73F_0C01, PAuthOperation::Autib, 0x2222, true),      // blrab x0, x1
        (0xD63F_081F, PAuthOperation::Autia, 0, true),           // blraaz x0
        (0xD63F_0C1F, PAuthOperation::Autib, 0, true),           // blrabz x0
    ];
    for (word, operation, modifier, call) in cases {
        let mut cpu = CpuState {
            pc: 0xCE50,
            ..Default::default()
        };
        cpu.SetX(0, 0x1111).unwrap();
        cpu.SetX(1, 0x2222).unwrap();
        cpu.SetX(30, 0x3333).unwrap();
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(cpu.pc, &word.to_le_bytes()).unwrap();
        let service = ExpectedPAuthCall {
            operation,
            value: 0x1111,
            modifier,
            result: 0x4444,
        };
        let mut executor = Executor::New(cpu, memory, service, 1).unwrap();
        assert_eq!(executor.Step().unwrap(), StepOutcome::Branch);
        assert_eq!(executor.Cpu().pc, 0x4444);
        assert_eq!(
            executor.Cpu().X(30).unwrap(),
            if call { 0xCE54 } else { 0x3333 }
        );
    }
}

#[test]
fn AuthenticatedReturnsUseLrAndSpWithoutChangingLr() {
    for (word, operation) in [
        (0xD65F_0BFF_u32, PAuthOperation::Autia),
        (0xD65F_0FFF, PAuthOperation::Autib),
    ] {
        let mut cpu = CpuState {
            pc: 0xCE58,
            sp: 0x2222,
            ..Default::default()
        };
        cpu.SetX(30, 0x1111).unwrap();
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(cpu.pc, &word.to_le_bytes()).unwrap();
        let service = ExpectedPAuthCall {
            operation,
            value: 0x1111,
            modifier: 0x2222,
            result: 0x4444,
        };
        let mut executor = Executor::New(cpu, memory, service, 1).unwrap();
        assert_eq!(executor.Step().unwrap(), StepOutcome::Branch);
        assert_eq!(executor.Cpu().pc, 0x4444);
        assert_eq!(executor.Cpu().X(30).unwrap(), 0x1111);
    }
}

#[test]
fn PauthServiceErrorsDoNotCommitBranchOrHintState() {
    for word in [0xD63F_081F_u32, 0xD503_233F] {
        let mut cpu = CpuState {
            pc: 0xCE5C,
            sp: 0x2222,
            ..Default::default()
        };
        cpu.SetX(0, 0x1111).unwrap();
        cpu.SetX(30, 0x3333).unwrap();
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(cpu.pc, &word.to_le_bytes()).unwrap();
        let mut executor = Executor::New(cpu, memory, RejectPAuthCall, 1).unwrap();
        assert!(matches!(executor.Step(), Err(ExecutionError::PAuth { .. })));
        assert_eq!(executor.Cpu().pc, 0xCE5C);
        assert_eq!(executor.Cpu().X(30).unwrap(), 0x3333);
    }
}

#[test]
fn SpPauthHintAliasesAuthenticateLrWithSp() {
    for (word, operation) in [
        (0xD503_233F_u32, PAuthOperation::Pacia),
        (0xD503_237F, PAuthOperation::Pacib),
        (0xD503_23BF, PAuthOperation::Autia),
        (0xD503_23FF, PAuthOperation::Autib),
    ] {
        let mut cpu = CpuState {
            pc: 0xCE60,
            sp: 0x2222,
            ..Default::default()
        };
        cpu.SetX(30, 0x1111).unwrap();
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(cpu.pc, &word.to_le_bytes()).unwrap();
        let service = ExpectedPAuthCall {
            operation,
            value: 0x1111,
            modifier: 0x2222,
            result: 0x3333,
        };
        let mut executor = Executor::New(cpu, memory, service, 1).unwrap();
        executor.Step().unwrap();
        assert_eq!(executor.Cpu().X(30).unwrap(), 0x3333);
        assert_eq!(executor.Cpu().pc, 0xCE64);
    }
}

#[test]
fn HalfPrecisionVectorFmlaAndFmlsOperatePerLane() {
    for (word, expected) in [
        (0x0E42_0C20, "0049004900490049"),
        (0x0EC2_0C20, "00c000c000c000c0"),
    ] {
        let mut cpu = CpuState {
            pc: 0xCE70,
            ..Default::default()
        };
        cpu.SetV(0, &hex::decode("00440044004400440000000000000000").unwrap())
            .unwrap();
        cpu.SetV(1, &hex::decode("00400040004000400000000000000000").unwrap())
            .unwrap();
        cpu.SetV(2, &hex::decode("00420042004200420000000000000000").unwrap())
            .unwrap();
        let mut executor = RunWord(word, cpu, &[]);
        executor.Step().unwrap();
        assert_eq!(
            &executor.Cpu().V(0).unwrap()[..8],
            &hex::decode(expected).unwrap()
        );
    }
}

#[test]
fn HalfPrecisionIndexedFmlaAndFmlsUseLaneOperands() {
    let mut cpu = CpuState {
        pc: 0xCE80,
        ..Default::default()
    };
    cpu.SetV(1, &HalfBytes(&[0x3C00, 0x4000, 0x4200, 0x4400]))
        .unwrap();
    cpu.SetV(2, &HalfBytes(&[0x4500, 0x4600, 0x4700, 0x4800]))
        .unwrap();
    cpu.SetV(3, &HalfBytes(&[0x3C00, 0x4000, 0x4200, 0x4400]))
        .unwrap();
    let mut executor = RunWord(0x0F23_1041, cpu, &[]);

    executor.Step().unwrap();

    assert_eq!(
        executor.Cpu().V(1).unwrap(),
        HalfBytes(&[0x4C00, 0x4D00, 0x4E00, 0x4F00]).as_slice()
    );

    let mut cpu = CpuState {
        pc: 0xCE84,
        ..Default::default()
    };
    cpu.SetV(4, &HalfBytes(&[0x4900])).unwrap();
    cpu.SetV(5, &HalfBytes(&[0x4000])).unwrap();
    cpu.SetV(6, &HalfBytes(&[0x3C00, 0x4200, 0x4500, 0x4800]))
        .unwrap();
    let mut executor = RunWord(0x5F16_50A4, cpu, &[]);

    executor.Step().unwrap();

    assert_eq!(
        executor.Cpu().V(4).unwrap(),
        HalfBytes(&[0x4400]).as_slice()
    );
}

#[test]
fn AuthenticatedBranchTargetsAreNormalizedBeforeBranching() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & !0xfff
    }

    let mut cpu = CpuState {
        pc: 0xCE90,
        ..Default::default()
    };
    cpu.SetX(2, 0x1111_2222_3333_4444).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD61F_085F_u32.to_le_bytes())
        .unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth { result: 0x2003 }, 1).unwrap();
    executor.SetAddressNormalizer(NormalizeAddress);

    assert_eq!(executor.Step().unwrap(), StepOutcome::Branch);
    assert_eq!(executor.Cpu().pc, 0x2000);
}

#[test]
fn ScalarLegacyBitOpsMultiplyHighAndExtractMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCEA0,
        ..Default::default()
    };
    cpu.SetX(6, 1).unwrap();
    let mut executor = RunWord(0xDAC0_10C5, cpu, &[]); // clz x5, x6
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(5).unwrap(), 63);

    let mut cpu = CpuState {
        pc: 0xCEA4,
        ..Default::default()
    };
    cpu.SetX(8, 1).unwrap();
    let mut executor = RunWord(0x5AC0_0107, cpu, &[]); // rbit w7, w8
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(7).unwrap(), 0x8000_0000);

    let mut cpu = CpuState {
        pc: 0xCEA8,
        ..Default::default()
    };
    cpu.SetX(10, 0x0123_4567_89AB_CDEF).unwrap();
    let mut executor = RunWord(0xDAC0_0D49, cpu, &[]); // rev x9, x10
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(9).unwrap(), 0xEFCD_AB89_6745_2301);

    let mut cpu = CpuState {
        pc: 0xCEAC,
        ..Default::default()
    };
    cpu.SetX(12, 0x1122_3344).unwrap();
    let mut executor = RunWord(0x5AC0_058B, cpu, &[]); // rev16 w11, w12
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(11).unwrap(), 0x2211_4433);

    let mut cpu = CpuState {
        pc: 0xCEB0,
        ..Default::default()
    };
    cpu.SetX(14, 0x1122_3344_5566_7788).unwrap();
    let mut executor = RunWord(0xDAC0_09CD, cpu, &[]); // rev32 x13, x14
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(13).unwrap(), 0x4433_2211_8877_6655);

    let mut cpu = CpuState {
        pc: 0xCEB4,
        ..Default::default()
    };
    cpu.SetX(16, 0x0123_4567_89AB_CDEF).unwrap();
    cpu.SetX(17, 0xFEDC_BA98_7654_3210).unwrap();
    let mut executor = RunWord(0x93D1_160F, cpu, &[]); // extr x15, x16, x17, #5
    executor.Step().unwrap();
    let expected = (0xFEDC_BA98_7654_3210_u64 >> 5) | (0x0123_4567_89AB_CDEF_u64 << 59);
    assert_eq!(executor.Cpu().X(15).unwrap(), expected);

    let mut cpu = CpuState {
        pc: 0xCEB8,
        ..Default::default()
    };
    cpu.SetX(19, 0xFFFF_FFFF_FFFF_FFFE).unwrap();
    cpu.SetX(20, 3).unwrap();
    let mut executor = RunWord(0x9B54_7E72, cpu, &[]); // smulh x18, x19, x20
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(18).unwrap(), 0xFFFF_FFFF_FFFF_FFFF);

    let mut cpu = CpuState {
        pc: 0xCEBC,
        ..Default::default()
    };
    cpu.SetX(22, 0xFFFF_FFFF_FFFF_FFFF).unwrap();
    cpu.SetX(23, 2).unwrap();
    let mut executor = RunWord(0x9BD7_7ED5, cpu, &[]); // umulh x21, x22, x23
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(21).unwrap(), 1);

    let mut cpu = CpuState {
        pc: 0xCEC0,
        ..Default::default()
    };
    cpu.SetX(25, 2).unwrap();
    cpu.SetX(26, 3).unwrap();
    cpu.SetX(27, 10).unwrap();
    let mut executor = RunWord(0x9B3A_EF38, cpu, &[]); // smsubl x24, w25, w26, x27
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(24).unwrap(), 4);
}

#[test]
fn ScalarLegacyLoadStoreExtensionsMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCED0,
        ..Default::default()
    };
    cpu.SetX(2, 0xD000).unwrap();
    let pair_words = [1_u32.to_le_bytes(), u32::MAX.to_le_bytes()].concat();
    let mut executor = RunWord(0x6940_0440, cpu, &[(0xD000, &pair_words)]); // ldpsw x0, x1, [x2]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(0).unwrap(), 1);
    assert_eq!(executor.Cpu().X(1).unwrap(), 0xFFFF_FFFF_FFFF_FFFF);

    let mut cpu = CpuState {
        pc: 0xCED4,
        ..Default::default()
    };
    cpu.SetX(4, 0xD100).unwrap();
    let halfword = [0_u8, 0_u8, 0x34, 0x12];
    let mut executor = RunWord(0x7840_2083, cpu, &[(0xD100, &halfword)]); // ldurh w3, [x4, #2]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(3).unwrap(), 0x1234);

    let mut cpu = CpuState {
        pc: 0xCED8,
        ..Default::default()
    };
    cpu.SetX(6, 0xD200).unwrap();
    let signed_byte = [0_u8, 0_u8, 0_u8, 0x80];
    let mut executor = RunWord(0x3880_30C5, cpu, &[(0xD200, &signed_byte)]); // ldursb x5, [x6, #3]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(5).unwrap(), 0xFFFF_FFFF_FFFF_FF80);

    let mut cpu = CpuState {
        pc: 0xCEDC,
        ..Default::default()
    };
    cpu.SetX(8, 0xD300).unwrap();
    let signed_halfword = [0x01_u8, 0x80];
    let mut executor = RunWord(0x7880_4107, cpu, &[(0xD304, &signed_halfword)]); // ldursh x7, [x8, #4]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(7).unwrap(), 0xFFFF_FFFF_FFFF_8001);

    let mut cpu = CpuState {
        pc: 0xCEE0,
        ..Default::default()
    };
    cpu.SetX(10, 0xD400).unwrap();
    let signed_word = [0x01_u8, 0x00, 0x00, 0x80];
    let mut executor = RunWord(0xB880_8149, cpu, &[(0xD408, &signed_word)]); // ldursw x9, [x10, #8]
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().X(9).unwrap(), 0xFFFF_FFFF_8000_0001);

    let mut cpu = CpuState {
        pc: 0xCEE4,
        ..Default::default()
    };
    cpu.SetX(12, 0xD500).unwrap();
    cpu.SetX(11, 0xA5).unwrap();
    let mut executor = RunWord(0x3800_518B, cpu, &[(0xD500, &[0_u8])]); // sturb w11, [x12, #5]
    executor.Step().unwrap();
    assert_eq!(executor.Memory().Writes().len(), 1);
    assert_eq!(executor.Memory().Writes()[0].address, 0xD505);
    assert_eq!(executor.Memory().Writes()[0].bytes, vec![0xA5]);

    let mut cpu = CpuState {
        pc: 0xCEE8,
        ..Default::default()
    };
    cpu.SetX(14, 0xD600).unwrap();
    cpu.SetX(13, 0xBEEF).unwrap();
    let mut executor = RunWord(0x7800_61CD, cpu, &[(0xD600, &[0_u8, 0_u8])]); // sturh w13, [x14, #6]
    executor.Step().unwrap();
    assert_eq!(executor.Memory().Writes().len(), 1);
    assert_eq!(executor.Memory().Writes()[0].address, 0xD606);
    assert_eq!(executor.Memory().Writes()[0].bytes, vec![0xEF, 0xBE]);
}

#[test]
fn ScalarLegacyFloatingUnaryBinaryCompareAndSelectMatchMonarchCReference() {
    let mut cpu = CpuState {
        pc: 0xCEF0,
        ..Default::default()
    };
    cpu.SetV(1, &(-3.5_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E60_C020, cpu, &[]); // fabs d0, d1
    executor.Step().unwrap();
    assert_eq!(
        u64::from_le_bytes(executor.Cpu().V(0).unwrap()[..8].try_into().unwrap()),
        3.5_f64.to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCEF4,
        ..Default::default()
    };
    cpu.SetV(3, &(4.0_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E21_4062, cpu, &[]); // fneg s2, s3
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(2).unwrap()[..4].try_into().unwrap()),
        (-4.0_f32).to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCEF8,
        ..Default::default()
    };
    cpu.SetV(5, &(9.0_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E61_C0A4, cpu, &[]); // fsqrt d4, d5
    executor.Step().unwrap();
    assert_eq!(
        u64::from_le_bytes(executor.Cpu().V(4).unwrap()[..8].try_into().unwrap()),
        3.0_f64.to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCEFC,
        ..Default::default()
    };
    cpu.SetV(7, &(2.0_f32).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(8, &(5.0_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E28_48E6, cpu, &[]); // fmax s6, s7, s8
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(6).unwrap()[..4].try_into().unwrap()),
        5.0_f32.to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF00,
        ..Default::default()
    };
    cpu.SetV(10, &(-1.0_f64).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(11, &(3.0_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E6B_5949, cpu, &[]); // fmin d9, d10, d11
    executor.Step().unwrap();
    assert_eq!(
        u64::from_le_bytes(executor.Cpu().V(9).unwrap()[..8].try_into().unwrap()),
        (-1.0_f64).to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF04,
        ..Default::default()
    };
    cpu.SetV(13, &f32::NAN.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(14, &(5.0_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E2E_69AC, cpu, &[]); // fmaxnm s12, s13, s14
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(12).unwrap()[..4].try_into().unwrap()),
        5.0_f32.to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF08,
        ..Default::default()
    };
    cpu.SetV(16, &f64::NAN.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(17, &(-7.0_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E71_7A0F, cpu, &[]); // fminnm d15, d16, d17
    executor.Step().unwrap();
    assert_eq!(
        u64::from_le_bytes(executor.Cpu().V(15).unwrap()[..8].try_into().unwrap()),
        (-7.0_f64).to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF0C,
        ..Default::default()
    };
    cpu.SetV(19, &(2.0_f32).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(20, &(3.0_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E34_8A72, cpu, &[]); // fnmul s18, s19, s20
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(18).unwrap()[..4].try_into().unwrap()),
        (-6.0_f32).to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF10,
        ..Default::default()
    };
    cpu.SetV(0, &(1.0_f64).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(1, &(2.0_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E61_2000, cpu, &[]); // fcmp d0, d1
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().nzcv, 0x8000_0000);

    let mut cpu = CpuState {
        pc: 0xCF14,
        ..Default::default()
    };
    cpu.SetV(2, &f32::NAN.to_bits().to_le_bytes()).unwrap();
    cpu.SetV(3, &(1.0_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E23_2050, cpu, &[]); // fcmpe s2, s3
    executor.Step().unwrap();
    assert_eq!(executor.Cpu().nzcv, 0x3000_0000);

    let mut cpu = CpuState {
        pc: 0xCF18,
        nzcv: 0x4000_0000,
        ..Default::default()
    };
    cpu.SetV(5, &(3.5_f64).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(6, &(7.25_f64).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E66_0CA4, cpu, &[]); // fcsel d4, d5, d6, eq
    executor.Step().unwrap();
    assert_eq!(
        u64::from_le_bytes(executor.Cpu().V(4).unwrap()[..8].try_into().unwrap()),
        3.5_f64.to_bits()
    );

    let mut cpu = CpuState {
        pc: 0xCF1C,
        nzcv: 0,
        ..Default::default()
    };
    cpu.SetV(8, &(11.5_f32).to_bits().to_le_bytes()).unwrap();
    cpu.SetV(9, &(13.5_f32).to_bits().to_le_bytes()).unwrap();
    let mut executor = RunWord(0x1E29_4D07, cpu, &[]); // fcsel s7, s8, s9, mi
    executor.Step().unwrap();
    assert_eq!(
        u32::from_le_bytes(executor.Cpu().V(7).unwrap()[..4].try_into().unwrap()),
        13.5_f32.to_bits()
    );
}

#[test]
fn ExternalSystemRegisterReadsUseTheTypedServiceBoundary() {
    let cases: [(u32, usize, SystemRegister, u64); 4] = [
        (0xD53B_0028, 8, SystemRegister::CtrEl0, 0x8444_C004),
        (0xD53B_E048, 8, SystemRegister::CntvctEl0, 0x1234_5678),
        (0xD53B_D049, 9, SystemRegister::TpidrEl0, 0x7100_2000),
        (0xD53B_E008, 8, SystemRegister::CntfrqEl0, 19_200_000),
    ];

    for (word, destination, register, value) in cases {
        let cpu = CpuState {
            pc: 0xCE10,
            ..Default::default()
        };
        let mut memory = GuestMemory::New(FixtureTarget, 1);
        memory.MapBytes(cpu.pc, &word.to_le_bytes()).unwrap();
        let service = ExpectedSystemRegister {
            register,
            value,
            write: false,
        };
        let mut executor =
            Executor::NewWithSystemRegisters(cpu, memory, FixturePAuth::default(), service, 77)
                .unwrap();

        executor.Step().unwrap();

        assert_eq!(executor.Cpu().X(destination).unwrap(), value);
    }
}

#[test]
fn ExternalSystemRegisterWritesUseTheTypedServiceBoundary() {
    let mut cpu = CpuState {
        pc: 0xCE14,
        ..Default::default()
    };
    cpu.SetX(9, 0x7100_3000).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 1);
    memory
        .MapBytes(cpu.pc, &0xD51B_D049_u32.to_le_bytes())
        .unwrap(); // msr tpidr_el0, x9
    let service = ExpectedSystemRegister {
        register: SystemRegister::TpidrEl0,
        value: 0x7100_3000,
        write: true,
    };
    let mut executor =
        Executor::NewWithSystemRegisters(cpu, memory, FixturePAuth::default(), service, 77)
            .unwrap();

    executor.Step().unwrap();
}

#[test]
fn DefaultSystemRegisterServiceRejectsKnownRegistersWithoutCommittingPc() {
    let cpu = CpuState {
        pc: 0xCE18,
        ..Default::default()
    };
    let mut executor = RunWord(0xD53B_0028, cpu, &[]); // mrs x8, ctr_el0

    let error = executor.Step().unwrap_err();

    assert!(matches!(error, ExecutionError::SystemRegister { .. }));
    assert_eq!(executor.Cpu().pc, 0xCE18);
    assert_eq!(executor.Cpu().X(8).unwrap(), 0);
}

#[test]
fn UnknownSystemRegistersRemainUnsupported() {
    let cpu = CpuState {
        pc: 0xCE1C,
        ..Default::default()
    };
    let mut executor = RunWord(0xD53B_D060, cpu, &[]); // mrs x0, tpidrro_el0

    let error = executor.Step().unwrap_err();

    assert!(matches!(error, ExecutionError::Unsupported { .. }));
    assert_eq!(executor.Cpu().pc, 0xCE1C);
}
