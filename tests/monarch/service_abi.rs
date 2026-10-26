#![allow(non_snake_case)]

use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;

use espframe::monarch::arm64::{
    CpuState, Executor, PAuthOperation, PAuthResult, PAuthService, ServiceError as PAuthError,
    StepOutcome, SystemRegister, SystemRegisterService,
};
use espframe::monarch::memory::{GuestMemory, MemoryError, TargetMemory};
use espframe::monarch::services::{
    GuestServices, KernelCall, KernelServices, ReviewedSystemRegisterService, ServiceConfig,
    ServiceError, SyncsourcePeek, VirtualKgslObject,
};
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
struct FixturePAuth;

impl PAuthService for FixturePAuth {
    fn Process(
        &self,
        _tid: i32,
        _operation: PAuthOperation,
        value: u64,
        _modifier: u64,
    ) -> Result<PAuthResult, PAuthError> {
        Ok(PAuthResult {
            value,
            ioctl_result: 0,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema: String,
    provenance: Provenance,
    cases: Vec<ServiceCase>,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    kind: String,
    source: String,
    current_device_evidence: bool,
}

#[derive(Debug, Deserialize)]
struct ServiceCase {
    name: String,
    before: State,
    kernel: KernelFixture,
    after: ExpectedState,
    #[serde(default)]
    ioctl: Option<IoctlFixture>,
    #[serde(default)]
    dispatch_error: String,
    #[serde(default)]
    dispatch_error_backend: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct IoctlFixture {
    request: u32,
    #[serde(rename = "type")]
    ioctl_type: u8,
    number: u8,
    direction: u8,
    size: u16,
}

#[derive(Debug, Deserialize)]
struct State {
    x: [u64; 6],
    x8: u64,
    nzcv: u32,
    pc: u64,
    exception_ticks: u64,
    exclusive_state: String,
    memory: Vec<MemoryBytes>,
    virtual_syncsources: Vec<u32>,
    virtual_objects: Vec<ExpectedObject>,
    #[serde(default)]
    publication_slot: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ExpectedState {
    x: [u64; 6],
    x8: u64,
    nzcv: u32,
    pc: u64,
    exception_ticks: u64,
    exclusive_state: String,
    memory_diff: Vec<ExpectedWrite>,
    virtual_syncsources: Vec<u32>,
    virtual_objects: Vec<ExpectedObject>,
    kernel_calls: Vec<KernelCall>,
}

#[derive(Debug, Deserialize)]
struct MemoryBytes {
    address: u64,
    #[serde(default)]
    bytes: String,
    #[serde(default)]
    fill: Option<u8>,
    #[serde(default)]
    size: Option<usize>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedWrite {
    pc: u64,
    address: u64,
    bytes: String,
    slot_mask: u8,
    provenance: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct ExpectedObject {
    fd: u32,
    id: u32,
    gpuaddr: u64,
    size: u64,
    va_len: u64,
    va_addr: u64,
    memtype_override: Option<u8>,
    metadata: String,
}

impl From<ExpectedObject> for VirtualKgslObject {
    fn from(value: ExpectedObject) -> Self {
        Self {
            fd: value.fd,
            id: value.id,
            gpuaddr: value.gpuaddr,
            size: value.size,
            va_len: value.va_len,
            va_addr: value.va_addr,
            memtype_override: value.memtype_override,
            metadata: hex::decode(value.metadata).unwrap(),
        }
    }
}

impl From<VirtualKgslObject> for ExpectedObject {
    fn from(value: VirtualKgslObject) -> Self {
        Self {
            fd: value.fd,
            id: value.id,
            gpuaddr: value.gpuaddr,
            size: value.size,
            va_len: value.va_len,
            va_addr: value.va_addr,
            memtype_override: value.memtype_override,
            metadata: hex::encode(value.metadata),
        }
    }
}

#[derive(Debug, Deserialize)]
struct KernelFixture {
    valid_fds: Vec<u32>,
    #[serde(default)]
    validation_errors: Vec<ValidationFixture>,
    peek: Vec<PeekFixture>,
    gpuobj: Vec<GpuobjFixture>,
}

#[derive(Debug, Deserialize)]
struct ValidationFixture {
    fd: u32,
    result: KernelResult,
}

#[derive(Debug, Deserialize)]
struct PeekFixture {
    fd: u32,
    min_id: u32,
    result: KernelResult,
}

#[derive(Debug, Deserialize)]
struct GpuobjFixture {
    fd: u32,
    request: u64,
    result: KernelResult,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum KernelResult {
    Ok {
        value: i64,
        #[serde(default)]
        output: String,
        #[serde(default)]
        backend: u32,
    },
    GuestErrno {
        errno: i32,
        #[serde(default)]
        backend: u32,
    },
    Infrastructure {
        errno: i32,
        #[serde(default)]
        backend: u32,
    },
}

struct FixtureKernel {
    valid_fds: BTreeSet<u32>,
    validation_errors: Vec<ValidationFixture>,
    peek: Mutex<VecDeque<PeekFixture>>,
    gpuobj: Vec<GpuobjFixture>,
}

impl FixtureKernel {
    fn New(fixture: KernelFixture) -> Self {
        Self {
            valid_fds: fixture.valid_fds.into_iter().collect(),
            validation_errors: fixture.validation_errors,
            peek: Mutex::new(fixture.peek.into()),
            gpuobj: fixture.gpuobj,
        }
    }
}

impl KernelServices for FixtureKernel {
    fn ValidateKgslFd(&self, pid: i32, fd: u32) -> bool {
        let _ = pid;
        self.valid_fds.contains(&fd)
    }

    fn ValidateKgslFdChecked(&self, pid: i32, fd: u32) -> Result<bool, ServiceError> {
        if let Some(fixture) = self.validation_errors.iter().find(|entry| entry.fd == fd) {
            return KernelResultToService(&fixture.result).map(|(value, _)| value != 0);
        }
        Ok(self.ValidateKgslFd(pid, fd))
    }

    fn PeekKgslSyncsourceId(&self, pid: i32, fd: u32, min_id: u32) -> Result<u32, ServiceError> {
        self.NextPeek(pid, fd, min_id).map(|peek| peek.id)
    }

    fn PeekKgslSyncsourceIdChecked(
        &self,
        pid: i32,
        fd: u32,
        min_id: u32,
    ) -> Result<SyncsourcePeek, ServiceError> {
        self.NextPeek(pid, fd, min_id)
    }

    fn GpuobjIoctl(
        &self,
        pid: i32,
        fd: u32,
        request: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<i64, ServiceError> {
        let fixture = self
            .gpuobj
            .iter()
            .find(|entry| entry.fd == fd && entry.request == request)
            .unwrap_or_else(|| panic!("missing gpuobj fixture fd={fd} request=0x{request:X}"));
        let _ = pid;
        let result = KernelResultToService(&fixture.result);
        if let KernelResult::Ok { output: bytes, .. } = &fixture.result {
            let decoded = hex::decode(bytes).unwrap();
            output[..decoded.len()].copy_from_slice(&decoded);
        }
        let _ = input;
        result.map(|(value, _)| value)
    }
}

impl FixtureKernel {
    fn NextPeek(&self, pid: i32, fd: u32, min_id: u32) -> Result<SyncsourcePeek, ServiceError> {
        let fixture = self
            .peek
            .lock()
            .expect("peek fixture lock")
            .pop_front()
            .unwrap_or_else(|| panic!("missing peek fixture fd={fd} min_id={min_id}"));
        assert_eq!(fixture.fd, fd, "peek fd sequence");
        assert_eq!(fixture.min_id, min_id, "peek min_id sequence");
        let _ = pid;
        KernelResultToService(&fixture.result).map(|(value, backend)| SyncsourcePeek {
            id: value as u32,
            backend,
        })
    }
}

fn KernelResultToService(result: &KernelResult) -> Result<(i64, u32), ServiceError> {
    match result {
        KernelResult::Ok { value, backend, .. } => Ok((*value, *backend)),
        KernelResult::GuestErrno { errno, backend } => {
            Err(ServiceError::GuestErrnoWithBackend(*errno, *backend))
        }
        KernelResult::Infrastructure { errno, backend } => Err(ServiceError::Infrastructure {
            operation: "fixture".to_owned(),
            errno: *errno,
            backend: *backend,
        }),
    }
}

#[test]
fn SvcTranscriptsMatchCpuCopyoutVirtualStateAndKernelCalls() {
    let fixture: Fixture =
        serde_json::from_slice(include_bytes!("../fixtures/monarch/service-abi-v1.json")).unwrap();
    assert_eq!(fixture.schema, "delta-monarch-service-abi-v1");
    assert_eq!(fixture.provenance.kind, "synthetic-cpp-parity");
    assert!(fixture.provenance.source.contains("guest_services.cpp"));
    assert!(!fixture.provenance.current_device_evidence);

    for case in fixture.cases {
        assert!(matches!(case.before.exclusive_state.as_str(), "none"));
        let mut cpu = CpuState {
            pc: case.before.pc,
            nzcv: case.before.nzcv,
            ..Default::default()
        };
        for (index, value) in case.before.x.iter().enumerate() {
            cpu.SetX(index, *value).unwrap();
        }
        cpu.SetX(8, case.before.x8).unwrap();
        if let Some(ioctl) = &case.ioctl {
            let decoded = espframe::monarch::services::IoctlRequest::Decode(ioctl.request);
            assert_eq!(decoded.raw, ioctl.request, "{} request", case.name);
            assert_eq!(decoded.ioctl_type, ioctl.ioctl_type, "{} type", case.name);
            assert_eq!(decoded.number, ioctl.number, "{} number", case.name);
            assert_eq!(
                decoded.direction, ioctl.direction,
                "{} direction",
                case.name
            );
            assert_eq!(decoded.size, ioctl.size, "{} size", case.name);
        }
        let mut memory = GuestMemory::New(FixtureTarget, 4242);
        if let Some(slot) = case.before.publication_slot {
            memory.SetPublicationSlot(slot);
        }
        memory
            .MapBytes(case.before.pc, &0xD400_0001_u32.to_le_bytes())
            .unwrap();
        for region in &case.before.memory {
            let bytes = match (region.fill, region.size) {
                (Some(fill), Some(size)) if region.bytes.is_empty() => vec![fill; size],
                (None, None) => hex::decode(&region.bytes).unwrap(),
                _ => panic!("{} invalid memory fixture", case.name),
            };
            memory.MapBytes(region.address, &bytes).unwrap();
        }
        let kernel = FixtureKernel::New(case.kernel);
        let mut services = GuestServices::New(
            kernel,
            ServiceConfig {
                pid: 4242,
                tid: 77,
                default_exception_ticks: 1,
                getpid_exception_ticks: 11,
                ioctl_exception_ticks: 13,
            },
        );
        services.SetExceptionTicks(case.before.exception_ticks);
        services.SeedVirtualSyncsources(&case.before.virtual_syncsources);
        services.SeedVirtualObjects(case.before.virtual_objects.iter().cloned().map(Into::into));
        let mut executor = Executor::New(cpu, memory, FixturePAuth, 77).unwrap();
        assert_eq!(executor.Step().unwrap(), StepOutcome::Svc, "{}", case.name);

        let result = services.DispatchSvc(&mut executor);
        assert_eq!(
            result.is_err(),
            !case.dispatch_error.is_empty(),
            "{}",
            case.name
        );
        if let Some(backend) = case.dispatch_error_backend {
            assert_eq!(
                result.as_ref().unwrap_err().Backend(),
                backend,
                "{} error backend",
                case.name
            );
        }
        for (index, value) in case.after.x.iter().enumerate() {
            assert_eq!(
                executor.Cpu().X(index).unwrap(),
                *value,
                "{} X{index}",
                case.name
            );
        }
        assert_eq!(
            executor.Cpu().X(8).unwrap(),
            case.after.x8,
            "{} X8",
            case.name
        );
        assert_eq!(executor.Cpu().nzcv, case.after.nzcv, "{} NZCV", case.name);
        assert_eq!(executor.Cpu().pc, case.after.pc, "{} PC", case.name);
        assert_eq!(
            services.ExceptionTicks(),
            case.after.exception_ticks,
            "{} ticks",
            case.name
        );
        assert_eq!(
            case.after.exclusive_state, "cleared",
            "{} schema",
            case.name
        );
        let writes: Vec<ExpectedWrite> = services
            .MemoryDiff()
            .iter()
            .map(|write| ExpectedWrite {
                pc: write.pc,
                address: write.address,
                bytes: hex::encode(&write.bytes),
                slot_mask: write.slot_mask,
                provenance: write.provenance.Name().to_owned(),
            })
            .collect();
        assert_eq!(writes, case.after.memory_diff, "{} memory", case.name);
        assert_eq!(
            services.MemoryDiff().len(),
            executor.Memory().Writes().len()
        );
        assert_eq!(
            services.VirtualSyncsources(),
            case.after.virtual_syncsources.as_slice(),
            "{} syncsources",
            case.name
        );
        let objects: Vec<ExpectedObject> = services
            .VirtualObjects()
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        assert_eq!(objects, case.after.virtual_objects, "{} objects", case.name);
        assert_eq!(
            services.KernelCalls(),
            case.after.kernel_calls,
            "{} calls",
            case.name
        );
    }
}

#[test]
fn GettidSvcOwnsPcAdvanceAndClearsTheExclusiveMonitor() {
    let mut cpu = CpuState {
        pc: 0x7000,
        ..Default::default()
    };
    cpu.SetX(0, 0x8000).unwrap();
    cpu.SetX(1, 99).unwrap();
    cpu.SetX(8, 178).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 4242);
    memory
        .MapBytes(0x7000, &0xC85F_7C02_u32.to_le_bytes())
        .unwrap(); // ldxr x2, [x0]
    memory
        .MapBytes(0x7004, &0xD400_0001_u32.to_le_bytes())
        .unwrap(); // svc #0
    memory
        .MapBytes(0x7008, &0xC803_7C01_u32.to_le_bytes())
        .unwrap(); // stxr w3, x1, [x0]
    memory.MapBytes(0x8000, &41_u64.to_le_bytes()).unwrap();
    let mut executor = Executor::New(cpu, memory, FixturePAuth, 77).unwrap();
    let mut services = GuestServices::New(
        FixtureKernel::New(KernelFixture {
            valid_fds: vec![],
            validation_errors: vec![],
            peek: vec![],
            gpuobj: vec![],
        }),
        ServiceConfig {
            pid: 4242,
            tid: 77,
            ..Default::default()
        },
    );

    assert_eq!(executor.Step().unwrap(), StepOutcome::Continue);
    assert_eq!(executor.Step().unwrap(), StepOutcome::Svc);
    assert_eq!(executor.Cpu().pc, 0x7008);
    services.DispatchSvc(&mut executor).unwrap();
    assert_eq!(executor.Cpu().pc, 0x7008, "handled SVC must not skip STXR");
    assert_eq!(executor.Cpu().X(0).unwrap(), 77);
    executor.CpuMut().SetX(0, 0x8000).unwrap();
    executor.Step().unwrap();

    assert_eq!(executor.Cpu().X(3).unwrap(), 1);
    assert_eq!(
        executor.MemoryMut().ReadVec(0x8000, 8).unwrap(),
        41_u64.to_le_bytes()
    );
}

#[test]
fn ServiceTransactionsRollbackVirtualSyncsourcesAndObjects() {
    let mut services = GuestServices::New(
        FixtureKernel::New(KernelFixture {
            valid_fds: vec![],
            validation_errors: vec![],
            peek: vec![],
            gpuobj: vec![],
        }),
        ServiceConfig::default(),
    );
    services.SeedVirtualSyncsources(&[2, 3]);
    services.SeedVirtualObjects([VirtualKgslObject {
        fd: 697,
        id: 42,
        gpuaddr: 0x7100_001000,
        ..Default::default()
    }]);
    let checkpoint = services.Checkpoint();
    services.RemoveVirtualSyncsource(2).unwrap();
    services.SeedVirtualObjects([]);
    services.Rollback(checkpoint).unwrap();
    assert_eq!(services.VirtualSyncsources(), &[2, 3]);
    assert_eq!(services.VirtualObjects().len(), 1);
    assert_eq!(services.VirtualObjects()[0].id, 42);
}

#[test]
fn ReviewedSystemRegistersUseOnlyInjectedValues() {
    let service = ReviewedSystemRegisterService::New(0x8444_C004, 19_200_000, 0x7100_2000, 1000);
    assert_eq!(service.ReviewedValues().ctr_el0, 0x8444_C004);
    assert_eq!(service.ReviewedValues().cntfrq_el0, 19_200_000);
    assert_eq!(service.ReviewedValues().tpidr_el0, 0x7100_2000);
    assert_eq!(service.ReviewedValues().cntvct_base, 1000);
    assert_eq!(
        service.Read(77, SystemRegister::CtrEl0).unwrap(),
        0x8444_C004
    );
    assert_eq!(
        service.Read(77, SystemRegister::CntfrqEl0).unwrap(),
        19_200_000
    );
    assert_eq!(
        service.Read(77, SystemRegister::TpidrEl0).unwrap(),
        0x7100_2000
    );
    service.SetProgress(23, 13);
    assert_eq!(service.Read(77, SystemRegister::CntvctEl0).unwrap(), 1036);
    service.SetCounterScaling(true, 2_600_000_000);
    service.SetProgress(2600, 7);
    assert_eq!(service.Read(77, SystemRegister::CntvctEl0).unwrap(), 1026);
}
