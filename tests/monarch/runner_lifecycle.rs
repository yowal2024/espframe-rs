#![allow(non_snake_case)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use espframe::monarch::arm64::{
    CpuState, ExclusiveMonitorState, Executor, PAuthOperation, PAuthResult, PAuthService,
};
use espframe::monarch::memory::{GuestMemory, MemoryError, TargetMemory};
use espframe::monarch::runner::{
    AddressRange, HookResult, Monarch, NoKernelServices, ObserverPhase, RunOptions, StopReason,
};
use espframe::monarch::services::{GuestServices, KernelServices, ServiceConfig, SyncsourcePeek};

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
    ) -> Result<PAuthResult, espframe::monarch::arm64::ServiceError> {
        Ok(PAuthResult {
            value,
            ioctl_result: 0,
        })
    }
}

#[derive(Clone, Default)]
struct FixtureKernel;

impl KernelServices for FixtureKernel {
    fn ValidateKgslFd(&self, _pid: i32, _fd: u32) -> bool {
        false
    }

    fn PeekKgslSyncsourceId(
        &self,
        _pid: i32,
        _fd: u32,
        _min_id: u32,
    ) -> Result<u32, espframe::monarch::services::ServiceError> {
        Ok(0)
    }

    fn PeekKgslSyncsourceIdChecked(
        &self,
        _pid: i32,
        _fd: u32,
        _min_id: u32,
    ) -> Result<SyncsourcePeek, espframe::monarch::services::ServiceError> {
        Ok(SyncsourcePeek { id: 0, backend: 0 })
    }

    fn GpuobjIoctl(
        &self,
        _pid: i32,
        _fd: u32,
        _request: u64,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<i64, espframe::monarch::services::ServiceError> {
        Ok(0)
    }
}

fn MapWords(memory: &mut GuestMemory<FixtureTarget>, base: u64, words: &[u32]) {
    for (index, word) in words.iter().enumerate() {
        memory
            .MapBytes(base + (index as u64) * 4, &word.to_le_bytes())
            .unwrap();
    }
}

fn BuildMonarch(
    words: &[u32],
    pc: u64,
) -> Monarch<
    FixtureTarget,
    FixturePAuth,
    espframe::monarch::arm64::RejectSystemRegisterService,
    NoKernelServices,
> {
    let cpu = CpuState {
        pc,
        ..Default::default()
    };
    let mut memory = GuestMemory::New(FixtureTarget, 7);
    MapWords(&mut memory, pc, words);
    let executor = Executor::New(cpu, memory, FixturePAuth, 11).unwrap();
    Monarch::New(executor).unwrap()
}

#[test]
fn RunCompletesAtStopAddressBeforeFetching() {
    let mut monarch = BuildMonarch(&[], 0x4000);

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x4000),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 0);
    assert_eq!(result.pc, 0x4000);
}

#[test]
fn RunStopsAtInstructionLimitAndKeepsTraceRing() {
    let mut monarch = BuildMonarch(&[0xD503_201F, 0xD503_201F, 0xD503_201F], 0x5000);

    let result = monarch.Run(RunOptions {
        instruction_limit: 2,
        trace_limit: 1,
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::InstructionLimit);
    assert_eq!(result.instruction_count, 2);
    assert_eq!(result.pc, 0x5008);
    assert_eq!(result.trace.len(), 1);
    assert_eq!(result.trace[0].pc, 0x5004);
    assert_eq!(result.trace[0].raw, 0xD503_201F);
}

#[test]
fn RunCanRedirectPcFromBeforeObserver() {
    let mut monarch = BuildMonarch(&[0xD503_201F], 0x6000);
    monarch.SetObserver(
        Box::new(|state, info| {
            if info.phase == ObserverPhase::Before && info.pc == 0x6000 {
                state.pc = 0x7000;
            }
            HookResult::Handled(0)
        }),
        true,
    );

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x7000),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 0);
    assert_eq!(result.pc, 0x7000);
}

#[test]
fn RunCallsObserverAfterExecution() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let mut monarch = BuildMonarch(&[0xD503_201F], 0x6100);
    monarch.SetObserver(
        Box::new(move |_state, info| {
            captured
                .lock()
                .unwrap()
                .push((info.phase, info.pc, info.instruction_count));
            HookResult::Handled(0)
        }),
        true,
    );

    let result = monarch.Run(RunOptions {
        instruction_limit: 1,
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::InstructionLimit);
    assert_eq!(
        &*seen.lock().unwrap(),
        &[
            (ObserverPhase::Before, 0x6100, 0),
            (ObserverPhase::After, 0x6100, 1),
        ]
    );
}

#[test]
fn RunAppliesCallHookReturnSemantics() {
    let mut monarch = BuildMonarch(&[0x9400_0004], 0x6200); // bl 0x6210
    monarch.AddCallHook(
        AddressRange::Single(0x6210),
        Box::new(|_state, info| {
            assert_eq!(info.source_pc, 0x6200);
            assert_eq!(info.target, 0x6210);
            assert_eq!(info.return_address, 0x6204);
            assert!(!info.indirect);
            HookResult::Return(77)
        }),
    );

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6204),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 77);
    assert_eq!(monarch.Executor().Cpu().X(30).unwrap(), 0x6204);
    assert_eq!(result.pc, 0x6204);
}

#[test]
fn RunNormalizesIndirectCallTargetsBeforeDispatchingHooks() {
    fn NormalizeAddress(value: u64) -> u64 {
        value & !0xfff
    }

    let mut monarch = BuildMonarch(&[0xD63F_0040], 0x6220); // blr x2
    monarch.ExecutorMut().CpuMut().SetX(2, 0x7ABC).unwrap();
    monarch.SetAddressNormalizer(NormalizeAddress);
    monarch.AddCallHook(
        AddressRange::Single(0x7000),
        Box::new(|_state, info| {
            assert_eq!(info.target, 0x7000);
            assert!(info.indirect);
            HookResult::Return(99)
        }),
    );

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6224),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 99);
    assert_eq!(monarch.Executor().Cpu().X(30).unwrap(), 0x6224);
}

#[test]
fn RunDispatchesAuthenticatedCallsThroughCallHooks() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let mut monarch = BuildMonarch(&[0xD73F_0801], 0x6240); // blraa x0, x1
    monarch.ExecutorMut().CpuMut().SetX(0, 0x7100).unwrap();
    monarch.ExecutorMut().CpuMut().SetX(1, 0x2222).unwrap();
    monarch.AddCallHook(
        AddressRange::Single(0x7100),
        Box::new(move |_state, info| {
            captured.lock().unwrap().push(*info);
            HookResult::Return(123)
        }),
    );

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6244),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 123);
    assert_eq!(monarch.Executor().Cpu().X(30).unwrap(), 0x6244);
    assert_eq!(
        &*seen.lock().unwrap(),
        &[espframe::monarch::runner::CallInfo {
            source_pc: 0x6240,
            target: 0x7100,
            return_address: 0x6244,
            indirect: true,
        }]
    );
}

#[test]
fn RunDispatchesSvcThroughGuestServices() {
    let mut cpu = CpuState {
        pc: 0x6300,
        ..Default::default()
    };
    cpu.SetX(8, 172).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 23);
    memory
        .MapBytes(0x6300, &0xD400_0001_u32.to_le_bytes())
        .unwrap();
    let executor = Executor::New(cpu, memory, FixturePAuth, 31).unwrap();
    let services = GuestServices::New(
        FixtureKernel,
        ServiceConfig {
            pid: 4321,
            tid: 31,
            ..Default::default()
        },
    );
    let mut monarch = Monarch::NewWithServices(executor, services).unwrap();

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6304),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(result.pc, 0x6304);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 4321_u64);
}

#[test]
fn RunHandlesSvcThroughExplicitHook() {
    let mut cpu = CpuState {
        pc: 0x6320,
        ..Default::default()
    };
    cpu.SetX(8, 172).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 23);
    memory
        .MapBytes(0x6320, &0xD400_0001_u32.to_le_bytes())
        .unwrap();
    let executor = Executor::New(cpu, memory, FixturePAuth, 31).unwrap();
    let mut monarch = Monarch::New(executor).unwrap();
    monarch.SetSyscallHook(Box::new(|_state, info| {
        assert_eq!(info.pc, 0x6320);
        assert_eq!(info.immediate, 0);
        assert_eq!(info.number, 172);
        HookResult::Handled(55)
    }));

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6324),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 55);
    assert_eq!(result.pc, 0x6324);
}

#[test]
fn RunPresentsSvcHookWithFaultingPcAndAdvancesAfterContinue() {
    let mut cpu = CpuState {
        pc: 0x6340,
        ..Default::default()
    };
    cpu.SetX(8, 172).unwrap();
    let mut memory = GuestMemory::New(FixtureTarget, 23);
    memory
        .MapBytes(0x6340, &0xD400_0001_u32.to_le_bytes())
        .unwrap();
    let executor = Executor::New(cpu, memory, FixturePAuth, 31).unwrap();
    let mut monarch = Monarch::New(executor).unwrap();
    monarch.SetSyscallHook(Box::new(|state, info| {
        assert_eq!(info.pc, 0x6340);
        assert_eq!(state.pc, 0x6340);
        state.pc = 0x9000;
        HookResult::Handled(66)
    }));

    let result = monarch.Run(RunOptions {
        stop_address: Some(0x6344),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.instruction_count, 1);
    assert_eq!(monarch.Executor().Cpu().X(0).unwrap(), 66);
    assert_eq!(monarch.Executor().Cpu().pc, 0x6344);
}

#[test]
fn RunStopsWhenCancelledBeforeExecution() {
    let mut monarch = BuildMonarch(&[], 0x6400);
    monarch.SetCancelCallback(Box::new(|| true));

    let result = monarch.Run(RunOptions::default());

    assert_eq!(result.stop_reason, StopReason::Cancelled);
    assert_eq!(result.instruction_count, 0);
    assert_eq!(result.pc, 0x6400);
}

#[test]
fn RunStopsOnWallClockLimit() {
    let mut monarch = BuildMonarch(&[0x1400_0000], 0x6500); // b .

    let result = monarch.Run(RunOptions {
        instruction_limit: 0,
        wall_clock_limit: Duration::from_millis(1),
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::WallClockLimit);
    assert!(result.instruction_count > 0);
    assert_eq!(result.pc, 0x6500);
}

#[test]
fn SaveRestoreAndResetRoundTripCpuState() {
    let mut monarch = BuildMonarch(&[0xD503_201F], 0x6600);
    monarch.ExecutorMut().CpuMut().SetX(3, 0xAAAA).unwrap();
    let saved = monarch.SaveContext();
    monarch.ExecutorMut().CpuMut().SetX(3, 0xBBBB).unwrap();
    monarch.ExecutorMut().CpuMut().pc = 0x7777;

    monarch.RestoreContext(&saved);
    assert_eq!(monarch.Executor().Cpu().X(3).unwrap(), 0xAAAA);
    assert_eq!(monarch.Executor().Cpu().pc, 0x6600);

    monarch.Reset();
    assert_eq!(monarch.Executor().Cpu(), &CpuState::default());
}

#[test]
fn SaveRestoreAndResetPreserveExclusiveMonitorState() {
    let mut monarch = BuildMonarch(&[0xD503_201F], 0x6680);
    let monitor = ExclusiveMonitorState {
        address: 0x9000,
        size: 16,
    };
    monarch.ExecutorMut().SetExclusiveMonitor(Some(monitor));

    let saved = monarch.SaveContext();
    monarch.ExecutorMut().SetExclusiveMonitor(None);
    monarch.RestoreContext(&saved);

    assert_eq!(monarch.Executor().ExclusiveMonitor(), Some(monitor));

    monarch.Reset();
    assert_eq!(monarch.Executor().ExclusiveMonitor(), None);
}

#[test]
fn DecodeCacheInvalidationApisAreNoOpsForUncachedDecoder() {
    let mut monarch = BuildMonarch(&[0xD503_201F], 0x6700);

    monarch.InvalidateDecodeCache(0x6700);
    monarch.ClearDecodeCache();

    let result = monarch.Run(RunOptions {
        instruction_limit: 1,
        ..Default::default()
    });

    assert_eq!(result.stop_reason, StopReason::InstructionLimit);
    assert_eq!(result.instruction_count, 1);
}
