#![allow(non_snake_case)]

use std::sync::{Arc, Mutex};

use espframe::monarch::memory::{GuestMemory, MemoryError, TargetMemory};

type ReadLog = Arc<Mutex<Vec<(u64, usize, bool)>>>;

#[derive(Clone)]
struct CountingTarget {
    bytes: Arc<Vec<u8>>,
    base: u64,
    reads: ReadLog,
}

#[derive(Clone)]
struct FailSecondPageTarget;

impl TargetMemory for FailSecondPageTarget {
    fn Read(
        &self,
        _pid: i32,
        address: u64,
        output: &mut [u8],
        _cached: bool,
    ) -> Result<(), MemoryError> {
        if address >= 0x8000 {
            return Err(MemoryError::Target("second page unavailable".to_owned()));
        }
        output.fill(0);
        Ok(())
    }
}

impl TargetMemory for CountingTarget {
    fn Read(
        &self,
        _pid: i32,
        address: u64,
        output: &mut [u8],
        cached: bool,
    ) -> Result<(), MemoryError> {
        self.reads
            .lock()
            .unwrap()
            .push((address, output.len(), cached));
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::Unmapped)? as usize;
        let end = offset
            .checked_add(output.len())
            .ok_or(MemoryError::AddressOverflow)?;
        let source = self.bytes.get(offset..end).ok_or(MemoryError::Unmapped)?;
        output.copy_from_slice(source);
        Ok(())
    }
}

fn Target() -> (CountingTarget, ReadLog) {
    let reads = Arc::new(Mutex::new(Vec::new()));
    (
        CountingTarget {
            bytes: Arc::new(vec![0; 0x3000]),
            base: 0x7000,
            reads: Arc::clone(&reads),
        },
        reads,
    )
}

#[test]
fn RollbackRestoresCowPages() {
    let (target, reads) = Target();
    let mut memory = GuestMemory::New(target, 11);
    let checkpoint = memory.Checkpoint();

    memory.Write(0x7100, &[1, 2, 3, 4], 0x7200).unwrap();
    assert_eq!(memory.ReadVec(0x7100, 4).unwrap(), vec![1, 2, 3, 4]);
    memory.Rollback(checkpoint).unwrap();

    assert_eq!(memory.ReadVec(0x7100, 4).unwrap(), vec![0, 0, 0, 0]);
    assert_eq!(memory.Writes().len(), 0);
    assert_eq!(
        reads.lock().unwrap().len(),
        1,
        "page snapshot is shared by COW"
    );
}

#[test]
fn OverlappingPublicationWritesRecordPcAndByteMask() {
    let (target, _) = Target();
    let mut memory = GuestMemory::New(target, 11);
    memory.SetPublicationSlot(0x7200);

    memory
        .Write(0x71FE, &[0xAA, 0xBB, 1, 2, 3, 4], 0x4568)
        .unwrap();
    memory.Write(0x7206, &[5, 6, 0xCC], 0x4570).unwrap();

    let writes = memory.PublicationWrites();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].pc, 0x4568);
    assert_eq!(writes[0].address, 0x71FE);
    assert_eq!(writes[0].slot_mask, 0b0000_1111);
    assert_eq!(writes[1].pc, 0x4570);
    assert_eq!(writes[1].slot_mask, 0b1100_0000);
}

#[test]
fn InvalidBoundsFailBeforeTargetAccess() {
    let (target, reads) = Target();
    let mut memory = GuestMemory::New(target, 11);

    assert_eq!(
        memory.ReadVec(u64::MAX - 1, 4).unwrap_err(),
        MemoryError::AddressOverflow
    );
    assert_eq!(
        memory.Write(u64::MAX, &[1, 2], 0x1000).unwrap_err(),
        MemoryError::AddressOverflow
    );
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn CrossPageWritePreservesUntouchedTargetBytes() {
    let (target, reads) = Target();
    let mut memory = GuestMemory::New(target, 11);
    memory.Write(0x7FFE, &[1, 2, 3, 4], 0x2000).unwrap();

    assert_eq!(
        memory.ReadVec(0x7FFC, 8).unwrap(),
        vec![0, 0, 1, 2, 3, 4, 0, 0]
    );
    assert_eq!(reads.lock().unwrap().len(), 2);
}

#[test]
fn CrossPageWriteIsAtomicWhenLaterPageReadFails() {
    let mut memory = GuestMemory::New(FailSecondPageTarget, 11);

    let error = memory.Write(0x7FFE, &[1, 2, 3, 4], 0x2000).unwrap_err();

    assert_eq!(
        error,
        MemoryError::Target("second page unavailable".to_owned())
    );
    assert!(memory.Writes().is_empty());
    assert!(memory.PublicationWrites().is_empty());
    assert_eq!(memory.ReadVec(0x7FFE, 2).unwrap(), vec![0, 0]);
}
