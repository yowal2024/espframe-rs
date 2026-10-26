use std::collections::BTreeMap;
use std::sync::Arc;

const PAGE_SIZE: usize = 4096;
const MAX_ACCESS_SIZE: usize = 1024 * 1024;

pub trait TargetMemory: Send + Sync {
    fn Read(
        &self,
        pid: i32,
        address: u64,
        output: &mut [u8],
        cached: bool,
    ) -> Result<(), MemoryError>;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MemoryError {
    #[error("guest address range overflows")]
    AddressOverflow,
    #[error("guest access exceeds the maximum transaction size")]
    AccessTooLarge,
    #[error("guest address is unmapped")]
    Unmapped,
    #[error("target memory read failed: {0}")]
    Target(String),
    #[error("checkpoint does not belong to this memory transaction")]
    InvalidCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryWrite {
    pub pc: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub slot_mask: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationWrite {
    pub pc: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub slot_mask: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCheckpoint {
    id: u64,
}

#[derive(Clone)]
struct CowPage {
    original: Arc<Vec<u8>>,
    current: Arc<Vec<u8>>,
}

impl CowPage {
    fn New(bytes: Vec<u8>) -> Self {
        let original = Arc::new(bytes);
        Self {
            current: Arc::clone(&original),
            original,
        }
    }
}

struct CheckpointState {
    id: u64,
    pages: BTreeMap<u64, Arc<Vec<u8>>>,
    writes_len: usize,
    publication_writes_len: usize,
}

pub struct GuestMemory<M> {
    target: M,
    pid: i32,
    pages: BTreeMap<u64, CowPage>,
    writes: Vec<MemoryWrite>,
    publication_writes: Vec<PublicationWrite>,
    publication_slot: Option<u64>,
    checkpoints: Vec<CheckpointState>,
    next_checkpoint_id: u64,
}

impl<M: TargetMemory> GuestMemory<M> {
    pub fn New(target: M, pid: i32) -> Self {
        Self {
            target,
            pid,
            pages: BTreeMap::new(),
            writes: Vec::new(),
            publication_writes: Vec::new(),
            publication_slot: None,
            checkpoints: Vec::new(),
            next_checkpoint_id: 1,
        }
    }

    pub fn SetPublicationSlot(&mut self, address: u64) {
        self.publication_slot = Some(address);
    }

    pub fn ClearPublicationSlot(&mut self) {
        self.publication_slot = None;
    }

    pub fn Checkpoint(&mut self) -> MemoryCheckpoint {
        let id = self.next_checkpoint_id;
        self.next_checkpoint_id = self.next_checkpoint_id.wrapping_add(1).max(1);
        self.checkpoints.push(CheckpointState {
            id,
            pages: self
                .pages
                .iter()
                .map(|(address, page)| (*address, Arc::clone(&page.current)))
                .collect(),
            writes_len: self.writes.len(),
            publication_writes_len: self.publication_writes.len(),
        });
        MemoryCheckpoint { id }
    }

    pub fn Rollback(&mut self, checkpoint: MemoryCheckpoint) -> Result<(), MemoryError> {
        let index = self
            .checkpoints
            .iter()
            .position(|state| state.id == checkpoint.id)
            .ok_or(MemoryError::InvalidCheckpoint)?;
        let state = self.checkpoints.remove(index);
        self.checkpoints.truncate(index);
        for (address, page) in &mut self.pages {
            page.current = state
                .pages
                .get(address)
                .cloned()
                .unwrap_or_else(|| Arc::clone(&page.original));
        }
        self.writes.truncate(state.writes_len);
        self.publication_writes
            .truncate(state.publication_writes_len);
        Ok(())
    }

    pub fn Commit(&mut self, checkpoint: MemoryCheckpoint) -> Result<(), MemoryError> {
        let index = self
            .checkpoints
            .iter()
            .position(|state| state.id == checkpoint.id)
            .ok_or(MemoryError::InvalidCheckpoint)?;
        self.checkpoints.remove(index);
        Ok(())
    }

    pub fn MapBytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Self::ValidateRange(address, bytes.len())?;
        let mut cursor = address;
        let mut offset = 0;
        while offset < bytes.len() {
            let page_address = Self::PageAddress(cursor);
            let page_offset = (cursor - page_address) as usize;
            let count = (PAGE_SIZE - page_offset).min(bytes.len() - offset);
            let page = self
                .pages
                .entry(page_address)
                .or_insert_with(|| CowPage::New(vec![0; PAGE_SIZE]));
            Arc::make_mut(&mut page.current)[page_offset..page_offset + count]
                .copy_from_slice(&bytes[offset..offset + count]);
            page.original = Arc::clone(&page.current);
            cursor += count as u64;
            offset += count;
        }
        Ok(())
    }

    pub fn ReadVec(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        Self::ValidateRange(address, size)?;
        let mut output = vec![0; size];
        self.Read(address, &mut output)?;
        Ok(output)
    }

    pub fn Read(&mut self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        Self::ValidateRange(address, output.len())?;
        let mut cursor = address;
        let mut offset = 0;
        while offset < output.len() {
            let page_address = Self::PageAddress(cursor);
            self.EnsurePage(page_address)?;
            let page_offset = (cursor - page_address) as usize;
            let count = (PAGE_SIZE - page_offset).min(output.len() - offset);
            let page = self.pages.get(&page_address).ok_or(MemoryError::Unmapped)?;
            output[offset..offset + count]
                .copy_from_slice(&page.current[page_offset..page_offset + count]);
            cursor += count as u64;
            offset += count;
        }
        Ok(())
    }

    pub fn Write(&mut self, address: u64, bytes: &[u8], pc: u64) -> Result<(), MemoryError> {
        Self::ValidateRange(address, bytes.len())?;
        let mut cursor = address;
        let mut offset = 0;
        while offset < bytes.len() {
            let page_address = Self::PageAddress(cursor);
            self.EnsurePage(page_address)?;
            let page_offset = (cursor - page_address) as usize;
            let count = (PAGE_SIZE - page_offset).min(bytes.len() - offset);
            cursor += count as u64;
            offset += count;
        }

        cursor = address;
        offset = 0;
        while offset < bytes.len() {
            let page_address = Self::PageAddress(cursor);
            let page_offset = (cursor - page_address) as usize;
            let count = (PAGE_SIZE - page_offset).min(bytes.len() - offset);
            let page = self
                .pages
                .get_mut(&page_address)
                .ok_or(MemoryError::Unmapped)?;
            Arc::make_mut(&mut page.current)[page_offset..page_offset + count]
                .copy_from_slice(&bytes[offset..offset + count]);
            cursor += count as u64;
            offset += count;
        }

        let slot_mask = self.PublicationMask(address, bytes.len());
        let write = MemoryWrite {
            pc,
            address,
            bytes: bytes.to_vec(),
            slot_mask,
        };
        self.writes.push(write.clone());
        if slot_mask != 0 {
            self.publication_writes.push(PublicationWrite {
                pc,
                address,
                bytes: bytes.to_vec(),
                slot_mask,
            });
        }
        Ok(())
    }

    pub fn Writes(&self) -> &[MemoryWrite] {
        &self.writes
    }

    pub fn PublicationWrites(&self) -> &[PublicationWrite] {
        &self.publication_writes
    }

    fn EnsurePage(&mut self, page_address: u64) -> Result<(), MemoryError> {
        if self.pages.contains_key(&page_address) {
            return Ok(());
        }
        let mut bytes = vec![0; PAGE_SIZE];
        self.target.Read(self.pid, page_address, &mut bytes, true)?;
        self.pages.insert(page_address, CowPage::New(bytes));
        Ok(())
    }

    fn ValidateRange(address: u64, size: usize) -> Result<(), MemoryError> {
        if size > MAX_ACCESS_SIZE {
            return Err(MemoryError::AccessTooLarge);
        }
        if size != 0 && address.checked_add(size as u64).is_none() {
            return Err(MemoryError::AddressOverflow);
        }
        Ok(())
    }

    fn PageAddress(address: u64) -> u64 {
        address & !((PAGE_SIZE as u64) - 1)
    }

    fn PublicationMask(&self, address: u64, size: usize) -> u8 {
        let Some(slot) = self.publication_slot else {
            return 0;
        };
        let end = address + size as u64;
        let mut mask = 0;
        for index in 0..8_u64 {
            let byte = slot.saturating_add(index);
            if byte >= address && byte < end {
                mask |= 1_u8 << index;
            }
        }
        mask
    }
}
