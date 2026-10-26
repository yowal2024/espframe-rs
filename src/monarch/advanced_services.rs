#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdvancedServiceError {
    #[error("atomic RCW service is unavailable for {0:?}")]
    AtomicRcwUnavailable(AtomicRcwOperation),
    #[error("memory tag service is unavailable for {0:?}")]
    MemoryTagUnavailable(MemoryTagOperation),
    #[error("LS64 service is unavailable for {0:?}")]
    Store64Unavailable(Store64Operation),
    #[error("GCS service is unavailable for {0:?}")]
    GcsUnavailable(GcsOperation),
    #[error("MOPS service is unavailable for {0:?}")]
    MopsUnavailable(MopsOperation),
    #[error("exception return service is unavailable")]
    ExceptionReturnUnavailable,
    #[error("advanced AArch64 service failed: {0}")]
    Service(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicRcwOperation {
    CompareSwap,
    Clear,
    Set,
    Swap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicRcwInfo {
    pub pc: u64,
    pub address: u64,
    pub operation: AtomicRcwOperation,
    pub software_checks: bool,
    pub element_count: u8,
    pub compare: [u64; 2],
    pub operand: [u64; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AtomicRcwResult {
    pub old_value: [u64; 2],
    pub nzcv: u32,
}

pub trait AtomicRcwService: Send + Sync {
    fn Process(
        &self,
        tid: i32,
        info: AtomicRcwInfo,
    ) -> Result<AtomicRcwResult, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAtomicRcwService;

impl AtomicRcwService for RejectAtomicRcwService {
    fn Process(
        &self,
        _tid: i32,
        info: AtomicRcwInfo,
    ) -> Result<AtomicRcwResult, AdvancedServiceError> {
        Err(AdvancedServiceError::AtomicRcwUnavailable(info.operation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTagOperation {
    Load,
    Store,
    LoadMultiple,
    StoreMultiple,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryTagInfo {
    pub pc: u64,
    pub address: u64,
    pub operation: MemoryTagOperation,
    pub value: u64,
    pub granule_count: usize,
    pub zero_data: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MemoryTagResult {
    pub value: u64,
}

pub trait MemoryTagService: Send + Sync {
    fn Process(
        &self,
        tid: i32,
        info: MemoryTagInfo,
    ) -> Result<MemoryTagResult, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectMemoryTagService;

impl MemoryTagService for RejectMemoryTagService {
    fn Process(
        &self,
        _tid: i32,
        info: MemoryTagInfo,
    ) -> Result<MemoryTagResult, AdvancedServiceError> {
        Err(AdvancedServiceError::MemoryTagUnavailable(info.operation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store64Operation {
    Store,
    StoreWithStatus,
    StoreWithStatusAndAccdata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Store64Info {
    pub pc: u64,
    pub address: u64,
    pub operation: Store64Operation,
    pub data: [u64; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Store64Result {
    pub status: u64,
}

pub trait Store64Service: Send + Sync {
    fn Process(&self, tid: i32, info: Store64Info) -> Result<Store64Result, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectStore64Service;

impl Store64Service for RejectStore64Service {
    fn Process(&self, _tid: i32, info: Store64Info) -> Result<Store64Result, AdvancedServiceError> {
        Err(AdvancedServiceError::Store64Unavailable(info.operation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcsOperation {
    PopExceptionChecked,
    Pop,
    PopException,
    Push,
    PushException,
    SwitchStackPhase1,
    SwitchStackPhase2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcsInfo {
    pub pc: u64,
    pub operation: GcsOperation,
    pub reg: u8,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GcsResult {
    pub value: u64,
}

pub trait GcsService: Send + Sync {
    fn Process(&self, tid: i32, info: GcsInfo) -> Result<GcsResult, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectGcsService;

impl GcsService for RejectGcsService {
    fn Process(&self, _tid: i32, info: GcsInfo) -> Result<GcsResult, AdvancedServiceError> {
        Err(AdvancedServiceError::GcsUnavailable(info.operation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MopsOperation {
    Copy,
    Set,
    SetTags,
    SetTagsOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MopsInfo {
    pub pc: u64,
    pub operation: MopsOperation,
    pub destination_address: u64,
    pub source_address: u64,
    pub count: u64,
    pub fill_byte: u8,
    pub backwards: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MopsResult;

pub trait MopsService: Send + Sync {
    fn Process(&self, tid: i32, info: MopsInfo) -> Result<MopsResult, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectMopsService;

impl MopsService for RejectMopsService {
    fn Process(&self, _tid: i32, info: MopsInfo) -> Result<MopsResult, AdvancedServiceError> {
        Err(AdvancedServiceError::MopsUnavailable(info.operation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExceptionReturnInfo {
    pub pc: u64,
    pub key_b: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ExceptionReturnResult {
    pub target: u64,
}

pub trait ExceptionReturnService: Send + Sync {
    fn Process(
        &self,
        tid: i32,
        info: ExceptionReturnInfo,
    ) -> Result<ExceptionReturnResult, AdvancedServiceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectExceptionReturnService;

impl ExceptionReturnService for RejectExceptionReturnService {
    fn Process(
        &self,
        _tid: i32,
        _info: ExceptionReturnInfo,
    ) -> Result<ExceptionReturnResult, AdvancedServiceError> {
        Err(AdvancedServiceError::ExceptionReturnUnavailable)
    }
}
