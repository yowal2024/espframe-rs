#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PAuthOperation {
    Pacga,
    Pacia,
    Pacib,
    Pacda,
    Pacdb,
    Autia,
    Autib,
    Autda,
    Autdb,
    Xpaci,
    Xpacd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PAuthResult {
    pub value: u64,
    pub ioctl_result: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("pointer authentication service failed: {0}")]
    PAuth(String),
}

pub trait PAuthService: Send + Sync {
    fn Process(
        &self,
        tid: i32,
        operation: PAuthOperation,
        value: u64,
        modifier: u64,
    ) -> Result<PAuthResult, ServiceError>;
}
