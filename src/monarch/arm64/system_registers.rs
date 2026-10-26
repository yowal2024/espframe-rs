#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemRegister {
    CtrEl0,
    CntvctEl0,
    TpidrEl0,
    CntfrqEl0,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SystemRegisterError {
    #[error("system register {0:?} is unavailable")]
    Unavailable(SystemRegister),
    #[error("system register service failed: {0}")]
    Service(String),
}

pub trait SystemRegisterService: Send + Sync {
    fn Read(&self, tid: i32, register: SystemRegister) -> Result<u64, SystemRegisterError>;

    fn Write(
        &self,
        tid: i32,
        register: SystemRegister,
        value: u64,
    ) -> Result<(), SystemRegisterError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectSystemRegisterService;

impl SystemRegisterService for RejectSystemRegisterService {
    fn Read(&self, _tid: i32, register: SystemRegister) -> Result<u64, SystemRegisterError> {
        Err(SystemRegisterError::Unavailable(register))
    }

    fn Write(
        &self,
        _tid: i32,
        register: SystemRegister,
        _value: u64,
    ) -> Result<(), SystemRegisterError> {
        Err(SystemRegisterError::Unavailable(register))
    }
}
