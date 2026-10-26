use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("kernel functionality is unavailable in the Task 1 skeleton")]
pub struct KernelError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("injection functionality is unavailable in the Task 1 skeleton")]
pub struct InjectError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("stub or payload functionality is unavailable in the Task 1 skeleton")]
pub struct StubPayloadError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("offsets functionality is unavailable in the Task 1 skeleton")]
pub struct OffsetsError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("UE functionality is unavailable in the Task 1 skeleton")]
pub struct UeError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("authentication functionality is unavailable in the Task 1 skeleton")]
pub struct AuthError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("gyro aim functionality is unavailable in the Task 1 skeleton")]
pub struct GyroAimError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("Android functionality is unavailable in the Task 1 skeleton")]
pub struct AndroidError;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RenderError {
    #[error("invalid render surface")]
    InvalidSurface,
    #[error("render backend is not initialized")]
    NotInitialized,
    #[error("render context was lost")]
    ContextLost,
    #[error("render surface was lost")]
    SurfaceLost,
    #[error("invalid texture upload")]
    InvalidTexture,
    #[error("render backend failed: {0}")]
    Device(String),
    #[error("ImGui frame failed: {0}")]
    Ui(String),
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("Monarch functionality is unavailable in the Task 1 skeleton")]
pub struct MonarchError;

#[derive(Debug, Error)]
pub enum EspFrameError {
    #[error("kernel failure: {0}")]
    Kernel(#[from] KernelError),
    #[error("injection failure: {0}")]
    Injection(#[from] InjectError),
    #[error("stub or payload failure: {0}")]
    StubPayload(#[from] StubPayloadError),
    #[error("offsets failure: {0}")]
    Offsets(#[from] OffsetsError),
    #[error("authentication failure: {0}")]
    Authentication(#[from] AuthError),
    #[error("gyro aim failure: {0}")]
    GyroAim(#[from] GyroAimError),
    #[error("android failure: {0}")]
    Android(#[from] AndroidError),
    #[error("render failure: {0}")]
    Render(#[from] RenderError),
}
