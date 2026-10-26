pub type Result<T> = core::result::Result<T, LoaderError>;

#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("operation is only supported on Unix ELF targets")]
    UnsupportedPlatform,

    #[error("{0}")]
    InvalidElf(String),

    #[error("{0}")]
    Link(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}
