use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not an Archydes archive")]
    NotArchydes,
    #[error("unsupported format version {0}.{1}")]
    UnsupportedVersion(u16, u16),
    #[error("archive is damaged: {0}")]
    Corrupt(String),
    #[error("not supported by this version: {0}")]
    Unsupported(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("cancelled")]
    Cancelled,
    /// The archive is encrypted and no password was given.
    #[error("the archive is encrypted, a password is needed")]
    PasswordRequired,
    #[error("wrong password")]
    WrongPassword,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn corrupt(message: impl Into<String>) -> Error {
    Error::Corrupt(message.into())
}
