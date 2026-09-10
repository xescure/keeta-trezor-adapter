use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("bad input: {0}")]
    BadInput(String),
    #[error("device error: {0}")]
    Device(String),
    #[error("device returned address {got}, expected {expected} (wrong passphrase, identity, or index?)")]
    UnexpectedKey { got: String, expected: String },
    #[error("device returned a malformed signature ({0})")]
    MalformedSignature(String),
    #[error("signature did not verify against the device public key: {0}")]
    VerifyFailed(String),
    #[error("keeta sdk error: {0}")]
    Keeta(String),
}

pub type Result<T> = std::result::Result<T, Error>;
