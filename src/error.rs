use thiserror::Error;
use windows_sys::{core::HRESULT, Win32::Foundation::WIN32_ERROR};

#[derive(Debug, Error, PartialEq)]
pub enum ConversionError {
    #[error("Input too large")]
    InputTooLarge,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("DPAPI had an error. Code: {0}")]
    DpapiFailedToDecrypt(HRESULT),
    #[error("{0} Win32_Code {1}")]
    Other(String, WIN32_ERROR),
    #[error("Invalid buffer length")]
    InvalidBufLen,
}

#[derive(Debug, Error)]
pub enum LapsError {
    #[error("A ldap error occured: {0}")]
    LdapError(String),
    #[error("{0}")]
    ConversionError(ConversionError),
    #[error("{0}")]
    DecryptionError(DecryptionError),
    #[error("{0}")]
    Other(String),
}
