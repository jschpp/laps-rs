use ldap3::LdapError;
use thiserror::Error;
use windows_sys::core::HRESULT;

#[derive(Debug, Error)]
pub enum LapsError {
    /// Encapsulated LdapError
    #[error("A ldap error occured: {source}")]
    LdapError {
        #[from]
        source: LdapError,
    },
    /// Conversion Error
    #[error("{0}")]
    ConversionError(String),
    /// Error within the decryption Routine
    #[error("DPAPI had an error. Code: {0}")]
    DpapiFailedToDecrypt(HRESULT),
    /// The cryptographic blob was too short
    #[error("The blob given was too short for the contained metadata")]
    BlobTooShort,
    #[error("Buffer was not of the expected length")]
    InvalidBufLen,
    /// Something was not found
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Other(String),
}
