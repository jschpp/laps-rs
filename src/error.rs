use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ConversionError {
    #[error("Input too large")]
    InputTooLarge,
}
