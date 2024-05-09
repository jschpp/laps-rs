use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ConversionError {
    #[error("Input too large")]
    InputTooLarge,
}

pub fn convert_to_uint32(data: &[u8]) -> Result<u32, ConversionError> {
    if data.len() > 4 {
        return Err(ConversionError::InputTooLarge);
    }
    Ok(data
        .iter()
        .enumerate()
        .fold(0, |acc, (idx, n)| acc | ((*n as u32) << (idx * 8) as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&[0x0, 0x0, 0x0, 0x0], u32::MIN)]
    #[case(&[0x0], u32::MIN)]
    #[case(&[0x1, 0x0, 0x0, 0x0], 1)]
    #[case(&[0x1, 0x1, 0x0, 0x0], 0x101)]
    #[case(&[0x1, 0x1, 0x1, 0x0], 0x10101)]
    #[case(&[0x1, 0x1, 0x1, 0x1], 0x1010101)]
    #[case(&[0xFF, 0xFF, 0xFF, 0xFF], u32::MAX)]
    fn uint32_conversion(#[case] input: &[u8], #[case] expected: u32) {
        assert_eq!(convert_to_uint32(&input).expect("valid inputs"), expected)
    }

    #[rstest]
    #[case(&[0, 0, 0, 0, 0])]
    #[case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF])]
    fn should_err_on_invalid_input(#[case] input: &[u8]) {
        let e = convert_to_uint32(&input);
        assert!(e.is_err());
        assert_eq!(e, Err(ConversionError::InputTooLarge));
    }
}
