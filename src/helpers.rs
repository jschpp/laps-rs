use super::error::ConversionError;
use chrono::{DateTime, TimeDelta, Utc};

/// Converts a slice of u8 to a u32
///
/// This operates in LSB to array index.
/// Which means that `data[0]` will be the LSB
///
/// # Errors
/// Will `Err()` on inputs containing more than 4 bytes
pub fn convert_to_uint32(data: &[u8]) -> Result<u32, ConversionError> {
    if data.len() > 4 {
        return Err(ConversionError::InputTooLarge);
    }
    Ok(data
        .iter()
        .enumerate()
        .fold(0, |acc, (idx, n)| acc | ((*n as u32) << (idx * 8) as u32)))
}

const WINDOWS_EPOCH: &str = "1601-01-01T00:00:00-00:00";

/// Converts from a Windows filetime to a Datetime
pub fn filetime_to_datetime(file_time: i64) -> DateTime<Utc> {
    let epoch = DateTime::parse_from_rfc3339(WINDOWS_EPOCH)
        .expect("Windows Epoch is a valid times")
        .to_utc();

    // windows filetime counts the number of 100ns intervals since the WINDOWS_EPOCH
    let td = TimeDelta::microseconds(file_time / 10);
    epoch
        .checked_add_signed(td)
        .expect("should still be a valid date")
}

#[cfg(test)]
mod uint_tests {
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
    fn conversion(#[case] input: &[u8], #[case] expected: u32) {
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

#[cfg(test)]
mod date_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(133596792000000000, DateTime::<Utc>::from_timestamp_nanos(1715205600000000000))]
    #[case(116444736000000000, DateTime::<Utc>::from_timestamp_nanos(0))]
    #[case(103821696000000000, DateTime::<Utc>::from_timestamp_nanos(-1262304000000000000))]
    fn conversion(#[case] input: i64, #[case] expected: chrono::DateTime<Utc>) {
        assert_eq!(filetime_to_datetime(input), expected)
    }
}
