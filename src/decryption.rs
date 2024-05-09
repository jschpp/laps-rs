use chrono::{DateTime, Utc};

use crate::helpers::{convert_to_uint32, filetime_to_datetime};

#[derive(Debug, PartialEq)]
struct EncryptedPasswordAttributePrefixInfo {
    _timestamp: DateTime<Utc>,
    encrypted_buffer_size: usize,
    _flags_reserved: u32,
}

impl EncryptedPasswordAttributePrefixInfo {
    /// This will take the first 16 bytes of the password attribute and convert its parts to the corresponding rust types.
    ///
    /// ```plain
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | dwHighDateTime (most significant part of filetime struct)     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | dwLowDateTime  (least significant part of filetime struct)    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | size of the encrypted password buffer                         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | reserved flags for future use                                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    /// All numbers are 32 bit numbers in LSB byte order
    ///
    /// # Returns None on inputs with `buf.len() < 16`
    ///
    fn try_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let parts: Vec<u32> = buf.chunks(4).take(4).flat_map(convert_to_uint32).collect();
        let time_offset: i64 = ((parts[0] as i64) << 32) | parts[1] as i64;
        Some(Self {
            _timestamp: filetime_to_datetime(time_offset),
            encrypted_buffer_size: parts[2] as usize,
            _flags_reserved: parts[3],
        })
    }
}

struct EncryptedPasswordAttribute {
    _prefix: EncryptedPasswordAttributePrefixInfo,
    data: Vec<u8>,
}

impl EncryptedPasswordAttribute {
    /// will convert the encrypted password attribute
    ///
    /// The first 16 bytes of the attribute are the PrefixInfo and will be parsed.
    ///
    /// The rest is the data. The data will be checked for size.
    ///
    /// The data will __not__ be decrypted at this staged yet.
    fn try_from(buf: &[u8]) -> Option<Self> {
        let prefix_opt = EncryptedPasswordAttributePrefixInfo::try_from(buf);
        if prefix_opt.is_none() {
            return None;
        }
        let prefix = prefix_opt.expect("prefix is Some(prefix)");
        let encrypted_buffer_size = prefix.encrypted_buffer_size;

        if buf.len() != encrypted_buffer_size + 16 {
            // Whole blob is too short
            return None;
        }
        Some(Self {
            _prefix: prefix,
            data: buf[16..(16 + encrypted_buffer_size)].to_owned(),
        })
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::EncryptedPasswordAttributePrefixInfo;
    use chrono::{DateTime, Utc};

    #[test]
    fn new() {
        // this is the Header we will construct in parts further down
        let test = EncryptedPasswordAttributePrefixInfo {
            _timestamp: DateTime::<Utc>::from_timestamp_nanos(-1262304000000000000),
            encrypted_buffer_size: 0x87654321,
            _flags_reserved: 0xDEADBEEF,
        };

        // header _must_ be at least 16 bytes long
        let mut header: Vec<u8> = Vec::with_capacity(16);

        // this is 103821696000000000 in HEX bytes in LSB Byte Order
        // the conversion for 103821696000000000 is tested in the conversion test of filetime_to_timestamp
        // upper (Most significant) bytes of the timestamp in LSB
        let timestamp_upper: [u8; 4] = [0x48, 0xd9, 0x70, 0x01];
        // lower (least significant) bytes of the timestamp in LSB
        let timestamp_lower: [u8; 4] = [0x00, 0x00, 0x0f, 0x4e];
        header.extend_from_slice(&timestamp_upper);
        header.extend_from_slice(&timestamp_lower);

        let buf_size: [u8; 4] = [0x21, 0x43, 0x65, 0x87];
        header.extend_from_slice(&buf_size);

        let reserved: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];
        header.extend_from_slice(&reserved);
        let res = EncryptedPasswordAttributePrefixInfo::try_from(&header);
        assert!(res.is_some());
        assert_eq!(res.expect("res is some"), test)
    }
}
