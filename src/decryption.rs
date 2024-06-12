#![deny(unsafe_op_in_unsafe_fn)]
use chrono::{DateTime, Utc};
use core::panic;
use std::{mem, ptr, usize};
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::Cryptography::{NCryptUnprotectSecret, NCRYPT_SILENT_FLAG},
};
use windows_sys::{
    core::HRESULT,
    Win32::Foundation::{LocalFree, HLOCAL},
};

use crate::{
    helpers::{convert_to_uint32, filetime_to_datetime},
    LapsError,
};

#[derive(Debug, PartialEq)]
struct EncryptedPasswordAttributePrefixInfo {
    _timestamp: DateTime<Utc>,
    encrypted_buffer_size: usize,
    _flags_reserved: u32,
}

impl TryFrom<&[u8]> for EncryptedPasswordAttributePrefixInfo {
    type Error = LapsError;

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
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 16 {
            return Err(LapsError::InvalidBufLen);
        }
        let parts: Vec<u32> = value
            .chunks(4)
            .take(4)
            .flat_map(convert_to_uint32)
            .collect();
        let time_offset: i64 = ((parts[0] as i64) << 32) | parts[1] as i64;
        Ok(Self {
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

impl TryFrom<&[u8]> for EncryptedPasswordAttribute {
    type Error = LapsError;

    /// will convert the encrypted password attribute
    ///
    /// This will return None in case of a Invalid Buffer Length
    ///
    /// The first 16 bytes of the attribute are the PrefixInfo and will be parsed.
    /// The rest is the data. The data will be checked for size.
    /// The data will __not__ be decrypted at this staged yet.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let prefix: EncryptedPasswordAttributePrefixInfo = value.try_into()?;
        let encrypted_buffer_size = prefix.encrypted_buffer_size;

        if value.len() != encrypted_buffer_size + 16 {
            // Whole blob is too short
            return Err(LapsError::BlobTooShort);
        }
        Ok(Self {
            _prefix: prefix,
            data: value[16..(16 + encrypted_buffer_size)].to_owned(),
        })
    }
}

/// Wrapper to a raw pointer as to handle gracefully freeing it
struct DroppablePointer(*mut *mut u8);

impl DroppablePointer {
    fn new() -> Self {
        Self(&mut ptr::null_mut())
    }
}

impl Default for DroppablePointer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DroppablePointer {
    fn drop(&mut self) {
        // safety:
        // this should only panic in case the pointer was not allocated correctly by NCryptUnprotectSecret
        // since we are only using this Pointer for Objects allocated by LocalAlloc(via NCryptUnprotectSecret) this should not be a Problem.
        // Double free should also not happen since this is the drop() call and that will be checked by rustc
        // In case the pointer was not allocated at all and still is a NULL pointer this will also not fail.
        // see also https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree#remarks
        unsafe { local_free(self.0) }
    }
}

/// uses DPAPI NG to decrypt an encrypted LAPS password BLOB
///
/// This function uses the credentials of the current process/user.
///
/// This function calls a bunch of `unsafe` internal windows functions.
///
/// This function should be safe to call. Every return is checked for errors.
pub fn decrypt_password_blob_ng(blob: &[u8]) -> Result<String, LapsError> {
    let attr = EncryptedPasswordAttribute::try_from(blob)?;
    // at this point we have a parsed well defined header

    // get the pointer to the data blob to hand to NCryptUnprotectSecret
    // this must be mut since NCryptUnprotectSecret expect a *mut
    let buf_ptr = attr.data.as_ptr();
    let buf_len = attr.data.len() as u32;

    // this pointer will be set by NCryptUnprotectSecret and will then point to the array of the encrypted bytes
    // DroppablePointer is used to call LocalFree() on drop
    let buf_out_ptr: DroppablePointer = DroppablePointer::default();
    // this will be set by NCryptUnprotectSecret and will cointain the size of the encrypted buffer
    let mut buf_out_len = 0_u32;

    // call to NCryptUnprotectSecret
    // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret
    // SECURITY_STATUS NCryptUnprotectSecret(
    //   [out, optional] NCRYPT_DESCRIPTOR_HANDLE *phDescriptor, Pointer to the protection descriptor handle.
    //   [in]            DWORD                    dwFlags,
    //   [in]            const BYTE               *pbProtectedBlob,
    //                   ULONG                    cbProtectedBlob,
    //   [in, optional]  const NCRYPT_ALLOC_PARA  *pMemPara,
    //   [in, optional]  HWND                     hWnd,
    //   [out]           BYTE                     **ppbData,
    //   [out]           ULONG                    *pcbData
    // );
    // safety: Every input is know to us and the outputs will be handled further down.
    //         buf_out_ptr is a Droppable pointer which will satisfy the need to be LocalFree'd when dropping it.
    let uprotect_result: HRESULT = unsafe {
        NCryptUnprotectSecret(
            ptr::null_mut(),    // this is not needed for our usecase
            NCRYPT_SILENT_FLAG, // Requests that the key service provider not display a user interface.
            buf_ptr,            // Pointer to an array of bytes that contains the data to decrypt.
            buf_len, // The number of bytes in the array pointed to by the pbProtectedBlob parameter.
            ptr::null(), // since this is set to null we need to free the memory ourselves by calling LocalFree. This will be handled by DroppablePointer::drop()
            0, // Handle to the parent window of the user interface, if any, to be displayed.
            buf_out_ptr.0, // Address of a variable that receives a pointer to the decrypted data.
            &mut buf_out_len, // Pointer to a ULONG variable that contains the size, in bytes, of the decrypted data pointed to by the ppbData variable.
        )
    } as _;

    if uprotect_result != 0 {
        // there was an error decrypting the result
        return Err(LapsError::DpapiFailedToDecrypt(uprotect_result));
    }

    if buf_out_ptr.0.is_null() || buf_out_len == 0 {
        // something went wrong within the memory allocation & decryption
        // this should be checked by uprotect_result but we will check it anyway since we want to use those things later
        return Err(LapsError::Other(
            "Decrypted buffer is invalid or of size 0".into(),
        ));
    }

    // convert buf_out_len to usize. This should not fail on modern windows computers
    let buf_out_len: usize = buf_out_len
        .try_into()
        .map_err(|_| LapsError::InvalidBufLen)?;

    // Check that len * mem::size_of::<T>() fits into an isize since that is needed to safely call std::slice::from_raw_parts()
    let _: isize = (buf_out_len * mem::size_of::<u8>())
        .try_into()
        .map_err(|_| LapsError::InvalidBufLen)?;

    // at this point we know both the length of the buffer as well as the location of the buffer
    let res: Vec<u8> =
    // safety: since both the length as well as the location is known and they are not null this is safe
    //         NCryptUnprotectSecret uses LocalAlloc (https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc) in the back
    //         LocalAlloc will allocate buf_out_len number of bytes. These should be continuous.
        unsafe { std::slice::from_raw_parts(*buf_out_ptr.0, buf_out_len) }.to_owned();
    if res.len() != buf_out_len {
        // there was some error within the slice copy process.
        return Err(LapsError::InvalidBufLen);
    }

    // at this point we should have copied everything we needed from the buffer and can free the memory allocated by NCryptUnprotectSecret
    drop(buf_out_ptr);

    // Conversion to UTF16 from UTF8
    let mut res: Vec<u16> = res
        .chunks(2)
        .map(|a| (a[1] as u16) << 2 | a[0] as u16)
        .collect();
    // The String is NULL-terminated. So we remove the last NULL byte
    assert!(res.last() == Some(&0));
    let _ = res.pop();
    String::from_utf16(&res)
        .map_err(|_| LapsError::ConversionError("Conversion from UTF16 failed".into()))
}

/// will try to free the memory behind the pointer
///
/// # Safety
/// This should only be called for Memory regions allocated by LocalAlloc().
///
/// # Panics
/// If given an invalid (not allocated by local allocator) handle
unsafe fn local_free(buf_out_ptr: *mut *mut u8) {
    // free memory allocated by NCryptUnprotectSecret
    // see: parameter `[in, optional] pMemPara` here: https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret#parameters
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree
    // safety:
    let ret: HLOCAL = unsafe { LocalFree(buf_out_ptr as HLOCAL) };
    if !ret.is_null() {
        // This will only happen if this function gets called with an invalid memory handle.
        // so we panic here.
        let err = unsafe { GetLastError() };
        panic!("Error freeing memory {}", err,);
    };
}

#[cfg(test)]
mod prefix_tests {
    use crate::LapsError;

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
        let res: Result<EncryptedPasswordAttributePrefixInfo, LapsError> =
            header.as_slice().try_into();
        assert!(res.is_ok());
        assert_eq!(res.expect("res is ok"), test)
    }
}
