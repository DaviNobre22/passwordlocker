//! The only place in the project that contains `unsafe` code: two calls
//! into the Windows Data Protection API (DPAPI).
//!
//! DPAPI encrypts bytes with a key that Windows derives from the logged-in
//! user's account, so a blob can only be opened by the same user on the same
//! machine. We never see or store that key.

use zeroize::Zeroizing;

use crate::DeviceError;

/// Mixed into every protect/unprotect call. DPAPI then refuses blobs made by
/// other programs running as the same user that did not pass the same value.
/// It is not a secret; it only separates our blobs from everyone else's.
#[cfg(windows)]
const ENTROPY: &[u8] = b"passwordlocker device key v1";

#[cfg(windows)]
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, DeviceError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData};

    let input = blob(plaintext)?;
    let entropy = blob(ENTROPY)?;
    let mut output = empty_blob();

    // SAFETY: `input` and `entropy` point at slices that outlive the call and
    // whose lengths fit in u32 (checked by `blob`); DPAPI only reads them.
    // `output` is a valid blob that DPAPI fills in. Optional arguments are
    // null, which the API documents as "not used". Flags are current-user
    // scope (no LOCAL_MACHINE) and forbid any UI prompt.
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(DeviceError::Dpapi);
    }
    Ok(take_output(output).to_vec())
}

#[cfg(windows)]
pub fn unprotect(protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, DeviceError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = blob(protected)?;
    let entropy = blob(ENTROPY)?;
    let mut output = empty_blob();

    // SAFETY: same contract as in `protect`. The description out-parameter is
    // null because we do not ask for it, so there is nothing extra to free.
    // Garbage input makes the call fail cleanly rather than misbehave.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(DeviceError::Dpapi);
    }
    Ok(take_output(output))
}

/// Describes a slice to DPAPI. The pointer is cast to `*mut` only because
/// the struct has one field type for both directions; DPAPI never writes
/// through an input blob.
#[cfg(windows)]
fn blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, DeviceError> {
    let len = u32::try_from(bytes.len()).map_err(|_| DeviceError::Dpapi)?;
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: len,
            pbData: bytes.as_ptr().cast_mut(),
        },
    )
}

#[cfg(windows)]
fn empty_blob() -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    }
}

/// Copies DPAPI's output into memory we own, then wipes and frees the
/// Windows-allocated buffer. Used for the plaintext direction too, so the
/// wipe matters.
#[cfg(windows)]
fn take_output(
    output: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Zeroizing<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;

    if output.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    // SAFETY: on success DPAPI returns `cbData` readable and writable bytes
    // at `pbData`, allocated with LocalAlloc and exclusively ours.
    let buffer = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copy = Zeroizing::new(buffer.to_vec());
    zeroize::Zeroize::zeroize(buffer);
    // SAFETY: `pbData` came from DPAPI's LocalAlloc and is freed exactly once;
    // `buffer` is not used afterwards.
    unsafe { LocalFree(output.pbData.cast()) };
    copy
}

#[cfg(not(windows))]
pub fn protect(_plaintext: &[u8]) -> Result<Vec<u8>, DeviceError> {
    Err(DeviceError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn unprotect(_protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, DeviceError> {
    Err(DeviceError::UnsupportedPlatform)
}
