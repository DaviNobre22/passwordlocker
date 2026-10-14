//! The device key: a random key kept on this PC and sealed by Windows, so a
//! stolen copy of the vault file is useless on any other machine.
//!
//! One device key serves every vault on this PC. A key per vault would need
//! a vault id to look it up and would leave orphaned files behind whenever a
//! vault is deleted; a per-PC key has nothing to coordinate. The cost is that
//! the key is shared, but it is only one of the two things needed to unlock
//! (the master password is the other), and each vault wraps it in its own
//! slot.
//!
//! This crate is separate from `locker-core` because DPAPI needs `unsafe`
//! code, which `locker-core` forbids. All of it is in the `dpapi` module.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::path::{Path, PathBuf};

use locker_core::{Key, read_file, write_atomic};
use zeroize::Zeroizing;

// Only this module is allowed to contain `unsafe`.
#[allow(unsafe_code)]
mod dpapi;

/// First bytes of the key file, so that a wrong file is recognised before
/// DPAPI is even asked to open it.
const MAGIC: &[u8; 4] = b"PWDK";
/// Bumped if the layout after the header ever changes.
const FILE_VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1;

/// Errors never carry key bytes.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("Windows could not protect or unprotect the device key")]
    Dpapi,

    #[error("device keys are only supported on Windows")]
    UnsupportedPlatform,

    #[error("the LOCALAPPDATA environment variable is not set")]
    NoLocalAppData,

    #[error("the device key file is not valid: {0}")]
    BadFile(&'static str),

    #[error("a device key already exists on this PC")]
    AlreadyExists,

    #[error(transparent)]
    Core(#[from] locker_core::Error),

    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, DeviceError>;

/// Encrypts `plaintext` for the current Windows user on this PC.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    dpapi::protect(plaintext)
}

/// Reverses [`protect`]. Fails on anything that was not produced by it for
/// this user on this PC, including damaged blobs.
pub fn unprotect(protected: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    dpapi::unprotect(protected)
}

/// Where the device key lives and how to read and write it.
#[derive(Clone, Debug)]
pub struct DeviceKeyStore {
    path: PathBuf,
}

impl DeviceKeyStore {
    /// `%LOCALAPPDATA%\passwordlocker\device.key`.
    ///
    /// Deliberately not next to the vault: the vault may sit in a synced
    /// folder, and the device key must never travel with it. `LOCALAPPDATA`
    /// (unlike `APPDATA`) is not roamed between PCs either.
    pub fn default_location() -> Result<Self> {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or(DeviceError::NoLocalAppData)?;
        Ok(Self::at(
            PathBuf::from(base)
                .join("passwordlocker")
                .join("device.key"),
        ))
    }

    /// A store at an explicit path, for tests.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the key, or `None` if this PC has none yet.
    pub fn load(&self) -> Result<Option<Key>> {
        let bytes = match read_file(&self.path) {
            Ok(bytes) => bytes,
            Err(locker_core::Error::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };

        let blob = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(DeviceError::BadFile("missing header"))?;
        match blob.split_first() {
            Some((&FILE_VERSION, blob)) => {
                let plain = unprotect(blob)?;
                let key = <&[u8; 32]>::try_from(plain.as_slice())
                    .map_err(|_| DeviceError::BadFile("unexpected key length"))?;
                Ok(Some(Key::from_bytes(key)))
            }
            Some(_) => Err(DeviceError::BadFile("unsupported version")),
            None => Err(DeviceError::BadFile("truncated header")),
        }
    }

    /// Generates a new key and stores it. Refuses to replace an existing
    /// file: losing the old key would lock the user out of every vault that
    /// uses it.
    pub fn create(&self) -> Result<Key> {
        if self.path.exists() {
            return Err(DeviceError::AlreadyExists);
        }
        let key = Key::generate()?;
        let blob = protect(key.as_bytes())?;

        let mut file = Vec::with_capacity(HEADER_LEN + blob.len());
        file.extend_from_slice(MAGIC);
        file.push(FILE_VERSION);
        file.extend_from_slice(&blob);

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_atomic(&self.path, &file)?;
        Ok(key)
    }

    /// The key for this PC, creating it on first use.
    pub fn load_or_create(&self) -> Result<Key> {
        match self.load()? {
            Some(key) => Ok(key),
            None => self.create(),
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, DeviceKeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceKeyStore::at(dir.path().join("sub").join("device.key"));
        (dir, store)
    }

    #[test]
    fn protect_then_unprotect_round_trips() {
        let secret = [7u8; 32];
        let blob = protect(&secret).unwrap();
        assert_ne!(&blob[..], &secret[..]);
        assert_eq!(&unprotect(&blob).unwrap()[..], &secret[..]);

        // Empty input is legal too.
        assert!(unprotect(&protect(b"").unwrap()).unwrap().is_empty());
    }

    #[test]
    fn unprotect_rejects_garbage_without_panicking() {
        let blob = protect(&[1u8; 32]).unwrap();

        assert!(unprotect(&[]).is_err());
        assert!(unprotect(b"not a dpapi blob at all").is_err());
        assert!(unprotect(&[0u8; 200]).is_err());
        for len in 0..blob.len() {
            assert!(unprotect(&blob[..len]).is_err(), "truncated to {len}");
        }
        for i in 0..blob.len() {
            let mut damaged = blob.clone();
            damaged[i] ^= 0x01;
            // Some bytes (e.g. an unused header field) may be tolerated, but
            // the result must never be a different successful plaintext.
            if let Ok(plain) = unprotect(&damaged) {
                assert_eq!(&plain[..], &[1u8; 32][..], "byte {i} changed the key");
            }
        }
    }

    #[test]
    fn create_then_load_returns_the_same_key() {
        let (_dir, store) = store();
        let created = store.create().unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(created.as_bytes(), loaded.as_bytes());
    }

    #[test]
    fn key_on_disk_is_not_the_plain_key() {
        let (_dir, store) = store();
        let key = store.create().unwrap();
        let file = std::fs::read(store.path()).unwrap();
        assert!(file.starts_with(b"PWDK\x01"));
        assert!(!file.windows(32).any(|w| w == key.as_bytes()));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let (_dir, store) = store();
        let first = store.create().unwrap();
        assert!(matches!(store.create(), Err(DeviceError::AlreadyExists)));
        assert_eq!(store.load().unwrap().unwrap().as_bytes(), first.as_bytes());
    }

    #[test]
    fn missing_file_loads_as_none() {
        let (_dir, store) = store();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn load_or_create_is_stable() {
        let (_dir, store) = store();
        let first = store.load_or_create().unwrap();
        let second = store.load_or_create().unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn bad_headers_are_errors() {
        let (_dir, store) = store();
        store.create().unwrap();
        let good = std::fs::read(store.path()).unwrap();

        let mut wrong_magic = good.clone();
        wrong_magic[0] = b'X';
        let mut wrong_version = good.clone();
        wrong_version[4] = 99;

        for bad in [
            Vec::new(),
            b"PWD".to_vec(),
            b"PWDK".to_vec(),
            wrong_magic,
            wrong_version,
            good[..HEADER_LEN + 3].to_vec(),
        ] {
            std::fs::write(store.path(), &bad).unwrap();
            assert!(store.load().is_err());
        }
    }

    #[test]
    fn blob_with_wrong_length_inside_is_an_error() {
        let (_dir, store) = store();
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        let mut file = b"PWDK\x01".to_vec();
        file.extend_from_slice(&protect(&[1u8; 16]).unwrap());
        std::fs::write(store.path(), file).unwrap();
        assert!(matches!(store.load(), Err(DeviceError::BadFile(_))));
    }

    #[test]
    fn default_location_is_under_local_app_data() {
        if let Ok(store) = DeviceKeyStore::default_location() {
            assert!(store.path().ends_with("passwordlocker/device.key"));
        }
    }
}
