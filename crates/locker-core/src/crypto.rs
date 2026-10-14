//! Thin wrappers around the audited RustCrypto crates. No algorithm is
//! implemented here; this module only fixes which ones we use and how.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 16;

/// A 256-bit secret key that is wiped from memory when dropped.
///
/// The bytes live on the heap behind a `Box`. Moving a `Key` then only moves
/// the pointer, so no stray copies of the secret are left behind on the
/// stack for the wipe to miss.
pub struct Key(Box<[u8; KEY_LEN]>);

impl Key {
    pub fn generate() -> Result<Self> {
        let mut key = Self::zeroed();
        fill_random(&mut key.0[..])?;
        Ok(key)
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        key
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn zeroed() -> Self {
        Self(Box::new([0u8; KEY_LEN]))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Hand-written so a key can never end up in a log by accident.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Argon2id cost settings. They are stored in the vault header, so they can
/// be raised later without breaking existing vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory to use, in KiB.
    pub m_cost_kib: u32,
    /// Number of passes over that memory.
    pub t_cost: u32,
    /// Number of lanes. Without the `parallel` feature lanes run one after
    /// another, so more lanes only slow down unlocking, not attackers.
    pub p_cost: u32,
}

impl KdfParams {
    /// 256 MiB and 3 passes: about half a second in a release build.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    // Upper bounds are checked before any derivation runs, so a damaged or
    // malicious header cannot make the app allocate gigabytes or spin forever.
    const MAX_M_COST_KIB: u32 = 1024 * 1024;
    const MAX_T_COST: u32 = 16;
    const MAX_P_COST: u32 = 4;

    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let params = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<()> {
        let in_range = (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost)
            && self.m_cost_kib >= Params::MIN_M_COST
            && self.m_cost_kib >= 8 * self.p_cost
            && self.m_cost_kib <= Self::MAX_M_COST_KIB;
        if in_range {
            Ok(())
        } else {
            Err(Error::InvalidKdfParams)
        }
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Turns the master password into a key. This is the slow, memory-hard step
/// that makes guessing passwords expensive.
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Key> {
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // Derive straight into the heap buffer so the key never sits on the stack.
    let mut key = Key::zeroed();
    argon
        .hash_password_into(password, salt, &mut key.0[..])
        .map_err(|_| Error::InvalidKdfParams)?;
    Ok(key)
}

/// Encrypts `plaintext` and authenticates both it and `aad`. The output is
/// the ciphertext followed by a 16-byte tag.
///
/// The nonce must never repeat for the same key. Callers pass a fresh random
/// 24-byte nonce every time, which is safe with XChaCha20.
pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed("data too large to encrypt"))
}

/// Reverses [`seal`]. Returns `None` if the key, nonce, ciphertext or `aad`
/// differ in any way from what was sealed. The caller decides what that
/// means (wrong key or damaged file).
pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    cipher(key)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    // `new_from_slice` copies the key into the cipher, which wipes its copy
    // when dropped thanks to the `zeroize` feature.
    XChaCha20Poly1305::new_from_slice(&key.0[..]).expect("key is exactly 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    #[test]
    fn same_password_and_salt_give_same_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_password_key(b"correct horse", &salt, &fast_params()).unwrap();
        let b = derive_password_key(b"correct horse", &salt, &fast_params()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let a = derive_password_key(b"pw", &[1u8; SALT_LEN], &fast_params()).unwrap();
        let b = derive_password_key(b"pw", &[2u8; SALT_LEN], &fast_params()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = Key::generate().unwrap();
        let nonce = random_array().unwrap();
        let sealed = seal(&key, &nonce, b"secret", b"context").unwrap();
        assert_eq!(sealed.len(), b"secret".len() + TAG_LEN);
        let opened = open(&key, &nonce, &sealed, b"context").unwrap();
        assert_eq!(&opened[..], b"secret");
    }

    #[test]
    fn open_rejects_wrong_key_nonce_aad_or_tampering() {
        let key = Key::generate().unwrap();
        let nonce = random_array().unwrap();
        let sealed = seal(&key, &nonce, b"secret", b"context").unwrap();

        assert!(open(&Key::generate().unwrap(), &nonce, &sealed, b"context").is_none());
        assert!(open(&key, &random_array().unwrap(), &sealed, b"context").is_none());
        assert!(open(&key, &nonce, &sealed, b"other").is_none());
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(open(&key, &nonce, &tampered, b"context").is_none());
    }

    #[test]
    fn kdf_params_reject_out_of_range_values() {
        assert!(KdfParams::new(8, 0, 1).is_err());
        assert!(KdfParams::new(8, 17, 1).is_err());
        assert!(KdfParams::new(8, 1, 0).is_err());
        assert!(KdfParams::new(8, 1, 5).is_err());
        assert!(KdfParams::new(4, 1, 1).is_err());
        assert!(KdfParams::new(2 * 1024 * 1024, 1, 1).is_err());
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn debug_output_hides_key_bytes() {
        let key = Key::from_bytes(&[0xAB; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "Key(<redacted>)");
    }
}
