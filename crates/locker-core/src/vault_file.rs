//! The vault file format and the key layers that open it.
//!
//! The contents are encrypted with a random *vault key* that never changes.
//! Each way of unlocking is a *slot*: a copy of the vault key wrapped in two
//! layers.
//!
//! - Inner layer: encrypted with a 32-byte second factor (the device key or
//!   the recovery key).
//! - Outer layer: encrypted with the *password key*, derived from the master
//!   password with Argon2id.
//!
//! Opening a slot needs both the password and that slot's factor. Changing
//! the password only replaces the outer layers, so it never needs the
//! recovery key, which lives on paper.
//!
//! File layout (integers are little-endian):
//!
//! ```text
//! "PWLK" | version u16 | kdf id u8 | m_cost u32 | t_cost u32 | p_cost u32 | salt [16]
//! slot count u8 | per slot: kind u8 | outer nonce [24] | outer ciphertext [88]
//! body nonce [24] | body ciphertext (rest of file)
//! ```
//!
//! Everything before the body ciphertext is authenticated along with the
//! body, so changing any header byte makes the file fail to open.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::{
    self, KEY_LEN, KdfParams, Key, NONCE_LEN, SALT_LEN, TAG_LEN, derive_password_key, random_array,
};
use crate::error::{Error, Result};

const MAGIC: [u8; 4] = *b"PWLK";
pub const FORMAT_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
pub const MAX_SLOTS: usize = 16;

/// Inner layer: its nonce, then the encrypted vault key and its tag.
const INNER_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// Outer layer: the whole inner layer, encrypted again, plus another tag.
const OUTER_LEN: usize = INNER_LEN + TAG_LEN;
const INNER_AAD_PREFIX: &[u8] = b"passwordlocker inner slot v1";

/// Which second factor a slot is locked with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorKind {
    /// A key kept by Windows on one PC.
    Device,
    /// The key behind the printed recovery code.
    Recovery,
}

impl FactorKind {
    fn to_byte(self) -> u8 {
        match self {
            FactorKind::Device => 1,
            FactorKind::Recovery => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(FactorKind::Device),
            2 => Ok(FactorKind::Recovery),
            _ => Err(Error::Malformed("unknown unlock slot kind")),
        }
    }
}

/// A slot with its outer layer removed. The inner layer is still encrypted
/// with the factor, which is all we need to rebuild the outer layer later.
struct Slot {
    kind: FactorKind,
    inner: [u8; INNER_LEN],
}

/// An open vault: holds the keys needed to save it again.
pub struct UnlockedVault {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    password_key: Key,
    vault_key: Key,
    slots: Vec<Slot>,
}

impl UnlockedVault {
    /// Starts a new vault with one device slot and one recovery slot.
    pub fn create(password: &[u8], kdf: KdfParams, device: &Key, recovery: &Key) -> Result<Self> {
        let salt = random_array()?;
        let mut vault = Self {
            kdf,
            salt,
            password_key: derive_password_key(password, &salt, &kdf)?,
            vault_key: Key::generate()?,
            slots: Vec::new(),
        };
        vault.add_slot(FactorKind::Device, device)?;
        vault.add_slot(FactorKind::Recovery, recovery)?;
        Ok(vault)
    }

    /// Opens a vault file and returns it with its decrypted contents.
    pub fn open(
        file: &[u8],
        password: &[u8],
        kind: FactorKind,
        factor: &Key,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let parsed = ParsedFile::parse(file)?;
        let password_key = derive_password_key(password, &parsed.salt, &parsed.kdf)?;
        let context = kdf_context(&parsed.kdf, &parsed.salt);

        // Every slot shares the password key, so a wrong password fails here.
        let mut slots = Vec::with_capacity(parsed.slots.len());
        for raw in &parsed.slots {
            let inner = crypto::open(
                &password_key,
                &raw.nonce,
                raw.outer,
                &outer_aad(&context, raw.kind),
            )
            .ok_or(Error::Unlock)?;
            let inner = inner[..].try_into().map_err(|_| Error::Unlock)?;
            slots.push(Slot {
                kind: raw.kind,
                inner,
            });
        }

        // A wrong factor fails here.
        let vault_key = slots
            .iter()
            .filter(|slot| slot.kind == kind)
            .find_map(|slot| unwrap_inner(slot, factor))
            .ok_or(Error::Unlock)?;

        // The keys were right, so a failure now means the file was changed.
        let body = crypto::open(
            &vault_key,
            &parsed.body_nonce,
            parsed.body,
            parsed.header_bytes,
        )
        .ok_or(Error::Corrupt)?;

        let vault = Self {
            kdf: parsed.kdf,
            salt: parsed.salt,
            password_key,
            vault_key,
            slots,
        };
        Ok((vault, body))
    }

    /// Encrypts `plaintext` into a complete vault file.
    ///
    /// Every call uses fresh random nonces, so saving the same contents
    /// twice gives two different files.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = kdf_context(&self.kdf, &self.salt);
        let context_len = out.len();
        out.push(self.slots.len() as u8);
        for slot in &self.slots {
            let nonce = random_array()?;
            let outer = crypto::seal(
                &self.password_key,
                &nonce,
                &slot.inner,
                &outer_aad(&out[..context_len], slot.kind),
            )?;
            out.push(slot.kind.to_byte());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&outer);
        }
        let body_nonce: [u8; NONCE_LEN] = random_array()?;
        out.extend_from_slice(&body_nonce);
        let body = crypto::seal(&self.vault_key, &body_nonce, plaintext, &out)?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Replaces the master password. The current one is required, so an
    /// unlocked vault left open cannot be taken over without it.
    pub fn change_password(&mut self, current: &[u8], new: &[u8], kdf: KdfParams) -> Result<()> {
        let check = derive_password_key(current, &self.salt, &self.kdf)?;
        if !keys_equal(&check, &self.password_key) {
            return Err(Error::Unlock);
        }
        let salt = random_array()?;
        self.password_key = derive_password_key(new, &salt, &kdf)?;
        self.salt = salt;
        self.kdf = kdf;
        Ok(())
    }

    /// Adds a slot for another PC's device key, e.g. after recovering on a
    /// new machine.
    pub fn add_device(&mut self, device: &Key) -> Result<()> {
        self.add_slot(FactorKind::Device, device)
    }

    /// Swaps in a new recovery key. The old recovery code stops working.
    pub fn replace_recovery(&mut self, recovery: &Key) -> Result<()> {
        self.slots.retain(|slot| slot.kind != FactorKind::Recovery);
        self.add_slot(FactorKind::Recovery, recovery)
    }

    pub fn slot_kinds(&self) -> Vec<FactorKind> {
        self.slots.iter().map(|slot| slot.kind).collect()
    }

    fn add_slot(&mut self, kind: FactorKind, factor: &Key) -> Result<()> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::TooManySlots);
        }
        let nonce: [u8; NONCE_LEN] = random_array()?;
        let wrapped = crypto::seal(factor, &nonce, self.vault_key.as_bytes(), &inner_aad(kind))?;
        let mut inner = [0u8; INNER_LEN];
        inner[..NONCE_LEN].copy_from_slice(&nonce);
        inner[NONCE_LEN..].copy_from_slice(&wrapped);
        self.slots.push(Slot { kind, inner });
        Ok(())
    }
}

// Redacted by hand, like `Key`: only non-secret details are shown.
impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("kdf", &self.kdf)
            .field("slots", &self.slot_kinds())
            .finish_non_exhaustive()
    }
}

fn unwrap_inner(slot: &Slot, factor: &Key) -> Option<Key> {
    let (nonce, wrapped) = slot.inner.split_at(NONCE_LEN);
    let nonce = nonce.try_into().ok()?;
    let key = crypto::open(factor, nonce, wrapped, &inner_aad(slot.kind))?;
    let bytes: &[u8; KEY_LEN] = key[..].try_into().ok()?;
    Some(Key::from_bytes(bytes))
}

/// The header fields every slot is bound to: format, KDF settings and salt.
fn kdf_context(kdf: &KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    out.extend_from_slice(&kdf.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf.p_cost.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

fn outer_aad(context: &[u8], kind: FactorKind) -> Vec<u8> {
    let mut aad = context.to_vec();
    aad.push(kind.to_byte());
    aad
}

fn inner_aad(kind: FactorKind) -> Vec<u8> {
    let mut aad = INNER_AAD_PREFIX.to_vec();
    aad.push(kind.to_byte());
    aad
}

/// Compares two keys in constant time, so how long the check takes reveals
/// nothing about where they differ.
fn keys_equal(a: &Key, b: &Key) -> bool {
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

struct RawSlot<'a> {
    kind: FactorKind,
    nonce: [u8; NONCE_LEN],
    outer: &'a [u8],
}

/// A vault file split into its fields, with nothing decrypted yet.
///
/// The `'a` lifetime says the slices borrow from the file bytes instead of
/// copying them, and the compiler guarantees they cannot outlive the file.
struct ParsedFile<'a> {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    slots: Vec<RawSlot<'a>>,
    body_nonce: [u8; NONCE_LEN],
    header_bytes: &'a [u8],
    body: &'a [u8],
}

impl<'a> ParsedFile<'a> {
    fn parse(file: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(file);
        if r.take(MAGIC.len()).ok() != Some(&MAGIC[..]) {
            return Err(Error::NotAVault);
        }
        let version = r.u16()?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if r.u8()? != KDF_ARGON2ID {
            return Err(Error::Malformed("unknown key derivation algorithm"));
        }
        let kdf = KdfParams {
            m_cost_kib: r.u32()?,
            t_cost: r.u32()?,
            p_cost: r.u32()?,
        };
        // Checked before any derivation runs.
        kdf.validate()?;
        let salt = r.array()?;

        let count = usize::from(r.u8()?);
        if count == 0 || count > MAX_SLOTS {
            return Err(Error::Malformed("bad unlock slot count"));
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(RawSlot {
                kind: FactorKind::from_byte(r.u8()?)?,
                nonce: r.array()?,
                outer: r.take(OUTER_LEN)?,
            });
        }

        let body_nonce = r.array()?;
        let header_len = r.position();
        let body = r.rest();
        if body.len() < TAG_LEN {
            return Err(Error::Malformed("file is truncated"));
        }
        Ok(Self {
            kdf,
            salt,
            slots,
            body_nonce,
            header_bytes: &file[..header_len],
            body,
        })
    }
}

/// Reads fields from the front of a byte slice. Every read checks the
/// length first, so a short or damaged file gives an error, never a panic.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&end| end <= self.buf.len());
        let end = end.ok_or(Error::Malformed("file is truncated"))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }
}
