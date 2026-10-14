//! Core of passwordlocker: everything that touches secrets lives here.
//!
//! This crate has no UI and no knowledge of Tauri, so it can be tested on
//! its own and reused by other front ends.

#![forbid(unsafe_code)]

mod contents;
mod crypto;
mod entry;
mod error;
mod generator;
mod locker;
mod recovery_code;
mod secret;
mod storage;
mod strength;
mod vault_file;

pub use contents::{CONTENTS_VERSION, VaultContents};
pub use crypto::{KdfParams, Key};
pub use entry::{Entry, EntryDraft, EntryId, EntrySummary, MAX_PASSWORD_HISTORY, PastPassword};
pub use error::{Error, Result};
pub use generator::{
    CharOptions, PassphraseOptions, generate_passphrase, generate_password, random_below,
};
pub use locker::Locker;
pub use secret::SecretString;
pub use storage::{DEFAULT_BACKUPS, read_file, write_atomic, write_with_backups};
pub use strength::{MIN_MASTER_PASSWORD_CHARS, check_master_password};
pub use vault_file::{FORMAT_VERSION, FactorKind, MAX_SLOTS, UnlockedVault};
// Renamed on export: a bare `encode`/`decode` at the crate root would be
// ambiguous next to the other encoders in this crate.
pub use recovery_code::{decode as decode_recovery_code, encode as encode_recovery_code};

/// Version of the core library, taken from `Cargo.toml` at compile time.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(version(), "0.1.0");
    }
}
