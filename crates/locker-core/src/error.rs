/// Everything that can go wrong in the core.
///
/// Variants never carry secret bytes, so errors are always safe to log or
/// show in the window.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this file is not a passwordlocker vault")]
    NotAVault,

    #[error("vault format version {0} is not supported by this version of the app")]
    UnsupportedVersion(u16),

    #[error("the vault file is damaged: {0}")]
    Malformed(&'static str),

    /// Deliberately vague: telling an attacker which of the two was wrong
    /// would help them.
    #[error("wrong password or second factor")]
    Unlock,

    /// The keys were right but the encrypted contents did not verify, so the
    /// file was damaged or modified after it was written.
    #[error("the vault contents failed their integrity check")]
    Corrupt,

    #[error("the vault already has the maximum number of unlock slots")]
    TooManySlots,

    #[error("key derivation settings are out of the allowed range")]
    InvalidKdfParams,

    #[error("the operating system's random number generator failed")]
    Random,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("vault contents format version {0} is not supported by this version of the app")]
    UnsupportedContentsVersion(u32),

    #[error("no entry with that id")]
    EntryNotFound,

    #[error("invalid entry: {0}")]
    InvalidEntry(&'static str),

    #[error("invalid generator settings: {0}")]
    InvalidGeneratorOptions(&'static str),

    /// `feedback` is advice from the strength checker. It is built from
    /// fixed texts and never contains any part of the password.
    #[error("the master password is too weak: {feedback}")]
    WeakPassword { feedback: String },

    #[error("a vault file already exists at that location")]
    VaultExists,
}

pub type Result<T> = std::result::Result<T, Error>;
