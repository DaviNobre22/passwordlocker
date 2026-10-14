//! End-to-end tests of the vault file: every unlock path, every agreed
//! flow, and rejection of damaged or modified files.

use locker_core::{Error, FactorKind, KdfParams, Key, UnlockedVault};

const PASSWORD: &[u8] = b"correct horse battery staple";
const CONTENTS: &[u8] = b"{\"entries\":[]}";

/// Tiny Argon2 settings so tests run fast. Production settings get their
/// own test below.
fn fast() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

struct Fixture {
    device: Key,
    recovery: Key,
    file: Vec<u8>,
}

fn fixture() -> Fixture {
    let device = Key::generate().unwrap();
    let recovery = Key::generate().unwrap();
    let vault = UnlockedVault::create(PASSWORD, fast(), &device, &recovery).unwrap();
    let file = vault.seal(CONTENTS).unwrap();
    Fixture {
        device,
        recovery,
        file,
    }
}

#[test]
fn opens_with_password_and_device_key() {
    let f = fixture();
    let (_, contents) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    assert_eq!(&contents[..], CONTENTS);
}

#[test]
fn opens_with_password_and_recovery_key() {
    let f = fixture();
    let (_, contents) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Recovery, &f.recovery).unwrap();
    assert_eq!(&contents[..], CONTENTS);
}

#[test]
fn wrong_password_is_rejected() {
    let f = fixture();
    let err = UnlockedVault::open(&f.file, b"wrong", FactorKind::Device, &f.device).unwrap_err();
    assert!(matches!(err, Error::Unlock));
}

#[test]
fn wrong_or_mismatched_factor_is_rejected() {
    let f = fixture();
    let stranger = Key::generate().unwrap();
    for (kind, factor) in [
        (FactorKind::Device, &stranger),
        (FactorKind::Device, &f.recovery),
        (FactorKind::Recovery, &f.device),
    ] {
        let err = UnlockedVault::open(&f.file, PASSWORD, kind, factor).unwrap_err();
        assert!(matches!(err, Error::Unlock));
    }
}

#[test]
fn recovery_key_alone_is_not_enough() {
    let f = fixture();
    let err = UnlockedVault::open(&f.file, b"", FactorKind::Recovery, &f.recovery).unwrap_err();
    assert!(matches!(err, Error::Unlock));
}

#[test]
fn every_save_uses_fresh_nonces() {
    let f = fixture();
    let (vault, _) = UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    let a = vault.seal(CONTENTS).unwrap();
    let b = vault.seal(CONTENTS).unwrap();
    assert_ne!(a, b);
    for file in [a, b] {
        UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    }
}

#[test]
fn changing_password_keeps_both_factors_working() {
    let f = fixture();
    let (mut vault, _) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    vault
        .change_password(PASSWORD, b"new password", fast())
        .unwrap();
    let file = vault.seal(CONTENTS).unwrap();

    let err = UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &f.device).unwrap_err();
    assert!(matches!(err, Error::Unlock));
    UnlockedVault::open(&file, b"new password", FactorKind::Device, &f.device).unwrap();
    UnlockedVault::open(&file, b"new password", FactorKind::Recovery, &f.recovery).unwrap();
}

#[test]
fn changing_password_requires_the_current_one() {
    let f = fixture();
    let (mut vault, _) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    let err = vault.change_password(b"guess", b"new", fast()).unwrap_err();
    assert!(matches!(err, Error::Unlock));
}

#[test]
fn recovering_on_a_new_pc_adds_a_device_slot() {
    let f = fixture();
    let (mut vault, _) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Recovery, &f.recovery).unwrap();
    let new_device = Key::generate().unwrap();
    vault.add_device(&new_device).unwrap();
    let file = vault.seal(CONTENTS).unwrap();

    UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &new_device).unwrap();
    UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &f.device).unwrap();
}

#[test]
fn replacing_recovery_key_cancels_the_old_one() {
    let f = fixture();
    let (mut vault, _) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    let new_recovery = Key::generate().unwrap();
    vault.replace_recovery(&new_recovery).unwrap();
    assert_eq!(
        vault.slot_kinds(),
        [FactorKind::Device, FactorKind::Recovery]
    );
    let file = vault.seal(CONTENTS).unwrap();

    UnlockedVault::open(&file, PASSWORD, FactorKind::Recovery, &new_recovery).unwrap();
    let err = UnlockedVault::open(&file, PASSWORD, FactorKind::Recovery, &f.recovery).unwrap_err();
    assert!(matches!(err, Error::Unlock));
}

#[test]
fn slot_count_is_capped() {
    let f = fixture();
    let (mut vault, _) =
        UnlockedVault::open(&f.file, PASSWORD, FactorKind::Device, &f.device).unwrap();
    while vault.slot_kinds().len() < locker_core::MAX_SLOTS {
        vault.add_device(&Key::generate().unwrap()).unwrap();
    }
    let err = vault.add_device(&Key::generate().unwrap()).unwrap_err();
    assert!(matches!(err, Error::TooManySlots));
}

#[test]
fn flipping_any_byte_makes_the_file_fail_to_open() {
    let f = fixture();
    let body_start = f.file.len() - (CONTENTS.len() + 16);
    for i in 0..f.file.len() {
        let mut tampered = f.file.clone();
        tampered[i] ^= 0x01;
        let result = UnlockedVault::open(&tampered, PASSWORD, FactorKind::Device, &f.device);
        let err = result
            .err()
            .unwrap_or_else(|| panic!("byte {i} flipped but file opened"));
        if i >= body_start {
            assert!(matches!(err, Error::Corrupt), "byte {i}: {err:?}");
        }
    }
}

#[test]
fn header_only_tampering_is_detected() {
    let f = fixture();
    // The body nonce is the last header field, just before the body.
    let body_nonce_byte = f.file.len() - (CONTENTS.len() + 16) - 1;
    let mut tampered = f.file.clone();
    tampered[body_nonce_byte] ^= 0x80;
    let err = UnlockedVault::open(&tampered, PASSWORD, FactorKind::Device, &f.device).unwrap_err();
    assert!(matches!(err, Error::Corrupt));
}

#[test]
fn every_truncation_is_rejected_without_panicking() {
    let f = fixture();
    for len in 0..f.file.len() {
        let result = UnlockedVault::open(&f.file[..len], PASSWORD, FactorKind::Device, &f.device);
        assert!(result.is_err(), "truncated to {len} bytes but opened");
    }
}

#[test]
fn non_vault_files_are_recognised() {
    let err = UnlockedVault::open(
        b"hello",
        PASSWORD,
        FactorKind::Device,
        &Key::generate().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::NotAVault));
}

#[test]
fn newer_format_versions_are_refused() {
    let f = fixture();
    let mut file = f.file.clone();
    file[4..6].copy_from_slice(&2u16.to_le_bytes());
    let err = UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &f.device).unwrap_err();
    assert!(matches!(err, Error::UnsupportedVersion(2)));
}

#[test]
fn oversized_kdf_settings_are_refused_before_deriving() {
    let f = fixture();
    let mut file = f.file.clone();
    // m_cost sits right after magic, version and the KDF id.
    file[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
    let err = UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &f.device).unwrap_err();
    assert!(matches!(err, Error::InvalidKdfParams));
}

#[test]
fn production_settings_round_trip() {
    let device = Key::generate().unwrap();
    let recovery = Key::generate().unwrap();
    let vault = UnlockedVault::create(PASSWORD, KdfParams::DEFAULT, &device, &recovery).unwrap();
    let file = vault.seal(CONTENTS).unwrap();
    let (_, contents) = UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &device).unwrap();
    assert_eq!(&contents[..], CONTENTS);
}

/// Run with `cargo test --release -p locker-core -- --ignored --nocapture`
/// to see how long one unlock takes with the default settings.
#[test]
#[ignore]
fn time_default_unlock() {
    let device = Key::generate().unwrap();
    let recovery = Key::generate().unwrap();
    let vault = UnlockedVault::create(PASSWORD, KdfParams::DEFAULT, &device, &recovery).unwrap();
    let file = vault.seal(CONTENTS).unwrap();
    let start = std::time::Instant::now();
    UnlockedVault::open(&file, PASSWORD, FactorKind::Device, &device).unwrap();
    println!("unlock took {:?}", start.elapsed());
}
