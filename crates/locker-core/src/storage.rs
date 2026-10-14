//! Reading and writing the vault file on disk.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::error::Result;

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// Replaces the file at `path` with `bytes` so that, even after a crash or
/// power cut, the file holds either the old contents or the new ones, never
/// a mix.
///
/// The bytes go to a temporary file next to the target, are flushed to the
/// disk, and the temporary file is then renamed over the target in a single
/// step.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(path)?;
    let result = write_synced(&tmp, bytes).and_then(|()| rename_with_retry(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

fn temp_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "vault path has no file name")
    })?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    Ok(path.with_file_name(tmp_name))
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    // Without this the data may still be sitting in a cache when the rename
    // happens, and a power cut could leave an empty file behind.
    file.sync_all()
}

/// On Windows, antivirus scanners and sync tools like OneDrive sometimes
/// hold a file open for a moment, which makes the rename fail with "access
/// denied" or a sharing violation. Retrying briefly gets past that.
fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    const ATTEMPTS: u64 = 5;
    for attempt in 1..=ATTEMPTS {
        match fs::rename(from, to) {
            Err(err) if is_file_busy(&err) && attempt < ATTEMPTS => {
                thread::sleep(Duration::from_millis(50 * attempt));
            }
            result => return result,
        }
    }
    unreachable!("the last attempt always returns")
}

fn is_file_busy(err: &io::Error) -> bool {
    // 32 is ERROR_SHARING_VIOLATION and 33 is ERROR_LOCK_VIOLATION. Rust has
    // no portable name for them, so they are matched by their Windows codes.
    err.kind() == io::ErrorKind::PermissionDenied || matches!(err.raw_os_error(), Some(32 | 33))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file_and_replaces_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pwlk");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(read_file(&path).unwrap(), b"first");

        write_atomic(&path, b"second").unwrap();
        assert_eq!(read_file(&path).unwrap(), b"second");
    }

    #[test]
    fn leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pwlk");
        write_atomic(&path, b"data").unwrap();

        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["vault.pwlk"]);
    }
}
