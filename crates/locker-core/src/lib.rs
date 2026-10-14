//! Core of passwordlocker: everything that touches secrets lives here.
//!
//! This crate has no UI and no knowledge of Tauri, so it can be tested on
//! its own and reused by other front ends.

#![forbid(unsafe_code)]

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
