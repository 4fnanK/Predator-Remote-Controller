//! The tray executable embedded into the single-file release (`--features embed-tray`).
//!
//! `scripts/build.ps1` builds `predator-tray.exe` first and then the service with
//! `PREDATOR_EMBED_TRAY=<path to that file>`; build.rs records its SHA-256 in
//! `PREDATOR_EMBED_TRAY_SHA256`. The bytes live in the read-only data section of the image: they
//! are never touched (so never paged in) unless setup extracts them, which keeps the installed
//! service's memory use unchanged.

use super::sha256;

#[cfg(feature = "embed-tray")]
static TRAY_EXE: &[u8] = include_bytes!(env!("PREDATOR_EMBED_TRAY"));
#[cfg(feature = "embed-tray")]
const TRAY_EXE_SHA256: &str = env!("PREDATOR_EMBED_TRAY_SHA256");

/// The embedded tray image and the SHA-256 that build.rs computed for it.
#[derive(Clone, Copy)]
pub(crate) struct Embedded {
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}

/// The embedded tray, or `None` in a build without the `embed-tray` feature.
pub(crate) fn tray() -> Option<Embedded> {
    #[cfg(feature = "embed-tray")]
    {
        Some(Embedded { bytes: TRAY_EXE, sha256: TRAY_EXE_SHA256 })
    }
    #[cfg(not(feature = "embed-tray"))]
    {
        None
    }
}

/// Check that embedded bytes still have the hash recorded at build time (a damaged download or
/// a modified file is caught before anything is written).
pub(crate) fn verify(e: &Embedded) -> Result<&'static [u8], String> {
    let actual = sha256::hex_digest(e.bytes);
    if !actual.eq_ignore_ascii_case(e.sha256) {
        return Err(format!(
            "the tray program embedded in this file is damaged (SHA-256 {actual}, expected {}). Download the release \
             again.",
            e.sha256
        ));
    }
    if e.bytes.len() < 2 || &e.bytes[..2] != b"MZ" {
        return Err("the tray program embedded in this file is not a Windows executable".into());
    }
    Ok(e.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_detects_damage() {
        static GOOD: &[u8] = b"MZ\x90\x00 fake image";
        let hash: &'static str = Box::leak(sha256::hex_digest(GOOD).into_boxed_str());
        assert!(verify(&Embedded { bytes: GOOD, sha256: hash }).is_ok());
        let upper: &'static str = Box::leak(hash.to_ascii_uppercase().into_boxed_str());
        assert!(verify(&Embedded { bytes: GOOD, sha256: upper }).is_ok());
        let e = verify(&Embedded { bytes: b"MZ\x90\x00 fake imagf", sha256: hash }).unwrap_err();
        assert!(e.contains("damaged"), "{e}");
        static NOT_PE: &[u8] = b"hello";
        let h2: &'static str = Box::leak(sha256::hex_digest(NOT_PE).into_boxed_str());
        assert!(verify(&Embedded { bytes: NOT_PE, sha256: h2 }).unwrap_err().contains("not a Windows executable"));
    }

    #[test]
    fn feature_state() {
        // A build with the feature always carries a verified image; without it there is none.
        let t = tray();
        assert_eq!(t.is_some(), cfg!(feature = "embed-tray"));
        if let Some(e) = t {
            assert!(verify(&e).is_ok());
        }
    }
}
