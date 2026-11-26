//! Cryptographically secure randomness from the OS (BCryptGenRandom, system-preferred RNG).

use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

/// Fill `buf` with secure random bytes. Panics only if the OS RNG fails (never expected).
pub fn fill(buf: &mut [u8]) {
    let status = unsafe {
        BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    assert!(status >= 0, "BCryptGenRandom failed: {status:#x}");
}

/// Lower-case hex string of `nbytes` random bytes.
pub fn hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `n` random decimal digits (uniform, rejection sampled).
pub fn digits(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let mut b = [0u8; 16];
        fill(&mut b);
        for x in b {
            if x < 250 && out.len() < n {
                out.push(char::from(b'0' + x % 10));
            }
        }
    }
    out
}

/// Random u64.
pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let h = hex(16);
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hex(16), hex(16));
        let d = digits(6);
        assert_eq!(d.len(), 6);
        assert!(d.chars().all(|c| c.is_ascii_digit()));
    }
}
