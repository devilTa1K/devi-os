use crate::auth_config::{HASH, ROUNDS, SALT};
use sha2::{Digest, Sha256};

/// Salted, iterated SHA-256. It must match setup-auth.ps1 exactly:
/// h = SHA256(salt || pass), then ROUNDS-1 times h = SHA256(h || salt || pass).
fn derive(pass: &[u8]) -> [u8; 32] {
    let mut first = Sha256::new();
    first.update(SALT);
    first.update(pass);
    let mut cur = [0u8; 32];
    cur.copy_from_slice(&first.finalize());
    for _ in 1..ROUNDS {
        let mut h = Sha256::new();
        h.update(cur);
        h.update(SALT);
        h.update(pass);
        cur.copy_from_slice(&h.finalize());
    }
    cur
}

/// Constant-time comparison: it never exits early on the first mismatch.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    core::hint::black_box(diff) == 0
}

/// True if `pass` matches the configured passphrase.
pub fn verify(pass: &[u8]) -> bool {
    if pass.is_empty() || pass.len() > 64 {
        return false;
    }
    ct_eq(&derive(pass), &HASH)
}
