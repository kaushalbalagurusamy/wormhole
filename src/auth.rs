//! The optional shared secret between hub and daemon. On the WebSocket upgrade the daemon
//! sends a fresh nonce; the hub answers with its own nonce and a proof over both, and the
//! daemon sends its proof in its first frame. A proof is HMAC-SHA256 under the secret over
//! the prover's role and both nonces, so it cannot be replayed or reflected. This
//! authenticates the two ends; it does not encrypt anything.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Request header with the daemon's nonce; response header with the hub's.
pub const NONCE_HEADER: &str = "x-wormhole-nonce";
/// Response header with the hub's proof.
pub const PROOF_HEADER: &str = "x-wormhole-proof";

fn mac(secret: &str, role: &str, daemon_nonce: &str, hub_nonce: &str) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    m.update(format!("wormhole {role}\n{daemon_nonce}\n{hub_nonce}").as_bytes());
    m
}

/// Hex proof that `role` ("hub" or "daemon") holds `secret`, for this pair of nonces.
pub fn proof(secret: &str, role: &str, daemon_nonce: &str, hub_nonce: &str) -> String {
    hex(&mac(secret, role, daemon_nonce, hub_nonce)
        .finalize()
        .into_bytes())
}

/// Check a hex proof in constant time.
pub fn verify(secret: &str, role: &str, daemon_nonce: &str, hub_nonce: &str, proof: &str) -> bool {
    unhex(proof).is_some_and(|p| {
        mac(secret, role, daemon_nonce, hub_nonce)
            .verify_slice(&p)
            .is_ok()
    })
}

/// 32 random bytes from `/dev/urandom`, as hex.
pub(crate) fn random_hex() -> Result<String, String> {
    use std::io::Read;
    let mut raw = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(hex(&raw))
}

/// A nonce as `random_hex` makes it.
pub(crate) fn is_nonce(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_bind_secret_role_and_both_nonces() {
        let (d, h) = ("a".repeat(64), "b".repeat(64));
        let p = proof("s", "hub", &d, &h);
        assert!(verify("s", "hub", &d, &h, &p));
        assert!(!verify("t", "hub", &d, &h, &p));
        assert!(!verify("s", "daemon", &d, &h, &p));
        assert!(!verify("s", "hub", &h, &d, &p));
        assert!(!verify("s", "hub", &d, &h, &p[..62]));
        assert!(!verify("s", "hub", &d, &h, ""));
        assert!(!verify("s", "hub", &d, &h, &"zz".repeat(32)));
        let n = random_hex().unwrap();
        assert!(is_nonce(&n) && n != random_hex().unwrap());
    }
}
