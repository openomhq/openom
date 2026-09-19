//! Root-key derivation: pin the frozen `openom:*` HKDF labels, delegating the Argon2id→HKDF split to
//! [`keyeo_crypto::derive_root`].
//!
//! The generic construction (one Argon2id master, then HKDF-SHA256 into sibling KEK / Ed25519
//! identity / X25519 HPKE keys) lives in `keyeo_crypto::root`. What stays HERE is openom's
//! **frozen** domain: the three `openom:*` labels a second implementation must reproduce
//! byte-for-byte. (The RVK label `keyeo:rvk:v1` is engine-neutral and owned by keyeo-crypto;
//! [`derive_rvk`](keyeo_crypto::derive_rvk) is re-exported unchanged.)

use keyeo_crypto::{KdfParams, RootKeys, RootLabels};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::CryptoError;

/// HKDF `info` label for the KEK. **Frozen.**
const HKDF_KEK_INFO: &[u8] = b"openom:kek:v1";
/// HKDF `info` label for the owner identity seed. **Frozen.**
const HKDF_IDENTITY_INFO: &[u8] = b"openom:identity:v1";
/// HKDF `info` label for the HPKE keypair IKM. **Frozen.**
const HKDF_HPKE_INFO: &[u8] = b"openom:hpke:v1";

/// The frozen openom label set fed to [`keyeo_crypto::derive_root`].
const OPENOM_ROOT_LABELS: RootLabels = RootLabels {
    kek: HKDF_KEK_INFO,
    identity: HKDF_IDENTITY_INFO,
    hpke: HKDF_HPKE_INFO,
};

/// Derive [`RootKeys`] from a passphrase under the frozen `openom:*` HKDF labels, delegating to
/// [`keyeo_crypto::derive_root`].
///
/// see that crate for the frozen construction and the zeroize-on-drop
/// guarantees.
///
///
/// # Errors
/// Returns [`CryptoError`] if Argon2id derivation fails.
pub fn derive_root(passphrase: &[u8], params: &KdfParams) -> Result<RootKeys, CryptoError> {
    keyeo_crypto::derive_root(passphrase, params, &OPENOM_ROOT_LABELS)
}

/// Derive [`RootKeys`] from a **stored-random account root** (32 bytes) under the frozen `openom:*` labels —
/// the durable-identity path (OPE-542). Unlike [`derive_root`], the master is the account root, NOT
/// Argon2id(passphrase), so the identity + HPKE keys (and thus `member_id`) stay stable across passphrase
/// changes; the passphrase only unwraps the account root. Byte-identical HKDF split to [`derive_root`].
#[must_use]
pub fn derive_account_keys(account_root: &[u8; 32]) -> RootKeys {
    keyeo_crypto::derive_root_from_master(account_root, &OPENOM_ROOT_LABELS)
}

/// A fresh random 256-bit **account root** — the durable-identity master (OPE-542). One per user profile,
/// stored wrapped under the passphrase- and recovery-code-KEKs; `member_id`/identity derive from it via
/// [`derive_account_keys`].
///
/// # Errors
/// Returns [`CryptoError::Rng`] if the system RNG fails.
pub fn generate_account_root() -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut root = Zeroizing::new([0u8; 32]);
    getrandom::fill(root.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(root)
}

/// The user-level `member_id`: `uuid8(SHA-256(author_pubkey)[..16])` — self-certifying (an admission point can
/// recompute it from the carried key), squat-proof, and stable across passphrase changes / trees / devices
/// (the identity key never changes). `UUIDv8` layout (version nibble + `RFC-4122` variant bits), lowercase-hex
/// canonical form. Shared by the vault (mint), the server (`/register` verification), and the client.
#[must_use]
pub fn derive_member_id(author_pubkey: &[u8]) -> String {
    let digest = Sha256::digest(author_pubkey);
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x80; // UUID version 8
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant (10xx)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use edsign::SigningKey;
    use keyeo_crypto::generate_salt;

    fn cheap(salt: Vec<u8>) -> KdfParams {
        KdfParams { salt, memory_kib: 8, iterations: 1, parallelism: 1 }
    }
    fn params() -> KdfParams {
        cheap(vec![7u8; 16])
    }

    #[test]
    fn frozen_labels_are_unchanged() {
        // A silent relabel would break every existing account's derivation. Pin the bytes.
        assert_eq!(HKDF_KEK_INFO, b"openom:kek:v1");
        assert_eq!(HKDF_IDENTITY_INFO, b"openom:identity:v1");
        assert_eq!(HKDF_HPKE_INFO, b"openom:hpke:v1");
    }

    #[test]
    fn wrapper_is_deterministic_and_uses_distinct_labels() {
        let a = derive_root(b"correct horse", &params()).unwrap();
        let b = derive_root(b"correct horse", &params()).unwrap();
        assert_eq!(a.kek.expose(), b.kek.expose());
        assert_eq!(
            a.identity.verifying_key().to_bytes(),
            b.identity.verifying_key().to_bytes()
        );
        // KEK / identity / HPKE are siblings (distinct labels), so none coincides with another.
        assert_ne!(
            SigningKey::from_seed(a.kek.expose()).verifying_key().to_bytes(),
            a.identity.verifying_key().to_bytes()
        );
        assert_ne!(a.kek.expose(), a.hpke_secret.expose());
    }

    #[test]
    fn the_hpke_keypair_is_usable() {
        use keyeo_crypto::{hpke_unwrap_dek, hpke_wrap_dek, Dek, KEY_LEN};
        let salt = generate_salt().unwrap().to_vec();
        let r = derive_root(b"member pass", &cheap(salt)).unwrap();
        let w = hpke_wrap_dek(&r.hpke_public, &Dek::new([9u8; KEY_LEN]), b"info").unwrap();
        let out = hpke_unwrap_dek(r.hpke_secret.expose(), w.encapped_key.as_ref(), w.ciphertext.as_ref(), b"info").unwrap();
        assert_eq!(out.expose(), &[9u8; KEY_LEN]);
    }
}
