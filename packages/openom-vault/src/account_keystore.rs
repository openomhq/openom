//! The **account keystore** — openom's durable, user-level identity (OPE-542).
//!
//! One keystore per local profile. It holds a stored-random **account root** (the identity master, 32 bytes)
//! wrapped under two credentials — the passphrase-KEK and the recovery-code-KEK — plus the plaintext public
//! fields (`member_id`, author + HPKE public keys) the unlock gate reads *synchronously, before any KDF*.
//!
//! The identity is derived from the account root ([`openom_crypto::derive_account_keys`]), NOT from the
//! passphrase, so `member_id = uuid8(SHA-256(author_pubkey))` is **stable** across passphrase changes, trees,
//! and devices — a user-level identity, decoupled from any one tree (the property the Supabase `sub → member_id`
//! binding needs). Model-1 of `design.durable-identity-dag.md` (identity *derived from* the root; the root is
//! the single stored-random master — the `ADR-004` refinement, simpler than a wrapped-identity layer since
//! true crypto-revocation of a durable identity is impossible anyway; anti-rollback is the `generation` floor).
//!
//! Reuses the keyeo `Wrap`/`kek_wrap`/`KekKind` primitives verbatim (a sibling of
//! [`crate::vault_core::RecoveryEscrow`]); the only new wire artifact is this record. `generation` rides the
//! wraps' `group_id` AAD scope, so a forged plaintext `generation` fails the unwrap.

use keyeo_crypto::{
    kek_wrap as keyeo_kek_wrap, unwrap_kek as keyeo_unwrap_kek, GroupId as KeyeoGroupId,
    KdfParams as KeyeoKdfParams, KekKind, Wrap as KeyeoWrap, WrapMethod as KeyeoWrapMethod,
};
use openom_crypto::{
    default_kdf_params, derive_account_keys, derive_kek, derive_member_id, generate_account_root,
    generate_recovery_code, generate_salt, parse_recovery_code, recovery_kdf_params, RecoveryCode,
    RootKeys,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault_core::validated_kdf;
use crate::VaultError;

/// Domain tag pinned into the account-keystore wrap AAD scope, so an account-root wrap can never be confused
/// with a tree-scoped keyring wrap (whose `group_id` is a raw `tree_id`). **Frozen.**
const ACCOUNT_KEYSTORE_DOMAIN: &[u8] = b"openom:account-keystore:v1";

/// The account keystore record (serde wire; a sibling of [`crate::vault_core::RecoveryEscrow`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeystore {
    /// `uuid8(SHA-256(author_public))` — plaintext, read by the synchronous unlock gate.
    pub member_id: String,
    /// Ed25519 identity public key (32 bytes) — plaintext; verified against the unwrapped identity on unlock.
    pub author_public: Vec<u8>,
    /// X25519 HPKE public key (32 bytes) — plaintext; verified on unlock.
    pub hpke_public: Vec<u8>,
    /// Monotonic anti-rollback counter, bound into the wraps' AAD scope; the client/server floor on it.
    pub generation: u64,
    /// The account root, KEK-wrapped once under the passphrase and once under the recovery code.
    pub wraps: Vec<KeyeoWrap<String>>,
}

/// An unlocked account: the derived [`RootKeys`] (identity / HPKE / KEK) plus the raw account root retained for
/// re-wrapping on a passphrase change. Zeroizes the root on drop.
pub struct UnlockedAccount {
    /// The identity / HPKE / KEK keys derived from the account root.
    pub root: RootKeys,
    /// The stable user-level `member_id`.
    pub member_id: String,
    /// The account root master (kept so [`AccountKeystore::change_passphrase`] can re-wrap without re-minting).
    account_root: Zeroizing<[u8; 32]>,
}

/// The AAD binding scope for an account-keystore wrap: `⟨domain ‖ member_id ‖ generation_le⟩`. `member_id` is a
/// fixed-length uuid8 and `generation` a fixed 8 bytes, so the concatenation is injective. Binding `generation`
/// here is what authenticates the plaintext `generation` field (a forged value makes the unwrap fail).
fn account_group_id(member_id: &str, generation: u64) -> KeyeoGroupId {
    let mut v =
        Vec::with_capacity(ACCOUNT_KEYSTORE_DOMAIN.len() + member_id.len() + core::mem::size_of::<u64>());
    v.extend_from_slice(ACCOUNT_KEYSTORE_DOMAIN);
    v.extend_from_slice(member_id.as_bytes());
    v.extend_from_slice(&generation.to_le_bytes());
    KeyeoGroupId::new(v)
}

/// Find the KEK wrap for a credential source, returning its validated KDF params + the wrap.
fn wrap_for(
    wraps: &[KeyeoWrap<String>],
    kind: KekKind,
) -> Result<(&KeyeoWrap<String>, KeyeoKdfParams), VaultError> {
    let wrap = wraps
        .iter()
        .find(|w| matches!(&w.method, KeyeoWrapMethod::Kek { kind: k, .. } if *k == kind))
        .ok_or(VaultError::MissingWrap)?;
    match &wrap.method {
        KeyeoWrapMethod::Kek { kdf, .. } => Ok((wrap, validated_kdf(kdf)?)),
        _ => Err(VaultError::MissingWrap),
    }
}

impl AccountKeystore {
    /// Mint a brand-new account: a fresh random account root, its derived identity, and both credential wraps.
    /// Returns the keystore, the one-time recovery code (show once), and the unlocked account.
    ///
    /// # Errors
    /// [`VaultError`] on RNG / KDF / wrap failure.
    pub fn create(passphrase: &[u8]) -> Result<(Self, RecoveryCode, UnlockedAccount), VaultError> {
        let account_root = generate_account_root()?;
        let root = derive_account_keys(&account_root);
        let author_public = root.identity.verifying_key().to_bytes().to_vec();
        let hpke_public = root.hpke_public.to_vec();
        let member_id = derive_member_id(&author_public);
        let generation = 0u64;
        let gid = account_group_id(&member_id, generation);

        let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
        let pass_kek = derive_kek(passphrase, &pass_kdf)?;
        let pass_wrap = keyeo_kek_wrap(
            account_root.as_slice(),
            member_id.clone(),
            KekKind::Passphrase,
            &pass_kek,
            pass_kdf,
            &gid,
        )?;

        let recovery_code = generate_recovery_code()?;
        let entropy = parse_recovery_code(&recovery_code)?;
        let rec_kdf = recovery_kdf_params(generate_salt()?.to_vec());
        let rec_kek = derive_kek(entropy.as_slice(), &rec_kdf)?;
        let rec_wrap = keyeo_kek_wrap(
            account_root.as_slice(),
            member_id.clone(),
            KekKind::RecoveryCode,
            &rec_kek,
            rec_kdf,
            &gid,
        )?;

        let keystore = Self {
            member_id: member_id.clone(),
            author_public,
            hpke_public,
            generation,
            wraps: vec![pass_wrap, rec_wrap],
        };
        let unlocked = UnlockedAccount { root, member_id, account_root };
        Ok((keystore, recovery_code, unlocked))
    }

    /// Unlock with the passphrase.
    ///
    /// # Errors
    /// [`VaultError`] if the passphrase is wrong, the KDF params are out of window, or the unwrapped identity
    /// does not match the plaintext public fields (tamper / forged-`generation` detection).
    pub fn unlock(&self, passphrase: &[u8]) -> Result<UnlockedAccount, VaultError> {
        self.unlock_with(passphrase, KekKind::Passphrase)
    }

    /// Unlock with the printed recovery code.
    ///
    /// # Errors
    /// As [`Self::unlock`], plus a malformed recovery code.
    pub fn unlock_with_recovery(&self, code: &RecoveryCode) -> Result<UnlockedAccount, VaultError> {
        let entropy = parse_recovery_code(code)?;
        self.unlock_with(entropy.as_slice(), KekKind::RecoveryCode)
    }

    fn unlock_with(&self, secret: &[u8], kind: KekKind) -> Result<UnlockedAccount, VaultError> {
        let (wrap, kdf) = wrap_for(&self.wraps, kind)?;
        let kek = derive_kek(secret, &kdf)?;
        let gid = account_group_id(&self.member_id, self.generation);
        let unwrapped = keyeo_unwrap_kek(wrap, &kek, &gid)?;
        let account_root = Zeroizing::new(*unwrapped);
        let root = derive_account_keys(&account_root);
        self.verify_public_fields(&root)?;
        Ok(UnlockedAccount {
            root,
            member_id: self.member_id.clone(),
            account_root,
        })
    }

    /// Re-wrap the account root under a NEW passphrase, keeping the same identity/`member_id` and the existing
    /// recovery wrap. Per `keyring-rekey-boundary` this is a re-wrap, not a rotation — `generation` is
    /// unchanged (the revocation/floor path lands with the rotate task).
    ///
    /// # Errors
    /// [`VaultError`] on KDF / wrap failure or a missing recovery wrap.
    pub fn change_passphrase(
        &self,
        unlocked: &UnlockedAccount,
        new_passphrase: &[u8],
    ) -> Result<Self, VaultError> {
        let gid = account_group_id(&self.member_id, self.generation);
        let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
        let pass_kek = derive_kek(new_passphrase, &pass_kdf)?;
        let pass_wrap = keyeo_kek_wrap(
            unlocked.account_root.as_slice(),
            self.member_id.clone(),
            KekKind::Passphrase,
            &pass_kek,
            pass_kdf,
            &gid,
        )?;
        let (rec_wrap, _) = wrap_for(&self.wraps, KekKind::RecoveryCode)?;
        Ok(Self {
            member_id: self.member_id.clone(),
            author_public: self.author_public.clone(),
            hpke_public: self.hpke_public.clone(),
            generation: self.generation,
            wraps: vec![pass_wrap, rec_wrap.clone()],
        })
    }

    /// Serialize to the persisted blob (JSON). The JS/host layer stores these bytes at rest and hands them back
    /// to [`Self::from_bytes`] on open — openom-vault does not itself touch storage (per the "let the platform
    /// persist" boundary). The wrapped account root is the only secret; the rest is public.
    ///
    /// # Errors
    /// [`VaultError`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self)
            .map_err(|e| VaultError::BadKeyring(format!("account keystore encode: {e}")))
    }

    /// Load a keystore from its persisted blob.
    ///
    /// # Errors
    /// [`VaultError`] if the bytes are not a valid keystore.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        serde_json::from_slice(bytes)
            .map_err(|e| VaultError::BadKeyring(format!("account keystore decode: {e}")))
    }

    /// Verify the plaintext public fields against the identity derived from the unwrapped account root — closes
    /// the KDF-downgrade / pubkey-swap tamper vector: a mutated public field is rejected rather than trusted.
    fn verify_public_fields(&self, root: &RootKeys) -> Result<(), VaultError> {
        let author = root.identity.verifying_key().to_bytes();
        let ok = author.as_slice() == self.author_public.as_slice()
            && root.hpke_public.as_slice() == self.hpke_public.as_slice()
            && derive_member_id(&self.author_public) == self.member_id;
        if ok {
            Ok(())
        } else {
            Err(VaultError::BadKeyring(
                "account keystore public fields do not match the unwrapped identity".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass() -> &'static [u8] {
        b"correct horse battery staple"
    }

    #[test]
    fn create_then_unlock_roundtrips_the_identity() {
        let (ks, _code, unlocked) = AccountKeystore::create(pass()).unwrap();
        let again = ks.unlock(pass()).unwrap();
        assert_eq!(unlocked.member_id, again.member_id);
        assert_eq!(
            unlocked.root.identity.verifying_key().to_bytes(),
            again.root.identity.verifying_key().to_bytes()
        );
        assert_eq!(ks.member_id, derive_member_id(&ks.author_public));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (ks, _code, _u) = AccountKeystore::create(pass()).unwrap();
        assert!(ks.unlock(b"wrong passphrase").is_err());
    }

    #[test]
    fn recovery_code_unlocks_the_same_identity() {
        let (ks, code, unlocked) = AccountKeystore::create(pass()).unwrap();
        let via_code = ks.unlock_with_recovery(&code).unwrap();
        assert_eq!(unlocked.member_id, via_code.member_id);
        assert_eq!(
            unlocked.root.identity.verifying_key().to_bytes(),
            via_code.root.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn change_passphrase_keeps_member_id_and_recovery() {
        let (ks, code, unlocked) = AccountKeystore::create(pass()).unwrap();
        let ks2 = ks.change_passphrase(&unlocked, b"a brand new passphrase").unwrap();
        // member_id + identity unchanged
        assert_eq!(ks.member_id, ks2.member_id);
        assert_eq!(ks.author_public, ks2.author_public);
        // new passphrase opens it, old one no longer does, recovery code still does
        let u2 = ks2.unlock(b"a brand new passphrase").unwrap();
        assert_eq!(u2.member_id, ks.member_id);
        assert!(ks2.unlock(pass()).is_err());
        assert!(ks2.unlock_with_recovery(&code).is_ok());
    }

    #[test]
    fn tampered_author_public_is_rejected() {
        let (mut ks, _code, _u) = AccountKeystore::create(pass()).unwrap();
        ks.author_public[0] ^= 0xff; // flip a bit — plaintext claim no longer matches the wrapped identity
        assert!(ks.unlock(pass()).is_err());
    }

    #[test]
    fn persisted_blob_roundtrips_and_still_unlocks() {
        let (ks, code, unlocked) = AccountKeystore::create(pass()).unwrap();
        let bytes = ks.to_bytes().unwrap();
        let loaded = AccountKeystore::from_bytes(&bytes).unwrap();
        assert_eq!(ks, loaded);
        // the reloaded blob still opens with both credentials, to the same identity
        let via_pass = loaded.unlock(pass()).unwrap();
        let via_code = loaded.unlock_with_recovery(&code).unwrap();
        assert_eq!(via_pass.member_id, unlocked.member_id);
        assert_eq!(via_code.member_id, unlocked.member_id);
    }

    #[test]
    fn member_id_is_stable_uuid8_golden() {
        // Frozen: a fixed author pubkey → a fixed uuid8 member_id (version 8 + RFC-4122 variant nibbles).
        let pubkey = [7u8; 32];
        let id = derive_member_id(&pubkey);
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'8', "version nibble must be 8");
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'), "RFC-4122 variant");
        // determinism
        assert_eq!(id, derive_member_id(&pubkey));
    }
}
