//! The **account keystore** — openom's durable, user-level identity (OPE-542).
//!
//! One keystore per local profile. **Model 2** (`design.durable-identity-dag.md` / ADR-004): two independent
//! stored-random secrets —
//! - `identity_master` (32 bytes): HKDF-derives the identity ([`openom_crypto::derive_account_keys`] →
//!   Ed25519 signing + X25519 HPKE + a KEK); `member_id = uuid8(SHA-256(author_pubkey))`. It is the durable
//!   identity, never changed, so `member_id` is stable across passphrase changes / trees / devices (the
//!   property the Supabase `sub → member_id` binding needs).
//! - `account_root` (32 bytes): a wrapping KEK that seals `identity_master`. **Rotatable** — a fresh
//!   `account_root` re-wraps the *same* `identity_master`, so the storage layer can be re-keyed under new key
//!   material with the identity (and `member_id`) unchanged (the crypto-hygiene capability Model 2 exists for).
//!
//! Layers: `identity_master` is wrapped under `account_root` (the INNER wrap, `KekKind::AccountRoot`);
//! `account_root` is wrapped under the passphrase-KEK and the recovery-code-KEK (the OUTER wraps). The public
//! fields (`member_id`, author + HPKE pubkeys) are plaintext so the unlock gate reads them synchronously before
//! any KDF. `generation` rides the OUTER wraps' `group_id` AAD scope (an outer wrap is always opened on unlock,
//! so a forged plaintext `generation` fails). Reuses the keyeo `Wrap`/`kek_wrap`/`KekKind` primitives.

use keyeo_crypto::{
    kek_wrap as keyeo_kek_wrap, unwrap_kek as keyeo_unwrap_kek, GroupId as KeyeoGroupId,
    KdfParams as KeyeoKdfParams, KekKind, Wrap as KeyeoWrap, WrapMethod as KeyeoWrapMethod,
};
use openom_crypto::{
    default_kdf_params, derive_account_keys, derive_kek, generate_account_root,
    generate_recovery_code, generate_salt, parse_recovery_code, recovery_kdf_params, Kek,
    Passphrase, RecoveryCode, RootKeys,
};
use openom_keyring_api::derive_member_id;
use openom_protocol::ids::MemberId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault_core::validated_kdf;
use crate::VaultError;

/// AAD domain for the OUTER wraps (`account_root` under passphrase / recovery), carrying `generation`. Frozen.
const ROOT_DOMAIN: &[u8] = b"openom:account-keystore:v1:root";
/// AAD domain for the INNER wrap (`identity_master` under `account_root`). No `generation` — the identity
/// master never changes, and a root rotation re-creates this wrap from the unlocked material. Frozen.
const IDENTITY_DOMAIN: &[u8] = b"openom:account-keystore:v1:identity";

/// The account keystore record (serde wire; sibling of [`crate::vault_core::RecoveryEscrow`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeystore {
    /// `uuid8(SHA-256(author_public))` — plaintext, read by the synchronous unlock gate.
    pub member_id: String,
    /// Ed25519 identity public key (32 bytes) — plaintext; verified against the unwrapped identity on unlock.
    pub author_public: Vec<u8>,
    /// X25519 HPKE public key (32 bytes) — plaintext; verified on unlock.
    pub hpke_public: Vec<u8>,
    /// Monotonic anti-rollback counter, bound into the OUTER wraps' AAD scope; the client/server floor on it.
    pub generation: u64,
    /// Three KEK wraps: `account_root` under the passphrase KEK, `account_root` under the recovery-code KEK,
    /// and `identity_master` under `account_root` (`KekKind::AccountRoot`).
    pub wraps: Vec<KeyeoWrap<String>>,
}

/// An unlocked account: the derived [`RootKeys`] plus both raw masters, retained so `change_passphrase`
/// re-wraps `account_root` and a future root rotation re-wraps `identity_master`. Zeroized on drop.
pub struct UnlockedAccount {
    /// Identity / HPKE / KEK keys derived from `identity_master`.
    pub root: RootKeys,
    /// The stable user-level `member_id`.
    pub member_id: MemberId,
    /// The rotatable wrapping root (re-wrapped by `change_passphrase`).
    account_root: Zeroizing<[u8; 32]>,
    /// The durable identity master (re-wrapped, unchanged, by a root rotation).
    identity_master: Zeroizing<[u8; 32]>,
}

impl UnlockedAccount {
    /// Derive a fresh owned key bundle for a tree session while this account remains unlocked and reusable.
    /// The returned secrets are independent allocations and are zeroized by their owning types on drop.
    pub(crate) fn tree_root(&self) -> RootKeys {
        derive_account_keys(&self.identity_master)
    }
}

/// A placeholder KDF for the INNER wrap: its KEK is the raw `account_root` supplied directly at unwrap, so the
/// wrap's stored `kdf` is never used to re-derive anything (mirrors `vault_core::open_rrk_secret`).
fn inner_placeholder_kdf() -> KeyeoKdfParams {
    KeyeoKdfParams {
        salt: Vec::new(),
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    }
}

/// OUTER AAD scope: `⟨ROOT_DOMAIN ‖ member_id ‖ generation_le⟩`. Binds `generation` (authenticating the
/// plaintext field) and `member_id`; fixed-length uuid8 + fixed 8-byte generation ⇒ injective.
fn outer_group_id(member_id: &str, generation: u64) -> KeyeoGroupId {
    let mut v =
        Vec::with_capacity(ROOT_DOMAIN.len() + member_id.len() + core::mem::size_of::<u64>());
    v.extend_from_slice(ROOT_DOMAIN);
    v.extend_from_slice(member_id.as_bytes());
    v.extend_from_slice(&generation.to_le_bytes());
    KeyeoGroupId::new(v)
}

/// INNER AAD scope: `⟨IDENTITY_DOMAIN ‖ member_id⟩`.
fn inner_group_id(member_id: &str) -> KeyeoGroupId {
    let mut v = Vec::with_capacity(IDENTITY_DOMAIN.len() + member_id.len());
    v.extend_from_slice(IDENTITY_DOMAIN);
    v.extend_from_slice(member_id.as_bytes());
    KeyeoGroupId::new(v)
}

/// Find an OUTER KEK wrap for a credential source, returning it + its validated KDF params.
fn outer_wrap_for(
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

/// Find the INNER (`account_root`) wrap of the identity master.
fn inner_wrap(wraps: &[KeyeoWrap<String>]) -> Result<&KeyeoWrap<String>, VaultError> {
    wraps
        .iter()
        .find(|w| {
            matches!(
                &w.method,
                KeyeoWrapMethod::Kek {
                    kind: KekKind::AccountRoot,
                    ..
                }
            )
        })
        .ok_or(VaultError::MissingWrap)
}

impl AccountKeystore {
    /// Mint a brand-new account: independent random `identity_master` + `account_root`, the derived identity,
    /// the inner wrap, and both credential (outer) wraps. Returns the keystore, the one-time recovery code, and
    /// the unlocked account.
    ///
    /// # Errors
    /// [`VaultError`] on RNG / KDF / wrap failure.
    pub fn create(
        passphrase: &Passphrase,
    ) -> Result<(Self, RecoveryCode, UnlockedAccount), VaultError> {
        let identity_master = generate_account_root()?;
        let account_root = generate_account_root()?;
        let root = derive_account_keys(&identity_master);
        let author_public = root.identity.verifying_key().to_bytes().to_vec();
        let hpke_public = root.hpke_public.to_vec();
        let member_id = derive_member_id(&author_public);
        let generation = 0u64;

        // INNER: identity_master wrapped under account_root.
        let account_root_kek: Kek = Zeroizing::new(*account_root).into();
        let inner = keyeo_kek_wrap(
            identity_master.as_slice(),
            member_id.clone(),
            KekKind::AccountRoot,
            &account_root_kek,
            inner_placeholder_kdf(),
            &inner_group_id(&member_id),
        )?;

        // OUTER: account_root under the passphrase KEK + the recovery-code KEK.
        let outer_gid = outer_group_id(&member_id, generation);
        let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
        let pass_kek = derive_kek(passphrase.expose(), &pass_kdf)?;
        let pass_wrap = keyeo_kek_wrap(
            account_root.as_slice(),
            member_id.clone(),
            KekKind::Passphrase,
            &pass_kek,
            pass_kdf,
            &outer_gid,
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
            &outer_gid,
        )?;

        let keystore = Self {
            member_id: member_id.clone(),
            author_public,
            hpke_public,
            generation,
            wraps: vec![pass_wrap, rec_wrap, inner],
        };
        let unlocked = UnlockedAccount {
            root,
            member_id: MemberId::new(member_id),
            account_root,
            identity_master,
        };
        Ok((keystore, recovery_code, unlocked))
    }

    /// Unlock with the passphrase.
    ///
    /// # Errors
    /// [`VaultError`] if the passphrase is wrong, the KDF params are out of window, or the unwrapped identity
    /// does not match the plaintext public fields (tamper / forged-`generation` detection).
    pub fn unlock(&self, passphrase: &Passphrase) -> Result<UnlockedAccount, VaultError> {
        self.unlock_with(passphrase.expose(), KekKind::Passphrase)
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
        // OUTER: credential KEK → account_root.
        let (outer, kdf) = outer_wrap_for(&self.wraps, kind)?;
        let kek = derive_kek(secret, &kdf)?;
        let account_root = keyeo_unwrap_kek(
            outer,
            &kek,
            &outer_group_id(&self.member_id, self.generation),
        )?;
        let account_root = Zeroizing::new(*account_root);

        // INNER: account_root → identity_master.
        let account_root_kek: Kek = Zeroizing::new(*account_root).into();
        let identity_master = keyeo_unwrap_kek(
            inner_wrap(&self.wraps)?,
            &account_root_kek,
            &inner_group_id(&self.member_id),
        )?;
        let identity_master = Zeroizing::new(*identity_master);

        let root = derive_account_keys(&identity_master);
        self.verify_public_fields(&root)?;
        Ok(UnlockedAccount {
            root,
            member_id: MemberId::new(&self.member_id),
            account_root,
            identity_master,
        })
    }

    /// Re-wrap `account_root` under a NEW passphrase, keeping the same identity/`member_id`, the recovery wrap,
    /// and the inner wrap. Re-wrap, not rotate (per `keyring-rekey-boundary`) — `generation` unchanged.
    ///
    /// # Errors
    /// [`VaultError`] on KDF / wrap failure or a missing recovery/inner wrap.
    pub fn change_passphrase(
        &self,
        unlocked: &UnlockedAccount,
        new_passphrase: &Passphrase,
    ) -> Result<Self, VaultError> {
        let outer_gid = outer_group_id(&self.member_id, self.generation);
        let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
        let pass_kek = derive_kek(new_passphrase.expose(), &pass_kdf)?;
        let pass_wrap = keyeo_kek_wrap(
            unlocked.account_root.as_slice(),
            self.member_id.clone(),
            KekKind::Passphrase,
            &pass_kek,
            pass_kdf,
            &outer_gid,
        )?;
        let (rec_wrap, _) = outer_wrap_for(&self.wraps, KekKind::RecoveryCode)?;
        let inner = inner_wrap(&self.wraps)?;
        Ok(Self {
            member_id: self.member_id.clone(),
            author_public: self.author_public.clone(),
            hpke_public: self.hpke_public.clone(),
            generation: self.generation,
            wraps: vec![pass_wrap, rec_wrap.clone(), inner.clone()],
        })
    }

    /// Rotate the wrapping root (the Model-2 capability): mint a fresh `account_root`, re-wrap the SAME
    /// `identity_master` under it, and re-wrap the fresh root under `passphrase` + a FRESH recovery code, at a
    /// bumped `generation`. The identity and `member_id` are unchanged — this re-keys the storage layer only.
    /// Returns the new keystore and the new one-time recovery code. The client/server generation FLOOR that
    /// makes this a *revocation* (refuse a below-floor blob) is enforced in OPE-549, not here.
    ///
    /// # Errors
    /// [`VaultError`] on RNG / KDF / wrap failure.
    pub fn rotate_account_root(
        &self,
        unlocked: &UnlockedAccount,
        passphrase: &Passphrase,
    ) -> Result<(Self, RecoveryCode), VaultError> {
        let generation = self.generation.saturating_add(1);
        let account_root = generate_account_root()?;

        let account_root_kek: Kek = Zeroizing::new(*account_root).into();
        let inner = keyeo_kek_wrap(
            unlocked.identity_master.as_slice(),
            self.member_id.clone(),
            KekKind::AccountRoot,
            &account_root_kek,
            inner_placeholder_kdf(),
            &inner_group_id(&self.member_id),
        )?;

        let outer_gid = outer_group_id(&self.member_id, generation);
        let pass_kdf = default_kdf_params(generate_salt()?.to_vec());
        let pass_kek = derive_kek(passphrase.expose(), &pass_kdf)?;
        let pass_wrap = keyeo_kek_wrap(
            account_root.as_slice(),
            self.member_id.clone(),
            KekKind::Passphrase,
            &pass_kek,
            pass_kdf,
            &outer_gid,
        )?;
        let recovery_code = generate_recovery_code()?;
        let entropy = parse_recovery_code(&recovery_code)?;
        let rec_kdf = recovery_kdf_params(generate_salt()?.to_vec());
        let rec_kek = derive_kek(entropy.as_slice(), &rec_kdf)?;
        let rec_wrap = keyeo_kek_wrap(
            account_root.as_slice(),
            self.member_id.clone(),
            KekKind::RecoveryCode,
            &rec_kek,
            rec_kdf,
            &outer_gid,
        )?;

        Ok((
            Self {
                member_id: self.member_id.clone(),
                author_public: self.author_public.clone(),
                hpke_public: self.hpke_public.clone(),
                generation,
                wraps: vec![pass_wrap, rec_wrap, inner],
            },
            recovery_code,
        ))
    }

    /// Serialize to the persisted blob (JSON). The JS/host layer stores these bytes at rest and hands them back
    /// to [`Self::from_bytes`] on open — openom-vault does not itself touch storage. The wrapped roots are the
    /// only secrets; the rest is public.
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

    /// Refuse a keystore whose `generation` is below the client's floor — the CLIENT half of credential
    /// revocation (OPE-549). After [`Self::rotate_account_root`] bumps `generation` to lock out a leaked
    /// passphrase/recovery code, a malicious or merely stale server that served the pre-rotation blob would
    /// silently re-enable the revoked credential; the client, holding a persisted monotonic floor (the max
    /// generation it has ever seen for this account), refuses any blob beneath it. Equal is allowed — an
    /// idempotent re-fetch of the current blob. Floor *persistence* and the fetch call site are the session
    /// layer's (OPE-8); this is the pure, always-enforceable check, mirroring the server's PUT floor.
    ///
    /// # Errors
    /// [`VaultError::KeystoreGenerationRollback`] if `self.generation < floor`.
    pub fn check_generation_floor(&self, floor: u64) -> Result<(), VaultError> {
        if self.generation < floor {
            return Err(VaultError::KeystoreGenerationRollback {
                floor,
                got: self.generation,
            });
        }
        Ok(())
    }

    /// Decode a keystore blob and enforce the generation floor in one step — the guarded sibling of
    /// [`Self::from_bytes`] for the session's keystore-fetch path.
    ///
    /// # Errors
    /// As [`Self::from_bytes`], plus [`VaultError::KeystoreGenerationRollback`] below the floor.
    pub fn from_bytes_with_floor(bytes: &[u8], floor: u64) -> Result<Self, VaultError> {
        let ks = Self::from_bytes(bytes)?;
        ks.check_generation_floor(floor)?;
        Ok(ks)
    }

    /// Verify the plaintext public fields against the identity derived from the unwrapped `identity_master` —
    /// closes the KDF-downgrade / pubkey-swap tamper vector.
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

    fn pass() -> Passphrase {
        Passphrase::new(b"correct horse battery staple".to_vec())
    }

    #[test]
    fn create_then_unlock_roundtrips_the_identity() {
        let (ks, _code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        assert_eq!(
            ks.wraps.len(),
            3,
            "passphrase + recovery + account-root wraps"
        );
        let again = ks.unlock(&pass()).unwrap();
        assert_eq!(unlocked.member_id, again.member_id);
        assert_eq!(
            unlocked.root.identity.verifying_key().to_bytes(),
            again.root.identity.verifying_key().to_bytes()
        );
        assert_eq!(ks.member_id, derive_member_id(&ks.author_public));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (ks, _code, _u) = AccountKeystore::create(&pass()).unwrap();
        assert!(ks
            .unlock(&Passphrase::new(b"wrong passphrase".to_vec()))
            .is_err());
    }

    #[test]
    fn recovery_code_unlocks_the_same_identity() {
        let (ks, code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        let via_code = ks.unlock_with_recovery(&code).unwrap();
        assert_eq!(unlocked.member_id, via_code.member_id);
        assert_eq!(
            unlocked.root.identity.verifying_key().to_bytes(),
            via_code.root.identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn change_passphrase_keeps_member_id_and_recovery() {
        let (ks, code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        let new_passphrase = Passphrase::new(b"a brand new passphrase".to_vec());
        let ks2 = ks.change_passphrase(&unlocked, &new_passphrase).unwrap();
        assert_eq!(ks.member_id, ks2.member_id);
        assert_eq!(ks.author_public, ks2.author_public);
        let u2 = ks2.unlock(&new_passphrase).unwrap();
        assert_eq!(u2.member_id.as_str(), ks.member_id);
        assert!(ks2.unlock(&pass()).is_err());
        assert!(ks2.unlock_with_recovery(&code).is_ok());
    }

    #[test]
    fn rotate_account_root_keeps_identity_and_revokes_the_old_recovery_code() {
        let (ks, old_code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        let (ks2, new_code) = ks.rotate_account_root(&unlocked, &pass()).unwrap();
        // identity + member_id unchanged; generation bumped
        assert_eq!(ks.member_id, ks2.member_id);
        assert_eq!(ks.author_public, ks2.author_public);
        assert_eq!(ks2.generation, ks.generation + 1);
        // the storage layer was re-keyed: the account-root inner wrap ciphertext changed
        let inner_before = inner_wrap(&ks.wraps).unwrap();
        let inner_after = inner_wrap(&ks2.wraps).unwrap();
        assert_ne!(
            inner_before.ciphertext.as_ref(),
            inner_after.ciphertext.as_ref()
        );
        // same identity still opens; the NEW recovery code works, the OLD one no longer does
        let u2 = ks2.unlock(&pass()).unwrap();
        assert_eq!(u2.member_id.as_str(), ks.member_id);
        assert!(ks2.unlock_with_recovery(&new_code).is_ok());
        assert!(ks2.unlock_with_recovery(&old_code).is_err());
    }

    #[test]
    fn generation_floor_refuses_a_rolled_back_keystore() {
        let (ks, _old_code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        let (ks2, _new_code) = ks.rotate_account_root(&unlocked, &pass()).unwrap();
        let floor = ks2.generation; // the client has now seen generation 1
        assert_eq!(floor, 1);

        // a server serving the pre-rotation blob (generation 0) is refused — the revoked recovery code stays
        // revoked because the stale keystore never loads.
        let stale = ks.to_bytes().unwrap();
        assert!(matches!(
            AccountKeystore::from_bytes_with_floor(&stale, floor),
            Err(VaultError::KeystoreGenerationRollback { floor: 1, got: 0 })
        ));
        assert!(ks.check_generation_floor(floor).is_err());

        // the current blob at the floor loads (equal ⇒ idempotent re-fetch), and so would a higher generation.
        let current = ks2.to_bytes().unwrap();
        assert!(AccountKeystore::from_bytes_with_floor(&current, floor).is_ok());
        assert!(ks2.check_generation_floor(floor).is_ok());
        assert!(ks2.check_generation_floor(0).is_ok());
    }

    #[test]
    fn tampered_author_public_is_rejected() {
        let (mut ks, _code, _u) = AccountKeystore::create(&pass()).unwrap();
        ks.author_public[0] ^= 0xff;
        assert!(ks.unlock(&pass()).is_err());
    }

    #[test]
    fn persisted_blob_roundtrips_and_still_unlocks() {
        let (ks, code, unlocked) = AccountKeystore::create(&pass()).unwrap();
        let bytes = ks.to_bytes().unwrap();
        let loaded = AccountKeystore::from_bytes(&bytes).unwrap();
        assert_eq!(ks, loaded);
        let via_pass = loaded.unlock(&pass()).unwrap();
        let via_code = loaded.unlock_with_recovery(&code).unwrap();
        assert_eq!(via_pass.member_id, unlocked.member_id);
        assert_eq!(via_code.member_id, unlocked.member_id);
    }

    #[test]
    fn member_id_is_stable_uuid8_golden() {
        let pubkey = [7u8; 32];
        let id = derive_member_id(&pubkey);
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'8', "version nibble must be 8");
        assert!(
            matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "RFC-4122 variant"
        );
        assert_eq!(id, derive_member_id(&pubkey));
    }
}
