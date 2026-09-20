//! The keyring vault — the passphrase lifecycle that turns a passphrase into a [`openom_sealer::Sealer`].
//!
//! Four flows: **provision** (first time), **unlock** (returning / new device), **recover**
//! (forgot passphrase, via the recovery code), **`change_passphrase`**. All fit the frozen
//! `Keyring` proto; none add a field.
//!
//! ## Two invariants that carry the security (from the design review)
//! - **Trusted context.** `tree_id` and `member_id` bound into every wrap's AAD (via keyeo's
//!   `GroupContext` + the wrap recipient) come from the caller's own expectation (the tree the app is
//!   operating on), NEVER from the parsed, untrusted keyring. Otherwise the "the AEAD binds `tree_id`"
//!   argument is circular. The keyring's `tree_id` is only *checked* against the expected one, never the AAD.
//! - **Untrusted revision on recovery.** Recovery skips the signature (it can't re-derive
//!   the old passphrase-derived identity), and the wrap AAD does not cover `revision`. So the
//!   served revision is untrusted: refuse a value below the caller's watermark *before*
//!   unwrapping, and mint the new revision as `checked(max(watermark, served) + 1)`.

// The recovery/rotation flows use intentionally-close domain abbreviations that clippy reads as typos:
// `rrk` (recovery root key) / `rvk` (recovery verification key) / `rk` (recovery key), and `old_`/`new_`
// pairs across a rotation. Renaming them would lose precision, so `similar_names` is off for this module.
#![allow(clippy::similar_names)]

use did::DidKey;
use openom_crypto::{
    default_kdf_params, derive_root, generate_dek, generate_hpke_keypair, generate_salt,
    CryptoError, Dek, HpkeKeypair, HpkePrivate, Passphrase, RecoveryCode, RootKeys, RrkSecret,
};
use openom_keyring_api::derive_member_id;
use openom_keyring_chain::{
    keyring_hash, sign_keyring, verify_keyring_any, SigningKey, VerifyingKey,
};
use openom_protocol::ids::{KeyId, MemberId, ReplicaId, TreeId};
use openom_protocol::v1::MemberRole;
// The keyring wire moved to openom-keyring-chain in OPE-300. The DEK epochs + recovery escrow wraps are
// keyeo key material the chain stores as `codec` bytes (OPE-377).
use keyeo_crypto::{
    codec, Epoch as KeyeoEpoch, KdfParams as KeyeoKdfParams, KekKind, KeyId as KeyeoKeyId,
    X25519PublicKey,
};
use openom_keyring_chain::wire::{Keyring, Member, RecoveryKey};
use openom_protocol::{Message, KEYRING_LAYOUT_VERSION};
// The founder is the owner (the sole OWNER-role member) of a freshly-built single-owner keyring. The
// signer set is DERIVED from members now (OPE-309): a member at CO_OWNER or stronger IS a signer, so there
// is no separate authorized-signer roster to build or read. The role constants live in openom-roles (one
// definition); aliased here to the local names used below.
use openom_roles::{MEMBER_CO_OWNER as CO_OWNER_MEMBER, MEMBER_OWNER as OWNER};

use crate::account_keystore::{AccountKeystore, UnlockedAccount};
use crate::vault_core::{
    build_account_escrow, epoch_deks, escrow_kek_wrap, member_epoch_deks, member_wrap_keyeo,
    open_rrk_secret, rrk_wrap_keyeo, sealer_set_from_deks, validate_kdf, write_epoch_by_ordinal,
};
use crate::VaultError;
use openom_sealer::SealerSet;

/// The epoch key id length (matches `Header.key_id`); 16 CSPRNG bytes.
const KEY_ID_LEN: usize = 16;
/// Bound on untrusted keyring input — a real V1 keyring is well under 1 KiB.
const MAX_KEYRING_BYTES: usize = 64 * 1024;

/// `H(DEK)` — the content commitment that lets the recover watermark authenticate key MATERIAL rather than
/// the forgeable public `key_id` label (OPE-286). SHA-256, the codebase's standard digest. `H` of a 32-byte
/// random DEK is neither invertible nor brute-forceable, so watermarking it leaks nothing.
fn dek_hash(dek: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(dek).to_vec()
}

/// The write epoch's `(key_id, H(DEK))` commitment — the highest-ordinal epoch's id and its DEK hash — for
/// the recover watermark's epoch pin (OPE-286). The DEKs come from a VERIFIED open, so this witnesses the
/// real key material. Used by the membership flows so a chain add/remove carries the pin forward (an add
/// leaves the write epoch unchanged; a removal mints a fresh one that this then commits to).
fn write_epoch_pin(deks: &[(Vec<u8>, u64, Dek)]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    deks.iter()
        .max_by_key(|(_, e, _)| *e)
        .map(|(k, _, d)| (k.clone(), dek_hash(d.expose())))
        .ok_or(VaultError::MissingWrap)
}

/// Decode a keyring's DEK epochs from their canonical `codec` bytes — the ONE place the chain vault reads
/// key material, propagating a decode failure (never defaulting to empty). On an already-verified keyring
/// the structure gate has validated this decode; the error path guards the (rare) unverified caller.
fn keyring_epochs(keyring: &Keyring) -> Result<Vec<KeyeoEpoch<String>>, VaultError> {
    keyring
        .key_material()
        .map_err(|_| VaultError::BadKeyring("keyring key material malformed".into()))
}

/// Result of [`provision`]: the encoded keyring to store, the recovery code to show ONCE,
/// and the ready sealer set (built from the fresh DEK — one Argon2id, no second unlock).
pub struct Provisioned {
    pub keyring: Vec<u8>,
    pub recovery_code: RecoveryCode,
    pub sealer: SealerSet,
    /// The owner's stable author id — a `did:key` over their PUBLIC identity key. Public; stamped as
    /// `createdBy` on claims. Distinct from the per-context sync replica id.
    pub did_key: DidKey,
    /// The genesis keyring `revision` the caller must watermark (parallels [`Unlocked::revision`]).
    pub revision: u32,
    /// The write epoch's `key_id` + `H(DEK)` — the caller watermarks these so a later [`recover`] (which
    /// can't verify signatures) can PIN the write epoch to authenticated key MATERIAL, not the forgeable
    /// public `key_id` label (OPE-286). See [`Unlocked::write_key_id`].
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Result of [`unlock`]: the sealer set (all epochs the caller can reach) plus the keyring
/// `revision` the caller must watermark.
pub struct Unlocked {
    pub sealer: SealerSet,
    pub revision: u32,
    /// The member's stable author id — a `did:key` over their PUBLIC identity key (see
    /// [`Provisioned::did_key`]). Stable across a member's tabs/reloads.
    pub did_key: DidKey,
    /// The write epoch's `key_id` and `H(DEK)`, watermarked so a later [`recover`] pins the write epoch to
    /// key MATERIAL. Sourced from a VERIFIED unlock — the trusted witness of the real epoch set (OPE-286).
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Result of [`recover`]: the (UNCHANGED) keyring anchor + the SAME durable identity restored, plus the
/// account keystore re-wrapped under the new passphrase.
///
/// OPE-543 durable identity: recovery is ACCOUNT-keystore-mediated — it restores the SAME account identity
/// the tree already trusts (no on-tree op, no new revision, no fresh owner key). `did_key` is therefore
/// UNCHANGED and the `keyring` anchor is returned verbatim; the only new durable output is `keystore` (the
/// account blob re-wrapped under `new_passphrase`) and the per-tree `recovery_code` is EMPTY.
pub struct Recovered {
    pub keyring: Vec<u8>,
    pub recovery_code: RecoveryCode,
    /// The account keystore blob re-wrapped under the new passphrase (OPE-542/543) — the sole new durable
    /// output of a recovery.
    pub keystore: Vec<u8>,
    pub sealer: SealerSet,
    pub revision: u32,
    /// The owner's stable author id — UNCHANGED across recovery (the durable account identity is restored,
    /// not re-minted).
    pub did_key: DidKey,
    /// The (unchanged) write epoch's `key_id` + `H(DEK)` to re-watermark.
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Result of [`change_passphrase`]: the (UNCHANGED) keyring anchor + the account keystore re-wrapped under
/// the new passphrase.
///
/// OPE-543 durable identity: a passphrase change is ACCOUNT-keystore-mediated — the durable identity the
/// tree trusts is unchanged, so there is NO on-tree op and NO new revision. The running sealer keeps working
/// (the DEKs are untouched). `keystore` is the account blob re-wrapped under the new passphrase; the per-tree
/// `recovery_code` is EMPTY (a passphrase change does not rotate the account's recovery code).
pub struct Rekeyed {
    pub keyring: Vec<u8>,
    pub recovery_code: RecoveryCode,
    /// The account keystore blob re-wrapped under the new passphrase (OPE-542/543).
    pub keystore: Vec<u8>,
    pub revision: u32,
    /// The (unchanged) write epoch's `key_id` + `H(DEK)` to re-watermark.
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Create a brand-new encrypted tree, owned by the durable ACCOUNT identity (OPE-543).
///
/// A fresh DEK under epoch 0, a fresh per-tree **recovery root key** (RRK) escrowing that epoch (and every
/// future one) — the RRK secret wrapped under the owner's STABLE durable-account KEK (`account.root.kek`),
/// not a per-tree passphrase credential — all in a keyring signed by the ACCOUNT signing identity (revision
/// 1). The owner reaches epochs via the RRK, so the keyring holds no per-epoch owner wrap.
///
/// The owner's identity (author + HPKE keys) is the durable account, so it is stable across passphrase
/// changes / devices, and there is NO per-tree recovery code (recovery is account-keystore-mediated); the
/// returned `recovery_code` is EMPTY. The owner's on-tree `member_id` is `derive_member_id(account key)` —
/// self-certifying, symmetric with the dag — so the caller's `member_id` argument is ignored for the owner
/// (the account identity is the sole source of the owner id).
///
/// # Errors
/// Returns [`VaultError`] if key derivation or the initial sealing fails.
pub fn provision(
    account: &UnlockedAccount,
    tree_id: &TreeId,
    _member_id: &MemberId,
    replica_id: &ReplicaId,
) -> Result<Provisioned, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the owner id is SELF-CERTIFYING — derived from the account key (symmetric with the dag), NOT
    // the caller's label. The account keypair exists only here, so this is derive-and-use, not an assert
    // (the caller can't know f(account key) before provision mints the account).
    let member_id_owned = derive_member_id(&account.root.identity.verifying_key().to_bytes());
    let member_id = member_id_owned.as_str();
    let replica_id = replica_id.as_bytes();
    let dek = generate_dek()?;
    let key_id = generate_salt()?.to_vec(); // 16 CSPRNG bytes as the epoch key id
                                            // Bind by field name (not positional): the secret and public can't be swapped into the wrong role.
    let HpkeKeypair {
        secret,
        public: rrk_public,
    } = generate_hpke_keypair()?;
    let rrk_secret = RrkSecret::from(secret);

    let epoch0 = KeyeoEpoch {
        key_id: KeyeoKeyId::new(key_id.clone()),
        ordinal: 0,
        dek_commitment: keyeo_crypto::dek_commitment(&dek),
        wraps: vec![rrk_wrap_keyeo(
            &rrk_public,
            &dek,
            tree_id,
            member_id,
            &key_id,
        )?],
    };
    // The RRK secret is escrowed under the DURABLE-ACCOUNT KEK (stable across passphrase changes, restored
    // verbatim by an account recovery) — the owner's only way to reach the RRK. No per-tree recovery code.
    let recovery_key = RecoveryKey::from(&build_account_escrow(
        &rrk_secret,
        &rrk_public,
        tree_id,
        member_id,
        &account.root.kek,
    )?);
    // The owner IS the durable account: its author + HPKE keys come from `account.root`, so the identity is
    // stable across passphrase changes / devices (OPE-542/543).
    let author_public = account.root.identity.verifying_key().to_bytes();
    let did_key = did::DidKey::from_public_key(&author_public);
    let identity_pub = author_public.to_vec();

    let mut keyring = Keyring {
        tree_id: tree_id.to_vec(),
        revision: 1,
        layout_version: KEYRING_LAYOUT_VERSION,
        prev_keyring_hash: Vec::new(), // genesis
        // The OWNER-role member is the founder signer (the signer set derives from members, OPE-309).
        members: vec![Member {
            member_id: member_id.to_string(),
            role: OWNER,
            author_public_key: identity_pub,
            hpke_public_key: account.root.hpke_public.to_vec(),
        }],
        signatures: Vec::new(),
        recovery_keys: vec![recovery_key],
        epochs: codec::encode_epochs(&[epoch0]),
        // Governance defaults to founder-or-unanimity (kind 0) at genesis; a later revision may set it.
        ..Default::default()
    };
    sign_keyring(&mut keyring, &account.root.identity);

    let dek_bytes = dek.into_inner();
    let write_dek_hash = dek_hash(&dek_bytes[..]);
    let sealer = SealerSet::new(
        TreeId::new(tree_id),
        ReplicaId::new(replica_id),
        vec![(key_id.clone(), dek_bytes)],
        KeyId::new(key_id.clone()),
    );
    Ok(Provisioned {
        revision: keyring.revision,
        keyring: keyring.encode_to_vec(),
        // Recovery is account-keystore-mediated (OPE-543): no per-tree recovery code.
        recovery_code: RecoveryCode::new(String::new()),
        sealer,
        did_key,
        write_key_id: key_id,
        write_dek_hash,
    })
}

/// Open an existing keyring with the durable ACCOUNT identity (OPE-543) and build a sealer set spanning
/// every epoch the owner can reach (via the recovery root key).
///
/// The account identity must BE the resolved OWNER member's author key (anti-substitution), and the keyring
/// must be signed by a current authorized signer (§4a V1). The RRK is reached via the STABLE account KEK.
///
/// # Errors
/// Returns [`VaultError`] if the account isn't this tree's owner, the served keyring is malformed, or no
/// epoch is reachable.
pub fn unlock(
    keyring_bytes: &[u8],
    account: &UnlockedAccount,
    tree_id: &TreeId,
    replica_id: &ReplicaId,
) -> Result<Unlocked, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the owner id is the account's SELF-CERTIFYING, tamper-checked `member_id` — sourced from the
    // VERIFIED account, never a caller label, so the DEK / escrow / author paths below cannot diverge from it.
    // (There is no longer any caller-supplied owner id to get wrong — the label bug is unrepresentable here.)
    let member_id_owned = account.member_id.clone();
    let member_id = member_id_owned.as_str();
    let replica_id = replica_id.as_bytes();
    let Opened {
        key_id: write_key_id,
        revision,
        rrk_secret,
        keyring,
        ..
    } = open_with_account(keyring_bytes, account, tree_id)?;
    // A tree session owns its signing key, while the profile account remains resident and reusable for other
    // trees. Re-derive an independent key bundle from the unlocked account's stored-random identity master.
    let root = account.tree_root();
    let did_key = did::DidKey::from_public_key(&root.identity.verifying_key().to_bytes());
    let epochs: Vec<(Vec<u8>, openom_crypto::Key32)> =
        epoch_deks(&keyring_epochs(&keyring)?, tree_id, member_id, &rrk_secret)
            .into_iter()
            .map(|(k, _e, d)| (k, d.into_inner()))
            .collect();
    // Sign entries once the tree HAS BEEN SHARED (a non-founder member was ever admitted). A never-shared
    // single-owner V1 tree stays unattributed (the launch gate skips verification for it); the moment it is
    // shared the sealer starts signing, and it KEEPS signing even after an un-share back to solo — gating on
    // `has_been_shared` (monotonic), not `epoch_is_attributed` (which a removal's re-key would reset,
    // reopening the unattributed-write hole for ex-members holding old-epoch DEKs).
    // Commit to the write epoch's key MATERIAL (H(DEK)) for the recover watermark — this unlock is VERIFIED,
    // so it's the trusted witness of the real write epoch's DEK (OPE-286).
    let write_dek_hash = epochs
        .iter()
        .find(|(k, _)| *k == write_key_id)
        .map(|(_, d)| dek_hash(&d[..]))
        .ok_or_else(|| VaultError::BadKeyring("write epoch not in the reachable set".into()))?;
    let attributed = crate::has_been_shared(&keyring);
    let mut sealer = SealerSet::new(
        TreeId::new(tree_id),
        ReplicaId::new(replica_id),
        epochs,
        KeyId::new(write_key_id.clone()),
    );
    if attributed {
        // The chain encodes the member's watermarked keyring head (`revision`) as the entry's opaque
        // governing_ref; every entry this sealer signs stamps it (OPE-277 GoverningRef).
        let governing_ref = openom_keyring_chain::encode_governing_ref(revision);
        sealer = sealer.with_author(root.identity, member_id.to_string(), governing_ref);
    }
    Ok(Unlocked {
        sealer,
        revision,
        did_key,
        write_key_id,
        write_dek_hash,
    })
}

/// Recover owner access with the recovery code under `new_passphrase` — ACCOUNT-keystore-mediated (OPE-543
/// durable identity).
///
/// The recovery code restores the SAME durable account identity the tree already trusts
/// ([`AccountKeystore::unlock_with_recovery`]); we re-wrap the account blob under `new_passphrase` and open
/// the tree by the NORMAL owner path with that restored identity. There is NO on-tree op: no re-founding, so
/// the keyring anchor is UNCHANGED, the resolved owner is UNCHANGED, and `did_key` is preserved — recovery
/// introduces no owner-succession surface and no rollback. Members who pinned the owner keep verifying (the
/// owner key never changed).
///
/// The only new durable output is the re-wrapped account `keystore` blob; the per-tree `recovery_code` is
/// EMPTY (the account's recovery code is not consumed/rotated by a recovery — the SAME code keeps working).
/// `watermark` carries the caller's anti-rollback floor (the served keyring is untrusted).
///
/// # Errors
/// Returns [`VaultError`] if the recovery code is wrong, the served keyring is malformed / below the
/// watermark, or the restored account is not this tree's owner.
// The flat argument list (anchor + keystore + code + new-pass + the three ids + watermark) is the
// lifecycle/host calling convention shared with `KeyringLifecycle::recover`, not a struct to bundle — the
// same convention the app-core lifecycle veneer carries the `#[allow]` for.
#[allow(clippy::too_many_arguments)]
pub fn recover(
    keyring_bytes: &[u8],
    keystore: &[u8],
    recovery_code: &RecoveryCode,
    new_passphrase: &Passphrase,
    tree_id: &TreeId,
    replica_id: &ReplicaId,
    watermark: &RecoverWatermark<'_>,
) -> Result<Recovered, VaultError> {
    let min_revision = watermark.min_revision;
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id.as_bytes() {
        return Err(VaultError::TreeMismatch);
    }
    // Refuse a rolled-back served keyring before doing any work (the anchor is not mutated; this guards the
    // read). Unlike the pre-543 op-based recover, the served head is signature-verified by the restored
    // durable identity inside `unlock` below — a forged keyring fails that check.
    if keyring.revision < min_revision {
        return Err(VaultError::RevisionRollback {
            have: min_revision,
            got: keyring.revision,
        });
    }

    // Restore the durable account identity from the keystore via the recovery code (SAME member_id / keys),
    // then re-wrap it under the new passphrase. Neither touches the tree.
    let ks = AccountKeystore::from_bytes(keystore)?;
    let unlocked = ks.unlock_with_recovery(recovery_code)?;
    let new_ks = ks.change_passphrase(&unlocked, new_passphrase.expose())?;

    // Open the tree with the restored identity by the ordinary owner path — the anchor is unchanged, so the
    // resolved owner is exactly this identity (anti-substitution inside `unlock` enforces it).
    let u = unlock(keyring_bytes, &unlocked, tree_id, replica_id)?;
    Ok(Recovered {
        keyring: keyring_bytes.to_vec(),
        recovery_code: RecoveryCode::new(String::new()),
        keystore: new_ks.to_bytes()?,
        sealer: u.sealer,
        revision: u.revision,
        did_key: u.did_key,
        write_key_id: u.write_key_id,
        write_dek_hash: u.write_dek_hash,
    })
}

/// Change the passphrase — ACCOUNT-keystore-mediated (OPE-543 durable identity).
///
/// The durable identity the tree trusts is unchanged, so this is purely an
/// [`AccountKeystore::change_passphrase`] re-wrap of the account blob under the new passphrase. There is NO
/// on-tree op: the keyring `anchor` and its revision are UNCHANGED and the running sealer keeps working (the
/// DEKs are untouched). Returns the new keystore blob; the per-tree `recovery_code` is EMPTY (a passphrase
/// change does not rotate the account's recovery code). `min_revision` is the anti-rollback floor.
///
/// # Errors
/// Returns [`VaultError`] if the current passphrase is wrong, the keystore is malformed, or the served
/// keyring is below the floor / for a different tree.
pub fn change_passphrase(
    keyring_bytes: &[u8],
    keystore: &[u8],
    old_passphrase: &Passphrase,
    new_passphrase: &Passphrase,
    tree_id: &TreeId,
    member_id: &MemberId,
    min_revision: u32,
) -> Result<Rekeyed, VaultError> {
    let _ = member_id; // the owner id is not needed — the change lives entirely in the account keystore.
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id.as_bytes() {
        return Err(VaultError::TreeMismatch);
    }
    // Anti-rollback symmetry with the dag: refuse a rolled-back served anchor before the re-wrap.
    if keyring.revision < min_revision {
        return Err(VaultError::RevisionRollback {
            have: min_revision,
            got: keyring.revision,
        });
    }

    let ks = AccountKeystore::from_bytes(keystore)?;
    let unlocked = ks.unlock(old_passphrase.expose())?; // a wrong current passphrase fails closed here
    let new_ks = ks.change_passphrase(&unlocked, new_passphrase.expose())?;

    Ok(Rekeyed {
        keyring: keyring_bytes.to_vec(),
        recovery_code: RecoveryCode::new(String::new()),
        keystore: new_ks.to_bytes()?,
        // The tree anchor is unchanged, so its revision (and the caller's pinned watermark) carries forward
        // verbatim — the lifecycle returns the floor unchanged rather than rebuilding a pin.
        revision: keyring.revision,
        write_key_id: Vec::new(),
        write_dek_hash: Vec::new(),
    })
}

/// What a joining member provisions from their own passphrase.
///
/// the KDF params they store
/// in their account record (to re-derive on any device) and the two **public** keys they
/// hand a tree owner out-of-band (§4a) — the Ed25519 author key and the X25519 HPKE key.
///
pub struct MemberProvision {
    pub kdf_params: KeyeoKdfParams,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// Provision a member identity from a passphrase: derive the account's signing + HPKE
/// keypairs and return the public keys (to share OOB) plus the KDF params (to persist).
///
/// The secrets are never returned — they re-derive from the passphrase on unlock.
///
/// # Errors
/// Returns [`VaultError`] if the member secret derivation fails.
pub fn provision_member(passphrase: &Passphrase) -> Result<MemberProvision, VaultError> {
    let passphrase = passphrase.expose();
    let kdf = default_kdf_params(generate_salt()?.to_vec());
    let root = derive_root(passphrase, &kdf)?;
    Ok(MemberProvision {
        // The member's account KDF record — keyeo's `KdfParams`, persisted client-side (the wasm / Tauri
        // boundary serializes it via `keyeo_crypto::codec`) and replayed on a later unlock.
        kdf_params: kdf,
        author_public_key: root.identity.verifying_key().to_bytes().to_vec(),
        hpke_public_key: root.hpke_public.to_vec(),
    })
}

/// Result of [`add_member`]: the new keyring to publish and its revision.
pub struct MemberAdded {
    pub keyring: Vec<u8>,
    pub revision: u32,
    /// The (unchanged) write epoch's `key_id` + `H(DEK)` to carry forward in the watermark — an add mints
    /// no new epoch, so the recover pin is preserved rather than erased (OPE-286).
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// The member being admitted to a tree ("the joiner"): their assigned id + role and the OOB-verified
/// public keys they provided (§4a).
///
/// The openom analog of keyeo's `MemberInit`, generic over the engine's
/// role type so the chain (`MemberRole`) and dag (`KeyringRole`) add paths — and the shared `do_add_member`
/// core — all speak one type. The two keys are DISTINCT types (`VerifyingKey` vs `X25519PublicKey`), so a
/// transposition is a *compile error*, not a convention; construct via [`Joiner::from_bytes`], which is the
/// single point that validates the raw boundary bytes into those types.
pub struct Joiner<R> {
    pub member_id: String,
    pub role: R,
    pub author_public_key: VerifyingKey,
    pub hpke_public_key: X25519PublicKey,
}

impl<R> Joiner<R> {
    /// Build a joiner from an id + role + the raw OOB-received key bytes, validating each once: the author
    /// key must be a well-formed Ed25519 point (32 bytes), the HPKE key must be 32 bytes. This is the ONLY
    /// place raw key bytes are narrowed/typed — thereafter the two keys cannot be confused.
    ///
    /// # Errors
    /// Returns [`VaultError::BadKeyring`] if either key is the wrong length or the author key is not a valid
    /// Ed25519 verifying key.
    pub fn from_bytes(
        member_id: &MemberId,
        role: R,
        author_public_key: &[u8],
        hpke_public_key: &[u8],
    ) -> Result<Self, VaultError> {
        let author: [u8; 32] = author_public_key
            .try_into()
            .map_err(|_| VaultError::BadKeyring("author public key must be 32 bytes".into()))?;
        let hpke: [u8; 32] = hpke_public_key
            .try_into()
            .map_err(|_| VaultError::BadKeyring("hpke public key must be 32 bytes".into()))?;
        // Self-cert admission (OPE-543): a member id MUST be `derive_member_id(author_public_key)`, so the id
        // binds the key it is admitted under — a joiner can't be registered under an id that does not certify
        // their own author key. The chain engine carries ids as opaque labels (it imposes no engine-level
        // self-cert rule), but the CLIENT constructs only self-certifying joiners on either engine, matching
        // the dag's admission gate and keeping the two engines' member models aligned.
        if member_id.as_str() != derive_member_id(&author) {
            return Err(VaultError::BadKeyring(
                "member id does not bind its author key (self-cert admission)".into(),
            ));
        }
        Ok(Self {
            member_id: member_id.as_str().to_string(),
            role,
            author_public_key: VerifyingKey::from_bytes(&author).map_err(|_| {
                VaultError::BadKeyring("author public key is not a valid key".into())
            })?,
            hpke_public_key: X25519PublicKey::from_bytes(hpke),
        })
    }
}

/// A non-owner caller's credentials for a shared tree.
///
/// their `passphrase` + account `kdf` (to re-derive
/// their identity), their `member_id`, and the `trusted_signers` they pinned out-of-band (§4a) as the
/// keyring's trust anchor.
///
/// Used by the member-unlock and co-owner administration paths.
pub struct MemberAuth<'a> {
    pub passphrase: &'a Passphrase,
    pub kdf: &'a KeyeoKdfParams,
    pub member_id: &'a MemberId,
    pub trusted_signers: &'a [VerifyingKey],
}

/// The caller's anti-rollback watermark floor for a recovery (OPE-286): the minimum acceptable `revision`
/// plus the write epoch's `key_id` + `H(DEK)` from a prior VERIFIED unlock.
///
/// Recovery skips signature
/// verification, so this pin is the sole authentication of the served epoch set (both key fields empty ⇒ a
/// stateless device with no watermark).
pub struct RecoverWatermark<'a> {
    pub min_revision: u32,
    pub write_key_id: &'a [u8],
    pub dek_hash: &'a [u8],
}

/// Add a member to a shared tree.
///
/// An authorized signer (V1: the owner) re-opens the
/// keyring with their passphrase to reach the DEK and their signing identity, HPKE-wraps
/// the DEK to the member's public key, records them in the signed member list, and
/// re-signs at the next revision (chained onto the prior one). The member's public keys
/// MUST have been verified out-of-band (§4a) before calling — this function trusts them.
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized, the keyring is malformed, or sealing the joiner's wraps fails.
pub fn add_member(
    keyring_bytes: &[u8],
    owner: &UnlockedAccount,
    tree_id: &TreeId,
    min_revision: u32,
    joiner: &Joiner<MemberRole>,
) -> Result<MemberAdded, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the owner id is the account's self-certifying, verified member_id, never a caller label.
    let owner_member_id = owner.member_id.as_str();
    let new_member_id = joiner.member_id.as_str();
    guard_ordinary_role(joiner.role)?;
    let Opened {
        rrk_secret,
        revision,
        prev_hash,
        keyring,
        ..
    } = open_with_account(keyring_bytes, owner, tree_id)?;

    if new_member_id == owner_member_id
        || keyring.members.iter().any(|m| m.member_id == new_member_id)
    {
        return Err(VaultError::MemberExists);
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    // The owner reaches every epoch's DEK via the RRK; wrap them all for the new member so
    // they see the full history.
    let deks = epoch_deks(
        &keyring_epochs(&keyring)?,
        tree_id,
        owner_member_id,
        &rrk_secret,
    );
    do_add_member(
        keyring,
        tree_id,
        &deks,
        &owner.root.identity,
        prev_hash,
        new_revision,
        joiner,
    )
}

/// Add a member to a shared tree **as a co-owner** (any-of administration).
///
/// Reaches the epoch
/// DEKs through the co-owner's own member wraps (not the RRK), verifies the keyring against a
/// pinned signer set, checks the caller is an authorized co-owner, and signs with the
/// co-owner's identity. The new member's public keys must have been OOB-verified.
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized, the keyring is malformed, or sealing fails.
pub fn add_member_as_co_owner(
    keyring_bytes: &[u8],
    co_owner: &MemberAuth<'_>,
    tree_id: &TreeId,
    min_revision: u32,
    joiner: &Joiner<MemberRole>,
) -> Result<MemberAdded, VaultError> {
    let tree_id = tree_id.as_bytes();
    let co_owner_member_id = co_owner.member_id.as_str();
    let new_member_id = joiner.member_id.as_str();
    guard_ordinary_role(joiner.role)?;
    let acc = open_as_co_owner(
        keyring_bytes,
        co_owner.passphrase.expose(),
        co_owner.kdf,
        tree_id,
        co_owner_member_id,
        co_owner.trusted_signers,
    )?;
    if new_member_id == co_owner_member_id
        || acc
            .keyring
            .members
            .iter()
            .any(|m| m.member_id == new_member_id)
    {
        return Err(VaultError::MemberExists);
    }
    let new_revision = min_revision
        .max(acc.revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;
    let deks = member_epoch_deks(
        &keyring_epochs(&acc.keyring)?,
        tree_id,
        co_owner_member_id,
        &acc.hpke_secret,
    );
    do_add_member(
        acc.keyring,
        tree_id,
        &deks,
        &acc.identity,
        acc.prev_hash,
        new_revision,
        joiner,
    )
}

/// Unlock a shared tree **as a member** (not the owner).
///
/// Verify the keyring against the
/// caller's **pinned** signer set (learned out-of-band, §4a — never the member's own key
/// and never the document's signer hints), then HPKE-unwrap the DEK with the member's
/// passphrase-derived secret.
///
/// `member_kdf` is the member's own account KDF params.
///
/// # Errors
/// Returns [`VaultError`] if the member reaches no epoch or the keyring is malformed.
pub fn unlock_as_member(
    keyring_bytes: &[u8],
    member: &MemberAuth<'_>,
    tree_id: &TreeId,
    replica_id: &ReplicaId,
    min_revision: u32,
) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
    validate_kdf(member.kdf)?;
    let root = derive_root(member.passphrase.expose(), member.kdf)?;
    unlock_as_member_with_root(
        keyring_bytes,
        root,
        member.member_id.as_str(),
        member.trusted_signers,
        tree_id,
        replica_id,
        min_revision,
    )
}

/// Unlock a shared tree as a non-owner member using the profile's durable account identity.
///
/// The account remains resident and reusable; this call derives an independently-owned signing/HPKE bundle
/// for the tree session and retains only the session's HPKE capability for later epoch adoption.
///
/// # Errors
/// Returns [`VaultError`] if the member is absent/removed, the keyring fails its pinned trust check, or no
/// epoch is reachable by the account's HPKE key.
pub fn unlock_as_account_member(
    keyring_bytes: &[u8],
    account: &UnlockedAccount,
    trusted_signers: &[VerifyingKey],
    tree_id: &TreeId,
    replica_id: &ReplicaId,
    min_revision: u32,
) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
    unlock_as_member_with_root(
        keyring_bytes,
        account.tree_root(),
        &account.member_id,
        trusted_signers,
        tree_id,
        replica_id,
        min_revision,
    )
}

fn unlock_as_member_with_root(
    keyring_bytes: &[u8],
    root: RootKeys,
    member_id: &str,
    trusted_signers: &[VerifyingKey],
    tree_id: &TreeId,
    replica_id: &ReplicaId,
    min_revision: u32,
) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
    let tree_id = tree_id.as_bytes();
    let replica_id = replica_id.as_bytes();
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(VaultError::TreeMismatch);
    }
    if keyring.revision < min_revision {
        return Err(VaultError::RevisionRollback {
            have: min_revision,
            got: keyring.revision,
        });
    }
    // The trust anchor: a signature from a key the member pinned OOB. This is the member
    // path's whole security — the member cannot derive the owner's key, so it must be
    // supplied, never taken from the (untrusted) document.
    verify_keyring_any(&keyring, trusted_signers).map_err(|_| CryptoError::Signature)?;
    // A set over every epoch the member's HPKE wraps reach (full history); no wrap anywhere
    // means a removed member.
    let deks = member_epoch_deks(
        &keyring_epochs(&keyring)?,
        tree_id,
        member_id,
        &root.hpke_secret,
    );
    let write_key_id = write_epoch_by_ordinal(&deks)?;
    let write_dek_hash = deks
        .iter()
        .find(|(k, _, _)| k.as_slice() == write_key_id.as_slice())
        .map(|(_, _, d)| dek_hash(d.expose()))
        .ok_or_else(|| VaultError::BadKeyring("write epoch not in the reachable set".into()))?;
    let did_key = did::DidKey::from_public_key(&root.identity.verifying_key().to_bytes());
    let mut sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id.clone());
    // A member is on a shared tree by definition (their admission set `first_shared_revision`), so they sign
    // every entry — stamping their watermarked head as the governing_ref, exactly like the owner path. Gated
    // on `has_been_shared` for symmetry (always true here), so the member and owner writers stay in lockstep.
    if crate::has_been_shared(&keyring) {
        let governing_ref = openom_keyring_chain::encode_governing_ref(keyring.revision);
        sealer = sealer.with_author(root.identity, member_id.to_string(), governing_ref);
    }
    // A member unlock ALWAYS carries the HPKE secret (a member exists only on a shared tree): the running core
    // retains it to adopt a later (post-removal) epoch on sync without the passphrase (OPE-393). It is a
    // first-class second value, not an `Option` on the shared `Unlocked` — the owner path structurally has none.
    Ok((
        Unlocked {
            sealer,
            revision: keyring.revision,
            did_key,
            write_key_id,
            write_dek_hash,
        },
        root.hpke_secret,
    ))
}

/// Re-derive a member's reachable epoch DEKs from a freshly-synced chain keyring, using the HPKE secret the
/// core retained at unlock — the crypto behind a member's epoch ADOPT on a rotation (OPE-393). No passphrase,
/// no signature re-check (the sync path already verified the keyring): just unwrap the member's per-epoch
/// wraps, like [`unlock_as_member`] but over an already-trusted keyring. Returns the reachable epochs + the
/// new write epoch + the refreshed `governing_ref`.
///
/// # Errors
/// Returns [`VaultError`] if the keyring is malformed, is for a different tree, or the member reaches no epoch.
pub fn adopt_member_epochs(
    keyring_bytes: &[u8],
    hpke_secret: &openom_crypto::HpkePrivate,
    tree_id: &[u8],
    member_id: &str,
) -> Result<crate::sharing::AdoptedEpochs, VaultError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(VaultError::TreeMismatch);
    }
    let deks = member_epoch_deks(&keyring_epochs(&keyring)?, tree_id, member_id, hpke_secret);
    let write_key_id = write_epoch_by_ordinal(&deks)?;
    let governing_ref = if crate::has_been_shared(&keyring) {
        openom_keyring_chain::encode_governing_ref(keyring.revision)
    } else {
        Vec::new()
    };
    let epochs = deks.into_iter().map(|(k, _e, d)| (k, d.into_inner())).collect();
    Ok(crate::sharing::AdoptedEpochs {
        epochs,
        write_key_id,
        governing_ref,
    })
}

/// Result of [`remove_member`]: the re-keyed keyring to publish, the new revision, and a
/// sealer scoped to the **new** epoch so the caller re-seals the tree snapshot under the new
/// key.
///
/// No recovery code — the RRK escrows the new epoch, so the code never rotates on a
/// removal.
pub struct MemberRemoved {
    pub keyring: Vec<u8>,
    pub revision: u32,
    pub sealer: SealerSet,
    /// The NEW forward-secret write epoch's `key_id` + `H(DEK)` for the watermark's recover pin (OPE-286).
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Remove a member with **forward-secure revocation**: mint a fresh DEK under a new epoch,
/// wrap it only for those who remain.
///
/// the founder via the recovery root key (HPKE to the
/// RRK **public** key, which needs no secret and so also works for a co-owner-initiated
/// removal) and each other member via HPKE to their pinned key — drop the removed member
/// from the member list and signer set, and re-sign at the next chained revision.
///
/// Old epochs
/// stay so remaining members still read pre-removal content; the removed member — who never
/// receives a new-epoch wrap — cannot read anything sealed after removal.
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized, the keyring is malformed, or the forward-secret reseal fails.
pub fn remove_member(
    keyring_bytes: &[u8],
    owner: &UnlockedAccount,
    tree_id: &TreeId,
    min_revision: u32,
    remove_member_id: &MemberId,
    replica_id: &ReplicaId,
) -> Result<MemberRemoved, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the owner id is the account's self-certifying, verified member_id (this also makes the
    // CannotRemoveOwner guard below compare the removal target against the REAL owner, not a caller label).
    let owner_member_id = owner.member_id.as_str();
    let remove_member_id = remove_member_id.as_str();
    let replica_id = replica_id.as_bytes();
    let Opened {
        revision,
        prev_hash,
        rrk_secret,
        keyring,
        ..
    } = open_with_account(keyring_bytes, owner, tree_id)?;

    if remove_member_id == owner_member_id {
        return Err(VaultError::CannotRemoveOwner);
    }
    if !keyring
        .members
        .iter()
        .any(|m| m.member_id == remove_member_id)
    {
        return Err(VaultError::MemberNotFound);
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    let (keyring, _new_key_id) = do_remove_member(
        keyring,
        tree_id,
        remove_member_id,
        &owner.root.identity,
        prev_hash,
        new_revision,
    )?;

    // The owner re-seals with a set spanning every epoch (reached via the RRK); the new epoch
    // is the highest, so the set writes under it.
    let deks = epoch_deks(
        &keyring_epochs(&keyring)?,
        tree_id,
        owner_member_id,
        &rrk_secret,
    );
    // Pin the freshly-minted write epoch (key_id + H(DEK)) into the result so the watermark commits to it
    // for the next recover (OPE-286 phase 2), before `deks` is moved into the sealer.
    let (write_key_id, write_dek_hash) = write_epoch_pin(&deks)?;
    let sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id.clone());
    Ok(MemberRemoved {
        keyring: keyring.encode_to_vec(),
        revision: new_revision,
        sealer,
        write_key_id,
        write_dek_hash,
    })
}

/// Remove an ordinary member **as a co-owner** (any-of administration): reaches the epoch
/// DEKs through the co-owner's own wraps, mints the new epoch, and signs with the co-owner's
/// identity.
///
/// A co-owner may only remove an *ordinary* member — removing a signer (co-owner or
/// founder) is a signer-set change, which is founder-only.
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized, the keyring is malformed, or the reseal fails.
pub fn remove_member_as_co_owner(
    keyring_bytes: &[u8],
    co_owner: &MemberAuth<'_>,
    tree_id: &TreeId,
    min_revision: u32,
    remove_member_id: &MemberId,
    replica_id: &ReplicaId,
) -> Result<MemberRemoved, VaultError> {
    let tree_id = tree_id.as_bytes();
    let co_owner_member_id = co_owner.member_id.as_str();
    let remove_member_id = remove_member_id.as_str();
    let replica_id = replica_id.as_bytes();
    let acc = open_as_co_owner(
        keyring_bytes,
        co_owner.passphrase.expose(),
        co_owner.kdf,
        tree_id,
        co_owner_member_id,
        co_owner.trusted_signers,
    )?;
    if !acc
        .keyring
        .members
        .iter()
        .any(|m| m.member_id == remove_member_id)
    {
        return Err(VaultError::MemberNotFound);
    }
    // A co-owner can't remove a signer (co-owner/founder) — that's a founder-gated set change. A signer
    // is a member at CO_OWNER or stronger (the signer set is derived from members, OPE-309).
    if acc
        .keyring
        .members
        .iter()
        .any(|m| m.member_id == remove_member_id && (m.role == OWNER || m.role == CO_OWNER_MEMBER))
    {
        return Err(VaultError::NotAuthorized);
    }
    let new_revision = min_revision
        .max(acc.revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    let (keyring, _new_key_id) = do_remove_member(
        acc.keyring,
        tree_id,
        remove_member_id,
        &acc.identity,
        acc.prev_hash,
        new_revision,
    )?;

    // The co-owner re-seals with a set spanning the epochs their own wraps reach (including
    // the new one they were re-wrapped into); the new epoch is the highest, so it's the write.
    let deks = member_epoch_deks(
        &keyring_epochs(&keyring)?,
        tree_id,
        co_owner_member_id,
        &acc.hpke_secret,
    );
    let (write_key_id, write_dek_hash) = write_epoch_pin(&deks)?;
    let sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id.clone());
    Ok(MemberRemoved {
        keyring: keyring.encode_to_vec(),
        revision: new_revision,
        sealer,
        write_key_id,
        write_dek_hash,
    })
}

/// Result of a co-owner promotion / demotion: the new keyring + revision. No new sealer or
/// recovery code — this changes signing authority, not keys.
pub struct CoOwnerChanged {
    pub keyring: Vec<u8>,
    pub revision: u32,
    /// The (UNCHANGED) write epoch's `key_id` + `H(DEK)` to re-watermark at the new revision (OPE-286): a
    /// role change touches no keys, so this pins the current write epoch forward so anti-rollback + a later
    /// recover authenticate against the correct key material. Mirrors [`MemberAdded`]'s pin.
    pub write_key_id: Vec<u8>,
    pub write_dek_hash: Vec<u8>,
}

/// Promote an existing member to **co-owner** — add them to the authorized-signer set so
/// they can administer the tree (rotate keys, add/remove ordinary members).
///
/// Changing the
/// signer set is founder-authorized ("founder-or-unanimity"): the new keyring is signed by
/// the founder's identity. The member's own author key — pinned and OOB-verified when they
/// were added — becomes their signer key, so no new key exchange is needed.
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized or the keyring is malformed.
pub fn add_co_owner(
    keyring_bytes: &[u8],
    founder: &UnlockedAccount,
    tree_id: &TreeId,
    min_revision: u32,
    target_member_id: &MemberId,
) -> Result<CoOwnerChanged, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the founder id is the account's self-certifying, verified member_id, never a caller label.
    let founder_member_id = founder.member_id.as_str();
    let target_member_id = target_member_id.as_str();
    let Opened {
        revision,
        prev_hash,
        rrk_secret,
        mut keyring,
        ..
    } = open_with_account(keyring_bytes, founder, tree_id)?;

    // Already a signer (this also rejects re-adding the founder) — a member at CO_OWNER or stronger.
    if keyring
        .members
        .iter()
        .any(|m| m.member_id == target_member_id && (m.role == OWNER || m.role == CO_OWNER_MEMBER))
    {
        return Err(VaultError::MemberExists);
    }
    // The target must exist and carry an author key — that pinned, OOB-verified key becomes their signer
    // key (a co-owner signs the keyring with it), so promotion needs no new key exchange.
    {
        let m = keyring
            .members
            .iter()
            .find(|m| m.member_id == target_member_id)
            .ok_or(VaultError::MemberNotFound)?;
        if m.author_public_key.is_empty() {
            return Err(VaultError::BadKeyring(
                "member has no author key to sign with".into(),
            ));
        }
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    // Promote by raising the member's role to CO_OWNER — which, since the signer set is derived from
    // members, makes them a signer. No separate roster entry to push.
    if let Some(m) = keyring
        .members
        .iter_mut()
        .find(|m| m.member_id == target_member_id)
    {
        m.role = CO_OWNER_MEMBER;
    }
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &founder.root.identity); // founder signs — authorizes the signer-set change
    // Pin the UNCHANGED write epoch at the new revision (OPE-286) — a promote re-wraps no keys.
    let deks = epoch_deks(&keyring_epochs(&keyring)?, tree_id, founder_member_id, &rrk_secret);
    let (write_key_id, write_dek_hash) = write_epoch_pin(&deks)?;
    Ok(CoOwnerChanged {
        keyring: keyring.encode_to_vec(),
        revision: new_revision,
        write_key_id,
        write_dek_hash,
    })
}

/// Demote a co-owner to an ordinary role, removing them from the authorized-signer set
/// (founder-authorized).
///
/// This revokes their signing/administration authority but NOT their
/// read access — they keep their per-epoch member wraps (forward-secrecy bound). To also
/// revoke read, remove them entirely with [`remove_member`]. `new_role` must be a non-signer
/// role (admin/editor/viewer).
///
/// # Errors
/// Returns [`VaultError`] if the author isn't authorized, the keyring is malformed, or the reseal fails.
pub fn remove_co_owner(
    keyring_bytes: &[u8],
    founder: &UnlockedAccount,
    tree_id: &TreeId,
    min_revision: u32,
    target_member_id: &MemberId,
    new_role: MemberRole,
) -> Result<CoOwnerChanged, VaultError> {
    let tree_id = tree_id.as_bytes();
    // OPE-543: the founder id is the account's self-certifying, verified member_id (this also makes the
    // founder-demote guard below compare against the REAL founder, not a caller label).
    let founder_member_id = founder.member_id.as_str();
    let target_member_id = target_member_id.as_str();
    if matches!(
        new_role,
        MemberRole::Unspecified | MemberRole::Owner | MemberRole::CoOwner
    ) {
        return Err(VaultError::BadKeyring(
            "demote target must be admin/editor/viewer".into(),
        ));
    }
    let Opened {
        revision,
        prev_hash,
        rrk_secret,
        mut keyring,
        ..
    } = open_with_account(keyring_bytes, founder, tree_id)?;

    if target_member_id == founder_member_id {
        return Err(VaultError::CannotRemoveOwner);
    }
    let is_co_owner = keyring
        .members
        .iter()
        .any(|m| m.member_id == target_member_id && m.role == CO_OWNER_MEMBER);
    if !is_co_owner {
        return Err(VaultError::MemberNotFound);
    }
    let new_revision = min_revision
        .max(revision)
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    // Demote by lowering the member's role to a non-signer role — which removes them from the derived
    // signer set. No separate roster entry to retain.
    if let Some(m) = keyring
        .members
        .iter_mut()
        .find(|m| m.member_id == target_member_id)
    {
        m.role = new_role as i32;
    }
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, &founder.root.identity); // founder signs
    // Pin the UNCHANGED write epoch at the new revision (OPE-286) — a demote re-wraps no keys.
    let deks = epoch_deks(&keyring_epochs(&keyring)?, tree_id, founder_member_id, &rrk_secret);
    let (write_key_id, write_dek_hash) = write_epoch_pin(&deks)?;
    Ok(CoOwnerChanged {
        keyring: keyring.encode_to_vec(),
        revision: new_revision,
        write_key_id,
        write_dek_hash,
    })
}

// ---- internals ----

struct Opened {
    /// The latest epoch's `key_id` (the write epoch).
    key_id: Vec<u8>,
    revision: u32,
    /// SHA-256 of this (opened) keyring's signing bytes — what a re-signed successor
    /// records as its `prev_keyring_hash` to chain the revision history.
    prev_hash: Vec<u8>,
    /// The recovery root private key (unwrapped via the account KEK) — reaches every epoch's DEK.
    rrk_secret: RrkSecret,
    /// The decoded prior keyring, so a mutating flow preserves its signers/members/epochs.
    keyring: Keyring,
}

/// Decode + verify the owner keyring and unwrap the recovery root key via the durable ACCOUNT KEK (OPE-543),
/// returning the write-epoch `key_id`, the RRK secret (which reaches every epoch), and coordinates.
///
/// The caller re-signs any mutation with `account.root.identity` (the owner IS the durable account, so its
/// signing key is threaded in, not re-derived here). Anti-substitution: the account identity must BE the
/// resolved OWNER `member_id`'s registered author key — a wrong account (or a swapped owner) fails closed.
fn open_with_account(
    keyring_bytes: &[u8],
    account: &UnlockedAccount,
    tree_id: &[u8],
) -> Result<Opened, VaultError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(VaultError::TreeMismatch);
    }
    // Anti-substitution + SELF-CERT (OPE-543): resolve the owner independently of the caller's label — the
    // account signing key must BE the resolved OWNER's registered author key AND the owner's on-tree id must
    // equal `derive_member_id(account key)`, so a server-swapped owner entry (mismatched id or key) fails
    // closed. The keyring must then be signed by SOME current authorized signer — a co-owner may have signed
    // the latest any-of change — so verify any-of over the current set (hardened by the deferred chain-walk).
    let account_pub = account.root.identity.verifying_key().to_bytes().to_vec();
    let expected_owner_id = derive_member_id(&account_pub);
    let is_owner = keyring
        .members
        .iter()
        .any(|m| m.role == OWNER && m.member_id == expected_owner_id && m.author_public_key == account_pub);
    if !is_owner {
        return Err(CryptoError::Signature.into());
    }
    // Use the self-certifying owner id (not the caller's label) for the RRK escrow lookup + AAD below.
    let member_id = expected_owner_id.as_str();
    verify_keyring_any(&keyring, &authorized_verify_keys(&keyring))
        .map_err(|_| CryptoError::Signature)?;
    // The owner reaches DEKs through the recovery root key, escrowed under the STABLE account KEK. `nonce` /
    // `wrapped` are owned (not borrowing the keyring). The wrap's stored KDF is a placeholder — the KEK is
    // the account's, supplied directly, never re-derived from the wrap.
    let escrow_wraps = {
        let rk = recovery_key_for(&keyring, member_id)?;
        rk.escrow_wraps()
            .map_err(|_| VaultError::BadKeyring("recovery key material malformed".into()))?
    };
    let (_kdf, nonce, wrapped) = escrow_kek_wrap(&escrow_wraps, KekKind::Passphrase)?;
    let rrk_secret = open_rrk_secret(
        &account.root.kek,
        nonce,
        wrapped,
        tree_id,
        member_id,
        KekKind::Passphrase,
    )?;

    let epochs = keyring_epochs(&keyring)?;
    let key_id = epochs
        .iter()
        .max_by_key(|e| e.ordinal)
        .ok_or_else(|| VaultError::BadKeyring("no epochs".into()))?
        .key_id
        .as_bytes()
        .to_vec();
    let prev_hash = keyring_hash(&keyring).to_vec();
    let revision = keyring.revision;
    Ok(Opened {
        key_id,
        revision,
        prev_hash,
        rrk_secret,
        keyring,
    })
}

fn decode_keyring(bytes: &[u8]) -> Result<Keyring, VaultError> {
    if bytes.len() > MAX_KEYRING_BYTES {
        return Err(VaultError::BadKeyring("too large".into()));
    }
    Keyring::decode(bytes).map_err(|e| VaultError::BadKeyring(e.to_string()))
}

/// `add_member` may only create an *ordinary* member — owner and co-owner are signer roles,
/// reached via provision / `add_co_owner`.
fn guard_ordinary_role(role: MemberRole) -> Result<(), VaultError> {
    if matches!(
        role,
        MemberRole::Unspecified | MemberRole::Owner | MemberRole::CoOwner
    ) {
        return Err(VaultError::BadKeyring(
            "member role must be admin/editor/viewer".into(),
        ));
    }
    Ok(())
}

/// What a co-owner's administrative open yields: their signing identity, their HPKE secret
/// (to reach epoch DEKs via their own member wraps), and the decoded keyring + coordinates.
struct CoOwnerAccess {
    identity: SigningKey,
    hpke_secret: HpkePrivate,
    revision: u32,
    prev_hash: Vec<u8>,
    keyring: Keyring,
}

/// Open a keyring for a co-owner's administrative action (any-of): verify against the
/// caller's **pinned** signer set (OOB, §4a), derive their identity + HPKE secret from their
/// account passphrase/KDF, and confirm they are a current **co-owner** signer with that
/// identity. Only then may they administer, signing with their own key.
fn open_as_co_owner(
    keyring_bytes: &[u8],
    passphrase: &[u8],
    kdf: &KeyeoKdfParams,
    tree_id: &[u8],
    member_id: &str,
    trusted_signers: &[VerifyingKey],
) -> Result<CoOwnerAccess, VaultError> {
    let keyring = decode_keyring(keyring_bytes)?;
    if keyring.tree_id != tree_id {
        return Err(VaultError::TreeMismatch);
    }
    // Anti-substitution anchor: the keyring's founder entry must match a key the co-owner
    // pinned out-of-band, so the server can't swap the whole signer set. The revision itself
    // may have been signed by any current authorized signer (a co-owner did an ordinary
    // change), so verify any-of over the current set — hardened later by the chain-walk.
    let founder_pinned = keyring.members.iter().any(|m| {
        m.role == OWNER
            && trusted_signers
                .iter()
                .any(|t| m.author_public_key.as_slice() == &t.to_bytes()[..])
    });
    if !founder_pinned {
        return Err(CryptoError::Signature.into());
    }
    verify_keyring_any(&keyring, &authorized_verify_keys(&keyring))
        .map_err(|_| CryptoError::Signature)?;
    validate_kdf(kdf)?;
    let root = derive_root(passphrase, kdf)?;
    // Authority: the caller must be a current co-owner signer (a CO_OWNER-role member) whose registered
    // author key is theirs.
    let my_pub = root.identity.verifying_key().to_bytes().to_vec();
    let authorized = keyring.members.iter().any(|m| {
        m.member_id == member_id && m.role == CO_OWNER_MEMBER && m.author_public_key == my_pub
    });
    if !authorized {
        return Err(VaultError::NotAuthorized);
    }
    let prev_hash = keyring_hash(&keyring).to_vec();
    let revision = keyring.revision;
    Ok(CoOwnerAccess {
        identity: root.identity,
        hpke_secret: root.hpke_secret,
        revision,
        prev_hash,
        keyring,
    })
}

/// The Ed25519 verify keys of the keyring's current authorized signers — the members at `CO_OWNER` or
/// stronger (the signer set is derived from members, OPE-309); malformed keys skipped. Used for any-of
/// verification of an ordinary revision, which a co-owner may have signed. Trusting this document-provided
/// set is hardened by the deferred client chain-walk.
fn authorized_verify_keys(keyring: &Keyring) -> Vec<VerifyingKey> {
    keyring
        .members
        .iter()
        .filter(|m| m.role == OWNER || m.role == CO_OWNER_MEMBER)
        .filter_map(|m| {
            let arr: [u8; 32] = m.author_public_key.as_slice().try_into().ok()?;
            VerifyingKey::from_bytes(&arr).ok()
        })
        .collect()
}

/// Founder identity's member id (needed to locate the RRK wrap and skip the founder — who
/// has no per-epoch member wrap — when re-wrapping a new epoch). The founder is the sole OWNER-role member.
fn founder_member_id(keyring: &Keyring) -> Result<String, VaultError> {
    keyring
        .members
        .iter()
        .find(|m| m.role == OWNER)
        .map(|m| m.member_id.clone())
        .ok_or_else(|| VaultError::BadKeyring("no founder".into()))
}

/// The core of adding a member: HPKE-wrap each reachable epoch's DEK to them, record them in
/// the member list, bump/chain the revision, and sign with `identity`. Shared by the founder
/// and co-owner paths so the two can't drift.
fn do_add_member(
    mut keyring: Keyring,
    tree_id: &[u8],
    deks: &[(Vec<u8>, u64, Dek)],
    identity: &SigningKey,
    prev_hash: Vec<u8>,
    new_revision: u32,
    joiner: &Joiner<MemberRole>,
) -> Result<MemberAdded, VaultError> {
    let new_member_id = joiner.member_id.as_str();
    // The joiner's HPKE key, narrowed once (in `Joiner::from_bytes`); the SAME value addresses every wrap
    // and is registered in the member list, so the wrapped key and the stored key are provably identical.
    let hpke_public_key = joiner.hpke_public_key.to_bytes();
    let mut epochs = keyring_epochs(&keyring)?;
    for (key_id, epoch, dek) in deks {
        let wrap = member_wrap_keyeo(&hpke_public_key, dek, tree_id, new_member_id, key_id)?;
        let ep = epochs
            .iter_mut()
            .find(|e| e.ordinal == *epoch)
            .ok_or_else(|| VaultError::BadKeyring("epoch vanished".into()))?;
        ep.wraps.push(wrap);
    }
    keyring.epochs = codec::encode_epochs(&epochs);
    keyring.members.push(Member {
        member_id: new_member_id.to_string(),
        role: joiner.role as i32,
        author_public_key: joiner.author_public_key.to_bytes().to_vec(),
        hpke_public_key: joiner.hpke_public_key.to_bytes().to_vec(),
    });
    // First share: a founding-solo tree becomes multi-author the instant a non-founder member is admitted.
    // Set the monotonic marker once, on that first add (later adds leave it — already non-zero). It is NEVER
    // cleared (remove_member doesn't touch it), so an un-shared-back-to-solo tree still requires attribution.
    // Set BEFORE sign_keyring so it is covered by the signature.
    if keyring.first_shared_revision == 0 {
        keyring.first_shared_revision = new_revision;
    }
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, identity);
    // An add mints no new epoch — carry the unchanged write epoch's pin forward so the watermark keeps
    // the recover commitment rather than erasing it (OPE-286 phase 2).
    let (write_key_id, write_dek_hash) = write_epoch_pin(deks)?;
    Ok(MemberAdded {
        keyring: keyring.encode_to_vec(),
        revision: new_revision,
        write_key_id,
        write_dek_hash,
    })
}

/// The core of a forward-secure removal: mint a new epoch DEK, wrap it for the founder (RRK
/// public key) and each remaining member, drop the removed member from the member list and
/// signer set, strip their wraps from old epochs, and sign with `identity`. Returns the
/// mutated keyring and the new epoch's key id (the caller builds the sealer set with their
/// own access). Shared by the founder and co-owner paths.
fn do_remove_member(
    mut keyring: Keyring,
    tree_id: &[u8],
    remove_member_id: &str,
    identity: &SigningKey,
    prev_hash: Vec<u8>,
    new_revision: u32,
) -> Result<(Keyring, Vec<u8>), VaultError> {
    let founder_id = founder_member_id(&keyring)?;
    let mut epochs = keyring_epochs(&keyring)?;
    let old_epoch = epochs
        .iter()
        .map(|e| e.ordinal)
        .max()
        .ok_or_else(|| VaultError::BadKeyring("no epochs".into()))?;
    let new_dek = generate_dek()?;
    let new_key_id = generate_salt()?.to_vec();
    let new_epoch = old_epoch
        .checked_add(1)
        .ok_or(VaultError::RevisionOverflow)?;

    let rrk_public = recovery_key_for(&keyring, &founder_id)?.public_key.clone();
    let mut wraps = vec![rrk_wrap_keyeo(
        &rrk_public,
        &new_dek,
        tree_id,
        &founder_id,
        &new_key_id,
    )?];
    for m in &keyring.members {
        if m.member_id == founder_id || m.member_id == remove_member_id {
            continue;
        }
        wraps.push(member_wrap_keyeo(
            &m.hpke_public_key,
            &new_dek,
            tree_id,
            &m.member_id,
            &new_key_id,
        )?);
    }

    epochs.push(KeyeoEpoch {
        key_id: KeyeoKeyId::new(new_key_id.clone()),
        ordinal: new_epoch,
        dek_commitment: keyeo_crypto::dek_commitment(&new_dek),
        wraps,
    });
    // Removing the member removes them from the derived signer set too (no separate roster to retain).
    keyring.members.retain(|m| m.member_id != remove_member_id);
    for ep in &mut epochs {
        ep.wraps.retain(|w| w.recipient != remove_member_id);
    }
    keyring.epochs = codec::encode_epochs(&epochs);
    keyring.revision = new_revision;
    keyring.prev_keyring_hash = prev_hash;
    keyring.signatures.clear();
    sign_keyring(&mut keyring, identity);
    Ok((keyring, new_key_id))
}

/// The founder's recovery key entry (by member id).
fn recovery_key_for<'a>(
    keyring: &'a Keyring,
    member_id: &str,
) -> Result<&'a RecoveryKey, VaultError> {
    keyring
        .recovery_keys
        .iter()
        .find(|r| r.member_id == member_id)
        .ok_or(VaultError::MissingWrap)
}

const _: () = assert!(KEY_ID_LEN == 16);


#[cfg(test)]
mod tests {
    use super::{
        add_co_owner, add_member, add_member_as_co_owner, adopt_member_epochs, change_passphrase,
        provision, provision_member, recover, remove_co_owner, remove_member,
        remove_member_as_co_owner, unlock, unlock_as_member, Joiner, MemberAuth, RecoverWatermark,
    };
    use crate::{AccountKeystore, UnlockedAccount, VaultError};
    use openom_crypto::{derive_root, generate_recovery_code, Passphrase, RecoveryCode};
    use openom_keyring_api::derive_member_id;
    use openom_keyring_chain::wire::{Keyring, Member};
    use openom_keyring_chain::{sign_keyring, verify_keyring, VerifyingKey};
    use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
    use openom_protocol::v1::MemberRole;
    use openom_protocol::Message;
    use openom_sealer::{EntryKind, SealContext, SealerSet};

    const TREE: &[u8] = b"tree-uuid-16byte";
    const MEMBER: &str = "acct-1";

    /// Mint an owner's durable ACCOUNT keystore (OPE-543 durable identity) from a passphrase, plus its
    /// one-time account recovery code. The derived identity is random-but-stable across unlock, so one
    /// keystore is the tree's single owner across provision / unlock / membership ops.
    fn make_owner(pass: &Passphrase) -> (AccountKeystore, RecoveryCode) {
        let (ks, code, _u) = AccountKeystore::create(pass.expose()).unwrap();
        (ks, code)
    }
    /// A fresh `UnlockedAccount` for the owner (each vault call that signs consumes one).
    fn acct(ks: &AccountKeystore, pass: &Passphrase) -> UnlockedAccount {
        ks.unlock(pass.expose()).unwrap()
    }
    /// The owner's SELF-CERTIFYING on-tree `member_id` (OPE-543): `derive_member_id(account author key)`.
    /// `provision` derives the owner id from the account key (ignoring the caller's label), so this is the id
    /// the keyring records and the id every owner-path DEK/escrow lookup is keyed by — tests assert against it
    /// and pass it where the real owner id is needed.
    fn owner_id(ks: &AccountKeystore, pass: &Passphrase) -> MemberId {
        MemberId::new(derive_member_id(
            &ks.unlock(pass.expose()).unwrap().root.identity.verifying_key().to_bytes(),
        ))
    }
    /// The self-certifying joiner id for a member's author key — the client constructs only self-certifying
    /// joiners (OPE-543 `Joiner::from_bytes` admission).
    fn jid(author_public_key: &[u8]) -> MemberId {
        MemberId::new(derive_member_id(author_public_key))
    }

    /// The founder's verify key, as a member would pin it out-of-band — the OWNER-role member's author key.
    fn founder_key(keyring_bytes: &[u8]) -> VerifyingKey {
        let k = Keyring::decode(keyring_bytes).unwrap();
        let founder = k
            .members
            .iter()
            .find(|m| m.role == MemberRole::Owner as i32)
            .unwrap();
        let bytes: [u8; 32] = founder.author_public_key.as_slice().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    fn vk(bytes: &[u8]) -> VerifyingKey {
        VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap()
    }

    fn seal_open(sealer: &SealerSet, plaintext: &[u8]) -> Vec<u8> {
        sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), plaintext)
            .unwrap()
            .envelope
    }

    fn first_shared(keyring_bytes: &[u8]) -> u32 {
        Keyring::decode(keyring_bytes).unwrap().first_shared_revision
    }

    fn no_watermark() -> RecoverWatermark<'static> {
        RecoverWatermark { min_revision: 0, write_key_id: &[], dek_hash: &[] }
    }

    #[test]
    fn provision_then_unlock_on_another_device_opens_the_same_data() {
        let pass = Passphrase::new(b"correct horse");
        let (ks, _code) = make_owner(&pass);
        let me = owner_id(&ks, &pass);
        let p = provision(
            &acct(&ks, &pass),
            &TreeId::new(TREE),
            &me,
            &ReplicaId::new(b"replica-A"),
        )
        .unwrap();
        assert!(p.recovery_code.expose().is_empty(), "no per-tree recovery code under durable identity");
        let sealed = seal_open(&p.sealer, b"the family tree");

        let u = unlock(
            &p.keyring,
            &acct(&ks, &pass),
            &TreeId::new(TREE),
            &ReplicaId::new(b"replica-B"),
        )
        .unwrap();
        assert_eq!(u.revision, 1);
        assert_eq!(u.did_key, p.did_key, "the durable account identity is stable");
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"the family tree");
    }

    #[test]
    fn unlock_with_the_wrong_account_is_rejected() {
        let pass = Passphrase::new(b"right");
        let (ks, _c) = make_owner(&pass);
        let p = provision(&acct(&ks, &pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        let other_pass = Passphrase::new(b"someone else");
        let (other_ks, _c2) = make_owner(&other_pass);
        assert!(unlock(
            &p.keyring,
            &acct(&other_ks, &other_pass),
            &TreeId::new(TREE),
            &ReplicaId::new(b"r"),
        )
        .is_err());
    }

    #[test]
    fn a_keyring_for_another_tree_is_refused() {
        let pass = Passphrase::new(b"pass");
        let (ks, _c) = make_owner(&pass);
        let p = provision(&acct(&ks, &pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        assert!(matches!(
            unlock(&p.keyring, &acct(&ks, &pass), &TreeId::new(b"other-tree-16byt"), &ReplicaId::new(b"r")),
            Err(VaultError::TreeMismatch)
        ));
    }

    #[test]
    fn a_tampered_keyring_fails_verification() {
        let pass = Passphrase::new(b"pass");
        let (ks, _c) = make_owner(&pass);
        let p = provision(&acct(&ks, &pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        let mut k = Keyring::decode(p.keyring.as_slice()).unwrap();
        k.epochs[0] ^= 0xFF;
        let bytes = k.encode_to_vec();
        assert!(unlock(&bytes, &acct(&ks, &pass), &TreeId::new(TREE), &ReplicaId::new(b"r")).is_err());
    }

    #[test]
    fn provisioned_keyring_is_a_genesis_single_owner() {
        let pass = Passphrase::new(b"pass");
        let (ks, _c) = make_owner(&pass);
        let me = owner_id(&ks, &pass);
        let p = provision(&acct(&ks, &pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r")).unwrap();
        let k = Keyring::decode(p.keyring.as_slice()).unwrap();
        assert_eq!(k.layout_version, 1);
        assert_eq!(k.revision, 1);
        assert!(k.prev_keyring_hash.is_empty());
        assert_eq!(k.members.len(), 1);
        assert_eq!(k.members[0].role, MemberRole::Owner as i32);
        assert_eq!(k.members[0].member_id, me.as_str());
        assert_eq!(k.signatures.len(), 1);
        assert_eq!(k.signatures[0].signer_public_key, k.members[0].author_public_key);
    }

    #[test]
    fn did_key_is_the_account_identity_and_stable_across_unlock() {
        let pass = Passphrase::new(b"correct horse");
        let (ks, _c) = make_owner(&pass);
        let me = owner_id(&ks, &pass);
        let p = provision(&acct(&ks, &pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"replica-A")).unwrap();
        let founder = founder_key(&p.keyring).to_bytes();
        assert_eq!(p.did_key.as_str(), did::encode_ed25519(&founder));
        assert!(p.did_key.as_str().starts_with("did:key:z6Mk"));
        let u = unlock(&p.keyring, &acct(&ks, &pass), &TreeId::new(TREE), &ReplicaId::new(b"replica-B")).unwrap();
        assert_eq!(u.did_key, p.did_key);
    }

    #[test]
    fn change_passphrase_rewraps_the_account_without_touching_the_tree() {
        let old = Passphrase::new(b"old");
        let (ks, _c) = make_owner(&old);
        let me = owner_id(&ks, &old);
        let p = provision(&acct(&ks, &old), &TreeId::new(TREE), &me, &ReplicaId::new(b"r")).unwrap();
        let ks_bytes = ks.to_bytes().unwrap();
        let re = change_passphrase(
            &p.keyring,
            &ks_bytes,
            &Passphrase::new(b"old"),
            &Passphrase::new(b"new"),
            &TreeId::new(TREE),
            &me,
            0,
        )
        .unwrap();
        assert_eq!(re.keyring, p.keyring, "the tree anchor is unchanged");
        assert_eq!(re.revision, 1);
        assert!(re.recovery_code.expose().is_empty());
        let new_ks = AccountKeystore::from_bytes(&re.keystore).unwrap();
        assert!(new_ks.unlock(b"new").is_ok());
        assert!(new_ks.unlock(b"old").is_err());
        let u = unlock(&re.keyring, &new_ks.unlock(b"new").unwrap(), &TreeId::new(TREE), &ReplicaId::new(b"r")).unwrap();
        assert_eq!(u.did_key, p.did_key);
    }

    #[test]
    fn change_passphrase_with_the_wrong_old_passphrase_fails() {
        let old = Passphrase::new(b"old");
        let (ks, _c) = make_owner(&old);
        let p = provision(&acct(&ks, &old), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        let ks_bytes = ks.to_bytes().unwrap();
        assert!(change_passphrase(
            &p.keyring,
            &ks_bytes,
            &Passphrase::new(b"wrong"),
            &Passphrase::new(b"new"),
            &TreeId::new(TREE),
            &MemberId::new(MEMBER),
            0,
        )
        .is_err());
    }

    #[test]
    fn recover_restores_the_same_identity_and_opens_the_data() {
        let old = Passphrase::new(b"old");
        let (ks, code) = make_owner(&old);
        let me = owner_id(&ks, &old);
        let p = provision(&acct(&ks, &old), &TreeId::new(TREE), &me, &ReplicaId::new(b"r")).unwrap();
        let sealed = seal_open(&p.sealer, b"data");
        let ks_bytes = ks.to_bytes().unwrap();

        let rec = recover(
            &p.keyring,
            &ks_bytes,
            &code,
            &Passphrase::new(b"new"),
            &TreeId::new(TREE),
            &ReplicaId::new(b"r2"),
            &no_watermark(),
        )
        .unwrap();
        assert_eq!(rec.did_key, p.did_key, "recovery restores the SAME durable identity");
        assert_eq!(rec.keyring, p.keyring, "no on-tree op — the anchor is unchanged");
        assert!(rec.recovery_code.expose().is_empty());
        assert_eq!(rec.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"data");
        let new_ks = AccountKeystore::from_bytes(&rec.keystore).unwrap();
        assert!(new_ks.unlock(b"new").is_ok());
        assert!(new_ks.unlock(b"old").is_err());
        assert!(new_ks.unlock_with_recovery(&code).is_ok());
    }

    #[test]
    fn recover_with_the_wrong_code_fails() {
        let old = Passphrase::new(b"old");
        let (ks, _code) = make_owner(&old);
        let p = provision(&acct(&ks, &old), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        let ks_bytes = ks.to_bytes().unwrap();
        let wrong = generate_recovery_code().unwrap();
        assert!(recover(
            &p.keyring,
            &ks_bytes,
            &wrong,
            &Passphrase::new(b"new"),
            &TreeId::new(TREE),
            &ReplicaId::new(b"r"),
            &no_watermark(),
        )
        .is_err());
    }

    #[test]
    fn recover_refuses_a_revision_below_the_watermark() {
        let old = Passphrase::new(b"old");
        let (ks, code) = make_owner(&old);
        let p = provision(&acct(&ks, &old), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r")).unwrap();
        let ks_bytes = ks.to_bytes().unwrap();
        assert!(matches!(
            recover(
                &p.keyring,
                &ks_bytes,
                &code,
                &Passphrase::new(b"new"),
                &TreeId::new(TREE),
                &ReplicaId::new(b"r"),
                &RecoverWatermark { min_revision: 5, write_key_id: &[], dek_hash: &[] },
            ),
            Err(VaultError::RevisionRollback { .. })
        ));
    }

    #[test]
    fn joiner_from_bytes_enforces_self_cert() {
        let m = provision_member(&Passphrase::new(b"m")).unwrap();
        assert!(Joiner::<MemberRole>::from_bytes(
            &MemberId::new("acct-not-derived"),
            MemberRole::Editor,
            &m.author_public_key,
            &m.hpke_public_key,
        )
        .is_err());
        assert!(Joiner::<MemberRole>::from_bytes(
            &jid(&m.author_public_key),
            MemberRole::Editor,
            &m.author_public_key,
            &m.hpke_public_key,
        )
        .is_ok());
    }

    #[test]
    fn owner_adds_a_member_who_unlocks_and_reads_the_tree() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        let sealed = seal_open(&owner.sealer, b"our shared ancestry");

        let m = provision_member(&Passphrase::new(b"member pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let added = add_member(
            &owner.keyring,
            &acct(&ks, &owner_pass),
            &TreeId::new(TREE),
            0,
            &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap(),
        )
        .unwrap();
        assert_eq!(added.revision, 2);
        let k = Keyring::decode(added.keyring.as_slice()).unwrap();
        assert!(k.members.iter().any(|mm| mm.member_id == mid.as_str() && mm.role == MemberRole::Editor as i32));

        let pinned = founder_key(&owner.keyring);
        let (u, _) = unlock_as_member(
            &added.keyring,
            &MemberAuth { passphrase: &Passphrase::new(b"member pass"), kdf: &m.kdf_params, member_id: &mid, trusted_signers: &[pinned] },
            &TreeId::new(TREE),
            &ReplicaId::new(b"r-mem"),
            0,
        )
        .unwrap();
        assert_eq!(u.revision, 2);
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"our shared ancestry");
    }

    #[test]
    fn a_member_unlock_needs_the_pinned_signer_and_right_passphrase() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        let m = provision_member(&Passphrase::new(b"member pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let added = add_member(
            &owner.keyring,
            &acct(&ks, &owner_pass),
            &TreeId::new(TREE),
            0,
            &Joiner::from_bytes(&mid, MemberRole::Viewer, &m.author_public_key, &m.hpke_public_key).unwrap(),
        )
        .unwrap();

        let wpass = Passphrase::new(b"someone else");
        let (wks, _wc) = make_owner(&wpass);
        let wrong = provision(&acct(&wks, &wpass), &TreeId::new(b"other-tree-16byt"), &MemberId::new("x"), &ReplicaId::new(b"r")).unwrap();
        let wrong_key = founder_key(&wrong.keyring);
        assert!(unlock_as_member(
            &added.keyring,
            &MemberAuth { passphrase: &Passphrase::new(b"member pass"), kdf: &m.kdf_params, member_id: &mid, trusted_signers: &[wrong_key] },
            &TreeId::new(TREE),
            &ReplicaId::new(b"r"),
            0,
        )
        .is_err());

        let pinned = founder_key(&owner.keyring);
        assert!(unlock_as_member(
            &added.keyring,
            &MemberAuth { passphrase: &Passphrase::new(b"WRONG"), kdf: &m.kdf_params, member_id: &mid, trusted_signers: &[pinned] },
            &TreeId::new(TREE),
            &ReplicaId::new(b"r"),
            0,
        )
        .is_err());
    }

    #[test]
    fn adding_the_same_member_twice_is_rejected() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        let m = provision_member(&Passphrase::new(b"member pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let added = add_member(
            &owner.keyring,
            &acct(&ks, &owner_pass),
            &TreeId::new(TREE),
            0,
            &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            add_member(
                &added.keyring,
                &acct(&ks, &owner_pass),
                &TreeId::new(TREE),
                0,
                &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap(),
            ),
            Err(VaultError::MemberExists)
        ));
    }

    #[test]
    fn add_member_with_the_wrong_owner_account_fails() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r-owner")).unwrap();
        let m = provision_member(&Passphrase::new(b"member pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let wpass = Passphrase::new(b"WRONG owner");
        let (wks, _wc) = make_owner(&wpass);
        assert!(add_member(
            &owner.keyring,
            &acct(&wks, &wpass),
            &TreeId::new(TREE),
            0,
            &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn removing_a_member_re_keys_and_denies_them_new_content() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        let a = provision_member(&Passphrase::new(b"a pass")).unwrap();
        let b = provision_member(&Passphrase::new(b"b pass")).unwrap();
        let a_id = jid(&a.author_public_key);
        let b_id = jid(&b.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&a_id, MemberRole::Editor, &a.author_public_key, &a.hpke_public_key).unwrap()).unwrap();
        let k2 = add_member(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&b_id, MemberRole::Viewer, &b.author_public_key, &b.hpke_public_key).unwrap()).unwrap();
        let pinned = founder_key(&owner.keyring);

        let removed = remove_member(&k2.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &a_id, &ReplicaId::new(b"r-owner2")).unwrap();
        let new_sealed = seal_open(&removed.sealer, b"post-removal secret");

        assert!(matches!(
            unlock_as_member(&removed.keyring, &MemberAuth { passphrase: &Passphrase::new(b"a pass"), kdf: &a.kdf_params, member_id: &a_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r"), 0),
            Err(VaultError::MissingWrap)
        ));

        let (bu, _) = unlock_as_member(&removed.keyring, &MemberAuth { passphrase: &Passphrase::new(b"b pass"), kdf: &b.kdf_params, member_id: &b_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-b"), 0).unwrap();
        assert_eq!(bu.sealer.open_entry(EntryKind::Snapshot, &new_sealed).unwrap(), b"post-removal secret");

        assert!(unlock(&removed.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), &ReplicaId::new(b"r")).is_ok());
    }

    #[test]
    fn a_remaining_member_adopts_the_rotated_epoch_without_a_passphrase() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        let a = provision_member(&Passphrase::new(b"a pass")).unwrap();
        let b = provision_member(&Passphrase::new(b"b pass")).unwrap();
        let a_id = jid(&a.author_public_key);
        let b_id = jid(&b.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&a_id, MemberRole::Editor, &a.author_public_key, &a.hpke_public_key).unwrap()).unwrap();
        let k2 = add_member(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&b_id, MemberRole::Editor, &b.author_public_key, &b.hpke_public_key).unwrap()).unwrap();
        let pinned = founder_key(&owner.keyring);

        let (bu, b_hpke) = unlock_as_member(&k2.keyring, &MemberAuth { passphrase: &Passphrase::new(b"b pass"), kdf: &b.kdf_params, member_id: &b_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-b"), 0).unwrap();
        let (_, a_hpke) = unlock_as_member(&k2.keyring, &MemberAuth { passphrase: &Passphrase::new(b"a pass"), kdf: &a.kdf_params, member_id: &a_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-a"), 0).unwrap();

        let removed = remove_member(&k2.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &a_id, &ReplicaId::new(b"r-owner2")).unwrap();
        let new_sealed = seal_open(&removed.sealer, b"post-removal secret");
        assert!(bu.sealer.open_entry(EntryKind::Snapshot, &new_sealed).is_err());

        let adopted = adopt_member_epochs(&removed.keyring, &b_hpke, TREE, b_id.as_str()).unwrap();
        let mut sealer = bu.sealer;
        sealer.adopt_epochs(adopted.epochs, adopted.write_key_id, adopted.governing_ref);
        assert_eq!(sealer.open_entry(EntryKind::Snapshot, &new_sealed).unwrap(), b"post-removal secret");

        assert!(matches!(adopt_member_epochs(&removed.keyring, &a_hpke, TREE, a_id.as_str()), Err(VaultError::MissingWrap)));
    }

    #[test]
    fn owner_reads_across_epochs_after_a_rotation() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let old = seal_open(&owner.sealer, b"old epoch content");
        let m = provision_member(&Passphrase::new(b"m pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap()).unwrap();
        let removed = remove_member(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &mid, &ReplicaId::new(b"r-o2")).unwrap();
        let new = seal_open(&removed.sealer, b"new epoch content");
        let u = unlock(&removed.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), &ReplicaId::new(b"r")).unwrap();
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &old).unwrap(), b"old epoch content");
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &new).unwrap(), b"new epoch content");
    }

    #[test]
    fn a_member_added_later_reads_the_pre_join_history() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let pre = seal_open(&owner.sealer, b"pre-join photo");
        let m = provision_member(&Passphrase::new(b"m pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let added = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&mid, MemberRole::Viewer, &m.author_public_key, &m.hpke_public_key).unwrap()).unwrap();
        let pinned = founder_key(&owner.keyring);
        let (u, _) = unlock_as_member(&added.keyring, &MemberAuth { passphrase: &Passphrase::new(b"m pass"), kdf: &m.kdf_params, member_id: &mid, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-m"), 0).unwrap();
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &pre).unwrap(), b"pre-join photo");
    }

    #[test]
    fn founder_promotes_and_demotes_a_co_owner() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let added = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();

        let promoted = add_co_owner(&added.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id).unwrap();
        let k = Keyring::decode(promoted.keyring.as_slice()).unwrap();
        assert!(k.members.iter().any(|m| m.member_id == co_id.as_str() && m.role == MemberRole::CoOwner as i32 && m.author_public_key == co.author_public_key));
        verify_keyring(&k, &founder_key(&owner.keyring)).unwrap();

        assert!(matches!(
            add_co_owner(&promoted.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id),
            Err(VaultError::MemberExists)
        ));
        assert!(matches!(
            add_co_owner(&promoted.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &MemberId::new("nobody")),
            Err(VaultError::MemberNotFound)
        ));

        let demoted = remove_co_owner(&promoted.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id, MemberRole::Viewer).unwrap();
        let k2 = Keyring::decode(demoted.keyring.as_slice()).unwrap();
        assert!(!k2.members.iter().any(|m| m.member_id == co_id.as_str() && (m.role == MemberRole::Owner as i32 || m.role == MemberRole::CoOwner as i32)));
        assert!(k2.members.iter().any(|m| m.member_id == co_id.as_str() && m.role == MemberRole::Viewer as i32));
        assert!(matches!(
            remove_co_owner(&demoted.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id, MemberRole::Viewer),
            Err(VaultError::MemberNotFound)
        ));
    }

    #[test]
    fn a_co_owner_adds_a_member_who_reads_the_tree() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let sealed = seal_open(&owner.sealer, b"tree content");
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();
        let promoted = add_co_owner(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id).unwrap();
        let pinned = founder_key(&owner.keyring);

        let m3 = provision_member(&Passphrase::new(b"m3 pass")).unwrap();
        let m3_id = jid(&m3.author_public_key);
        let added = add_member_as_co_owner(
            &promoted.keyring,
            &MemberAuth { passphrase: &Passphrase::new(b"co pass"), kdf: &co.kdf_params, member_id: &co_id, trusted_signers: &[pinned] },
            &TreeId::new(TREE),
            0,
            &Joiner::from_bytes(&m3_id, MemberRole::Viewer, &m3.author_public_key, &m3.hpke_public_key).unwrap(),
        )
        .unwrap();

        let co_vk = vk(&co.author_public_key);
        let (u, _) = unlock_as_member(&added.keyring, &MemberAuth { passphrase: &Passphrase::new(b"m3 pass"), kdf: &m3.kdf_params, member_id: &m3_id, trusted_signers: &[pinned, co_vk] }, &TreeId::new(TREE), &ReplicaId::new(b"r-m3"), 0).unwrap();
        assert_eq!(u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(), b"tree content");
    }

    #[test]
    fn a_co_owner_removes_a_member_forward_securely() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let victim = provision_member(&Passphrase::new(b"v pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let victim_id = jid(&victim.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();
        let k2 = add_member(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&victim_id, MemberRole::Editor, &victim.author_public_key, &victim.hpke_public_key).unwrap()).unwrap();
        let promoted = add_co_owner(&k2.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id).unwrap();
        let pinned = founder_key(&owner.keyring);

        let removed = remove_member_as_co_owner(
            &promoted.keyring,
            &MemberAuth { passphrase: &Passphrase::new(b"co pass"), kdf: &co.kdf_params, member_id: &co_id, trusted_signers: &[pinned] },
            &TreeId::new(TREE),
            0,
            &victim_id,
            &ReplicaId::new(b"r-co"),
        )
        .unwrap();
        let new = seal_open(&removed.sealer, b"post-removal");
        let co_vk = vk(&co.author_public_key);
        assert!(matches!(
            unlock_as_member(&removed.keyring, &MemberAuth { passphrase: &Passphrase::new(b"v pass"), kdf: &victim.kdf_params, member_id: &victim_id, trusted_signers: &[pinned, co_vk] }, &TreeId::new(TREE), &ReplicaId::new(b"r"), 0),
            Err(VaultError::MissingWrap)
        ));
        let ou = unlock(&removed.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), &ReplicaId::new(b"r-o2")).unwrap();
        assert_eq!(ou.sealer.open_entry(EntryKind::Snapshot, &new).unwrap(), b"post-removal");
    }

    #[test]
    fn an_ordinary_member_cannot_administer() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let ed = provision_member(&Passphrase::new(b"ed pass")).unwrap();
        let ed_id = jid(&ed.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&ed_id, MemberRole::Editor, &ed.author_public_key, &ed.hpke_public_key).unwrap()).unwrap();
        let pinned = founder_key(&owner.keyring);
        let m3 = provision_member(&Passphrase::new(b"m3 pass")).unwrap();
        let m3_id = jid(&m3.author_public_key);
        assert!(matches!(
            add_member_as_co_owner(&k1.keyring, &MemberAuth { passphrase: &Passphrase::new(b"ed pass"), kdf: &ed.kdf_params, member_id: &ed_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), 0, &Joiner::from_bytes(&m3_id, MemberRole::Viewer, &m3.author_public_key, &m3.hpke_public_key).unwrap()),
            Err(VaultError::NotAuthorized)
        ));
        assert!(matches!(
            remove_member_as_co_owner(&k1.keyring, &MemberAuth { passphrase: &Passphrase::new(b"ed pass"), kdf: &ed.kdf_params, member_id: &ed_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), 0, &MemberId::new(MEMBER), &ReplicaId::new(b"r")),
            Err(VaultError::NotAuthorized)
        ));
    }

    #[test]
    fn a_co_owner_cannot_remove_a_signer() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co1 = provision_member(&Passphrase::new(b"co1 pass")).unwrap();
        let co2 = provision_member(&Passphrase::new(b"co2 pass")).unwrap();
        let co1_id = jid(&co1.author_public_key);
        let co2_id = jid(&co2.author_public_key);
        let k1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co1_id, MemberRole::Editor, &co1.author_public_key, &co1.hpke_public_key).unwrap()).unwrap();
        let k2 = add_member(&k1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co2_id, MemberRole::Editor, &co2.author_public_key, &co2.hpke_public_key).unwrap()).unwrap();
        let p1 = add_co_owner(&k2.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co1_id).unwrap();
        let p2 = add_co_owner(&p1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co2_id).unwrap();
        let pinned = founder_key(&owner.keyring);
        assert!(matches!(
            remove_member_as_co_owner(&p2.keyring, &MemberAuth { passphrase: &Passphrase::new(b"co1 pass"), kdf: &co1.kdf_params, member_id: &co1_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), 0, &co2_id, &ReplicaId::new(b"r")),
            Err(VaultError::NotAuthorized)
        ));
    }

    #[test]
    fn add_member_rejects_a_signer_role() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r-o")).unwrap();
        let m = provision_member(&Passphrase::new(b"m pass")).unwrap();
        let mid = jid(&m.author_public_key);
        assert!(add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&mid, MemberRole::CoOwner, &m.author_public_key, &m.hpke_public_key).unwrap()).is_err());
        assert!(add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&mid, MemberRole::Owner, &m.author_public_key, &m.hpke_public_key).unwrap()).is_err());
    }

    #[test]
    fn a_signer_set_change_not_signed_by_the_founder_is_rejected() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let added = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();
        let promoted = add_co_owner(&added.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id).unwrap();
        let founder = founder_key(&owner.keyring);

        let co_identity = derive_root(b"co pass", &co.kdf_params).unwrap().identity;
        let mut k = Keyring::decode(promoted.keyring.as_slice()).unwrap();
        k.members.push(Member { member_id: "acct-rogue".into(), role: MemberRole::CoOwner as i32, author_public_key: vec![9u8; 32], hpke_public_key: vec![9u8; 32] });
        k.revision += 1;
        k.signatures.clear();
        sign_keyring(&mut k, &co_identity);
        assert!(verify_keyring(&k, &founder).is_err());
        verify_keyring(&k, &co_identity.verifying_key()).unwrap();
    }

    #[test]
    fn the_owner_cannot_be_removed_and_a_non_member_is_rejected() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        // The owner's on-tree id is the account's SELF-CERTIFYING derived id (OPE-543), not a caller label.
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        // Removing the DERIVED owner id hits CannotRemoveOwner — a caller can no longer smuggle the real owner
        // id past the guard (the guard compares against the resolved owner, not a spoofable caller label).
        assert!(matches!(
            remove_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &me, &ReplicaId::new(b"r")),
            Err(VaultError::CannotRemoveOwner)
        ));
        assert!(matches!(
            remove_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &MemberId::new("nobody"), &ReplicaId::new(b"r")),
            Err(VaultError::MemberNotFound)
        ));
    }

    #[test]
    fn recover_preserves_a_co_owner_signer_and_their_access() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, code) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let added = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();
        let promoted = add_co_owner(&added.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &co_id).unwrap();
        let pinned = founder_key(&owner.keyring);
        let ks_bytes = ks.to_bytes().unwrap();

        let rec = recover(&promoted.keyring, &ks_bytes, &code, &Passphrase::new(b"new pass"), &TreeId::new(TREE), &ReplicaId::new(b"r-o2"), &no_watermark()).unwrap();
        let k = Keyring::decode(rec.keyring.as_slice()).unwrap();
        assert!(k.members.iter().any(|m| m.member_id == co_id.as_str() && m.role == MemberRole::CoOwner as i32 && m.author_public_key == co.author_public_key));
        assert!(unlock_as_member(&rec.keyring, &MemberAuth { passphrase: &Passphrase::new(b"co pass"), kdf: &co.kdf_params, member_id: &co_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-co"), 0).is_ok());
    }

    #[test]
    fn change_passphrase_leaves_the_tree_and_its_members_untouched() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-o")).unwrap();
        let co = provision_member(&Passphrase::new(b"co pass")).unwrap();
        let co_id = jid(&co.author_public_key);
        let added = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 0, &Joiner::from_bytes(&co_id, MemberRole::Editor, &co.author_public_key, &co.hpke_public_key).unwrap()).unwrap();
        let pinned = founder_key(&owner.keyring);
        let ks_bytes = ks.to_bytes().unwrap();

        let re = change_passphrase(&added.keyring, &ks_bytes, &Passphrase::new(b"owner pass"), &Passphrase::new(b"new pass"), &TreeId::new(TREE), &me, 0).unwrap();
        assert_eq!(re.keyring, added.keyring);
        assert!(unlock_as_member(&re.keyring, &MemberAuth { passphrase: &Passphrase::new(b"co pass"), kdf: &co.kdf_params, member_id: &co_id, trusted_signers: &[pinned] }, &TreeId::new(TREE), &ReplicaId::new(b"r-co"), 0).is_ok());
    }

    #[test]
    fn first_shared_revision_is_set_once_carried_forward_and_never_cleared() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();
        assert_eq!(first_shared(&owner.keyring), 0);

        let m2 = provision_member(&Passphrase::new(b"m2 pass")).unwrap();
        let m2_id = jid(&m2.author_public_key);
        let add1 = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 1, &Joiner::from_bytes(&m2_id, MemberRole::Editor, &m2.author_public_key, &m2.hpke_public_key).unwrap()).unwrap();
        assert_eq!(add1.revision, 2);
        assert_eq!(first_shared(&add1.keyring), 2);

        let m3 = provision_member(&Passphrase::new(b"m3 pass")).unwrap();
        let m3_id = jid(&m3.author_public_key);
        let add2 = add_member(&add1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 2, &Joiner::from_bytes(&m3_id, MemberRole::Editor, &m3.author_public_key, &m3.hpke_public_key).unwrap()).unwrap();
        assert_eq!(first_shared(&add2.keyring), 2);

        let rem1 = remove_member(&add2.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 3, &m3_id, &ReplicaId::new(b"r-owner")).unwrap();
        assert_eq!(first_shared(&rem1.keyring), 2);
        let rem2 = remove_member(&rem1.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 4, &m2_id, &ReplicaId::new(b"r-owner")).unwrap();
        let k = Keyring::decode(rem2.keyring.as_slice()).unwrap();
        assert_eq!(k.members.len(), 1);
        assert_eq!(k.first_shared_revision, 2);
    }

    #[test]
    fn writer_signs_iff_the_tree_has_been_shared() {
        use openom_protocol::v1::Envelope;
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let me = owner_id(&ks, &owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &me, &ReplicaId::new(b"r-owner")).unwrap();

        let u_solo = unlock(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), &ReplicaId::new(b"r-b")).unwrap();
        let solo = Envelope::decode(seal_open(&u_solo.sealer, b"solo edit").as_slice()).unwrap().header.unwrap();
        assert!(solo.author_signature.is_empty(), "a never-shared tree writes unattributed");

        let m = provision_member(&Passphrase::new(b"m pass")).unwrap();
        let mid = jid(&m.author_public_key);
        let add = add_member(&owner.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), 1, &Joiner::from_bytes(&mid, MemberRole::Editor, &m.author_public_key, &m.hpke_public_key).unwrap()).unwrap();

        let u_owner = unlock(&add.keyring, &acct(&ks, &owner_pass), &TreeId::new(TREE), &ReplicaId::new(b"r-c")).unwrap();
        let owner_h = Envelope::decode(seal_open(&u_owner.sealer, b"owner edit").as_slice()).unwrap().header.unwrap();
        assert!(!owner_h.author_signature.is_empty(), "shared tree: owner signs");
        assert_eq!(owner_h.author_member_id, me.as_str());

        let founder = founder_key(&add.keyring);
        let (u_member, _) = unlock_as_member(&add.keyring, &MemberAuth { passphrase: &Passphrase::new(b"m pass"), kdf: &m.kdf_params, member_id: &mid, trusted_signers: &[founder] }, &TreeId::new(TREE), &ReplicaId::new(b"r-m"), 0).unwrap();
        let member_h = Envelope::decode(seal_open(&u_member.sealer, b"member edit").as_slice()).unwrap().header.unwrap();
        assert!(!member_h.author_signature.is_empty(), "shared tree: member signs");
        assert_eq!(member_h.author_member_id, mid.as_str());
    }

    #[test]
    fn first_shared_revision_is_covered_by_the_signature() {
        let owner_pass = Passphrase::new(b"owner pass");
        let (ks, _c) = make_owner(&owner_pass);
        let owner = provision(&acct(&ks, &owner_pass), &TreeId::new(TREE), &MemberId::new(MEMBER), &ReplicaId::new(b"r-owner")).unwrap();
        let founder = founder_key(&owner.keyring);
        let mut k = Keyring::decode(owner.keyring.as_slice()).unwrap();
        verify_keyring(&k, &founder).unwrap();
        k.first_shared_revision = 7;
        assert!(verify_keyring(&k, &founder).is_err());
    }
}
