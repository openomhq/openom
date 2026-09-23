//! The engine-agnostic client keyring **lifecycle**.
//!
//! the shared menu the two lockstep host consumers
//! (the web-worker RPC in the `wasm` module and the Tauri invoke host in `openom-vault-host`) dispatch over
//! once, instead of hand-wiring 2 engines × 2 hosts.
//!
//! This is OPE-277 piece #1 of the swap seam
//! (plan/keyring-dag/design.swap-seam-decision.md).
//!
//! **Anchor-in / anchor-out + watermark, all engine-OPAQUE bytes.** A tree's trust state is an opaque
//! `anchor` (the chain's is its signed `Keyring`; a future dag anchor is its op closure) and its
//! anti-rollback cursor is an opaque `watermark`. Guardrail #1 of the gate: the anti-rollback floor lives
//! INSIDE these opaque bytes, never as a shared scalar — a `u32 revision` would be security-critical for
//! the chain and meaningless for the dag (structurally monotonic), the textbook model leak. So the seam
//! carries the floor in and the cursor out as bytes; only the concrete engine reads them.
//!
//! **Shared menu only.** Engine-SPECIFIC behaviour stays as inherent methods on the concrete engine types
//! — never forced through this trait. That deliberately includes **membership authoring** (add/remove
//! member, promote/demote) and **endorsement**: the chain authors through two authority models
//! (owner-via-RRK vs co-owner-via-member-wrap + a pinned trusted-signer set) and its endorse
//! (`blob_sync::countersign`) is a Blob CAS I/O loop — neither fits a pure, non-leaky shared signature, and
//! the gate's own guardrail #4 keeps sync engine-owned. The hosts reach authoring behind the engine enum's
//! own arms; "author/endorse in the menu" is honoured as a capability at the single dispatch site, not as
//! a trait method. (Gate amendment, recorded in the decision doc; revisit promoting `author` alone once
//! the dag lifecycle — OPE-273 — exists and its authoring model is concrete.)
//!
//! **Why this lives in openom-vault, not the seam crate.** Every result carries a [`SealerSet`] plus
//! `RecoveryCode` / `DidKey` (client secret-handling types). The keyless `openom-keyring-api` is the
//! *server's* binding surface (roles only today) — putting these there would poison it with client crypto
//! deps. So the trait's home is openom-vault: above both keyring engines and above the lean DEK-session
//! sealer, which it uses only for [`SealerSet`] (OPE-279 extraction).

use did::DidKey;
use openom_crypto::{Passphrase, RecoveryCode};
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};

use crate::account_keystore::UnlockedAccount;
use crate::vault;
use crate::VaultError;
use openom_sealer::SealerSet;

/// The tree + member context every lifecycle call needs: which tree is being operated on and who is
/// acting.
///
/// These come from the caller's OWN expectation (the tree the app opened), NEVER the parsed,
/// untrusted keyring — the trusted-context invariant the vault's "the AEAD binds `tree_id`" security rests
/// on (see [`crate::vault`]).
pub struct VaultContext<'a> {
    pub tree_id: &'a TreeId,
    pub member_id: &'a MemberId,
    pub replica_id: &'a ReplicaId,
}

/// Result of [`KeyringLifecycle::provision`]: the initial trust `anchor` to publish + persist, the
/// one-time recovery code to show ONCE, the ready sealer, and the owner's stable `did:key`.
pub struct Provisioned {
    /// The engine-opaque trust state to publish (chain: the signed genesis keyring).
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    pub sealer: SealerSet,
    pub did_key: DidKey,
    /// The genesis anti-rollback cursor to persist — engine-opaque, like [`Unlocked::watermark`] (chain:
    /// the genesis revision as bytes; dag: the genesis frontier). Without this the caller would have to
    /// invent a starting floor, and a scalar guess (`1`) is only right for the chain by construction.
    pub watermark: Vec<u8>,
}

/// Result of [`KeyringLifecycle::unlock`]: the sealer plus the opaque anti-rollback `watermark` the caller
/// must persist (never interpret).
// The four advisory flags are INDEPENDENT repair signals a caller acts on separately (reseal / member
// backfill / rrk backfill / forced reseal), not a state machine — a bitflags/enum would obscure that each
// is its own out-of-band remedy, so keep them as named bools.
#[allow(clippy::struct_excessive_bools)]
pub struct Unlocked {
    pub sealer: SealerSet,
    /// The engine-opaque anti-rollback cursor to persist (chain: the keyring revision, as bytes).
    pub watermark: Vec<u8>,
    pub did_key: DidKey,
    /// Advisory: the current write epoch's wraps don't match the resolved membership, so a concurrent
    /// membership merge left it stale and a reseal is due (dag only — the chain, being linear, is always
    /// `false`). Never blocks unlock; the client repairs it out-of-band (OPE-282).
    pub needs_reseal: bool,
    /// Advisory: some RETAINED epoch lacks a wrap for a resolved member, so a concurrently-added member can't
    /// read that slice of history until the owner backfills it (dag only; chain is always `false`). Never
    /// blocks unlock; the OWNER repairs it out-of-band (only the RRK opens the old DEKs) (OPE-288).
    pub needs_backfill: bool,
    /// Advisory: some RETAINED epoch's RRK wrap doesn't bind the CURRENT recovery escrow — a rotation orphan
    /// (an epoch minted concurrently with a recovery rotation, which the rotation never re-wrapped), so the
    /// owner can't read it until a MEMBER re-wraps its DEK to the current escrow
    /// ([`crate::dag_vault::DagVault::backfill_rrk`]). The inverse of `needs_backfill` — an owner-read gap a
    /// member heals, not a member gap the owner heals (dag only; chain is always `false`) (OPE-381 / F3).
    pub needs_rrk_backfill: bool,
    /// Advisory: this unlocker's own DEK bag did NOT reach the current write epoch — locally derived, so it
    /// holds regardless of what the (unauthenticated) coverage hint claims. `needs_reseal` is computed from
    /// the author-DECLARED recipient key, so a malicious op that wraps the DEK to garbage while declaring the
    /// victim's real key reports "clean" and suppresses the automatic repair; this signal is immune to that.
    /// The caller responds by forcing a reseal ([`crate::dag_vault::ResealTrigger::Force`]) past the
    /// `needs_reseal` gate (dag only; chain is always `false` — a linear chain always reaches its write
    /// epoch) (OPE-299).
    pub write_epoch_unreachable: bool,
}

/// Result of [`KeyringLifecycle::recover`]: the `anchor` + recovery code (both to publish/show), the sealer,
/// the watermark, and the owner's `did:key`, plus the NEW account keystore blob.
///
/// **Engine split (OPE-543 2b).** The chain still mints a FRESH owner identity + a new keyring anchor + a
/// rotated recovery code (op-based), and passes the keystore through unchanged (empty). The dag is
/// account-keystore-mediated (durable identity): recovery restores the SAME account identity, so `did_key` is
/// UNCHANGED and the tree `anchor` is UNCHANGED — the only new durable output is `keystore`, the account blob
/// re-wrapped under the new passphrase (the per-tree `recovery_code` is empty; the account's recovery code did
/// not change).
pub struct Recovered {
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    /// The account keystore blob to persist (OPE-542/543). NON-EMPTY for the dag (durable identity: the account
    /// re-wrapped under the new passphrase); EMPTY for the chain (per-tree credential model, no account keystore).
    pub keystore: Vec<u8>,
    pub sealer: SealerSet,
    pub watermark: Vec<u8>,
    pub did_key: DidKey,
    /// See [`Unlocked::needs_reseal`] — recovery also returns a live sealer, so it carries the same signal.
    pub needs_reseal: bool,
    /// See [`Unlocked::needs_backfill`] — recovery returns a live owner sealer, so it carries this too.
    pub needs_backfill: bool,
}

/// Result of [`KeyringLifecycle::change_passphrase`]: the `anchor` + recovery code + watermark, plus the NEW
/// account keystore blob. The DEKs are unchanged, so any running sealer keeps working — no re-seal.
///
/// **Engine split (OPE-543 2b).** The chain re-wraps the keyring under a new KEK and rotates the recovery code
/// (op-based), passing the keystore through unchanged (empty). The dag is account-keystore-mediated: the change
/// is an `AccountKeystore::change_passphrase` re-wrap of the account blob — the tree `anchor` and `watermark`
/// are UNCHANGED and the per-tree `recovery_code` is empty (the account's recovery code is not rotated by a
/// passphrase change); the only new durable output is `keystore`.
pub struct Rekeyed {
    pub anchor: Vec<u8>,
    pub recovery_code: RecoveryCode,
    /// The account keystore blob to persist (OPE-542/543). NON-EMPTY for the dag (account re-wrapped under the
    /// new passphrase); EMPTY for the chain (no account keystore).
    pub keystore: Vec<u8>,
    pub watermark: Vec<u8>,
}

/// The client keyring lifecycle — the shared menu (see the module docs). `anchor` and `floor` are
/// engine-opaque bytes; results carry the new anchor to publish plus the opaque watermark to persist.
pub trait KeyringLifecycle {
    /// Create a brand-new encrypted tree under the caller's already-unlocked durable account identity.
    ///
    /// # Errors
    /// Returns [`VaultError`] if provisioning fails.
    fn provision(
        &self,
        ctx: &VaultContext,
        account: &UnlockedAccount,
    ) -> Result<Provisioned, VaultError>;

    /// Re-open an existing tree from its trusted `anchor` using the already-unlocked durable account.
    ///
    /// # Errors
    /// Returns [`VaultError`] if unlock fails (wrong passphrase / account, or a malformed/stale keyring).
    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
    ) -> Result<Unlocked, VaultError>;

    /// Recover with the recovery code, re-establishing owner access under `new_passphrase`, preserving
    /// members + epochs. `keystore` is the caller's persisted ACCOUNT keystore blob (OPE-542/543): the dag
    /// (durable-identity) engine REQUIRES it and recovers the account from it (restoring the SAME identity,
    /// re-wrapping under `new_passphrase`); the chain ignores it (op-based recovery mints a fresh identity),
    /// so the caller may pass an empty slice. `floor` is the caller's opaque anti-rollback watermark (the
    /// served anchor is untrusted on recovery — see [`crate::vault::recover`]).
    ///
    /// # Errors
    /// Returns [`VaultError`] if recovery fails (wrong code, or a malformed/stale keyring).
    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, VaultError>;

    /// Change the passphrase. The DEKs (and any running sealer) are unchanged, so the tree is not re-sealed.
    /// `keystore` is the caller's persisted ACCOUNT keystore blob (OPE-542/543): the dag engine re-wraps THAT
    /// blob under the new passphrase (no on-tree op — the durable identity is unchanged) and returns the new
    /// blob; the chain ignores it (op-based re-key of the keyring anchor), so the caller may pass an empty
    /// slice. `floor` is the opaque anti-rollback watermark.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the change fails (wrong current passphrase, or a malformed keyring).
    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, VaultError>;
}

/// The linear-chain engine's lifecycle — openom's shipping keyring.
///
/// Its anchor is the signed `Keyring`
/// bytes and its watermark is the keyring revision; each flow re-signs a new revision. Zero-sized: the
/// [`crate::vault`] flows are stateless free functions, so the engine choice is carried by the type, not
/// by held state. (The dag lifecycle impl is OPE-273.)
pub struct ChainVault;

/// The write-epoch `key_id` length (matches `vault::KEY_ID_LEN`) and the `H(DEK)` (SHA-256) length that make
/// up the chain watermark's epoch-pin (OPE-286).
const KEY_ID_LEN: usize = 16;
const DEK_HASH_LEN: usize = 32;

impl ChainVault {
    /// Encode the chain's opaque anti-rollback watermark: the keyring `revision` (4 BE bytes), then the write
    /// epoch's `key_id` (16 bytes) and `H(DEK)` (32 bytes). The epoch commitment authenticates key MATERIAL,
    /// so a later `recover` (which skips signature verification) can't be handed a forged epoch wearing a
    /// copied `key_id` (OPE-286). A revision-only (4-byte) form means "no epoch pin" (a bootstrap/stateless
    /// or pre-pin watermark).
    fn watermark(revision: u32, write_key_id: &[u8], write_dek_hash: &[u8]) -> Vec<u8> {
        let mut w = revision.to_be_bytes().to_vec();
        if write_key_id.len() == KEY_ID_LEN && write_dek_hash.len() == DEK_HASH_LEN {
            w.extend_from_slice(write_key_id);
            w.extend_from_slice(write_dek_hash);
        }
        w
    }

    /// Decode an opaque `floor` to `(min_revision, expected_write_key_id, expected_dek_hash)`. Empty ⇒ no
    /// floor. 4 bytes ⇒ revision only (no epoch pin). The full `4 + KEY_ID_LEN + DEK_HASH_LEN` (52) form
    /// carries the pin. Any other length is a corrupt watermark and is refused
    /// ([`VaultError::MalformedWatermark`]) — never silently dropped, which would drop protection.
    fn floor(bytes: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>), VaultError> {
        if bytes.is_empty() {
            return Ok((0, Vec::new(), Vec::new()));
        }
        if bytes.len() == 4 {
            let b: [u8; 4] = bytes[..4].try_into().expect("len checked");
            return Ok((u32::from_be_bytes(b), Vec::new(), Vec::new()));
        }
        if bytes.len() == 4 + KEY_ID_LEN + DEK_HASH_LEN {
            let rev = u32::from_be_bytes(bytes[..4].try_into().expect("len checked"));
            return Ok((
                rev,
                bytes[4..4 + KEY_ID_LEN].to_vec(),
                bytes[4 + KEY_ID_LEN..].to_vec(),
            ));
        }
        Err(VaultError::MalformedWatermark)
    }
}

impl KeyringLifecycle for ChainVault {
    fn provision(
        &self,
        ctx: &VaultContext,
        account: &UnlockedAccount,
    ) -> Result<Provisioned, VaultError> {
        let p = vault::provision(account, ctx.tree_id, ctx.member_id, ctx.replica_id)?;
        Ok(Provisioned {
            anchor: p.keyring,
            recovery_code: p.recovery_code,
            sealer: p.sealer,
            did_key: p.did_key,
            watermark: Self::watermark(p.revision, &p.write_key_id, &p.write_dek_hash),
        })
    }

    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
    ) -> Result<Unlocked, VaultError> {
        let u = vault::unlock(anchor, account, ctx.tree_id, ctx.replica_id)?;
        Ok(Unlocked {
            sealer: u.sealer,
            watermark: Self::watermark(u.revision, &u.write_key_id, &u.write_dek_hash),
            did_key: u.did_key,
            needs_reseal: false, // a linear chain has no concurrent-merge stale epoch
            needs_backfill: false, // nor a concurrent-add historical-read gap (OPE-288)
            needs_rrk_backfill: false, // nor a concurrent-rotation orphan (OPE-381) — rotation is total on the chain
            write_epoch_unreachable: false, // a linear chain always reaches its own write epoch (OPE-299)
        })
    }

    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, VaultError> {
        // OPE-543 durable identity: chain recovery is ACCOUNT-keystore-mediated (symmetric with the dag) —
        // it restores the SAME account identity (no on-tree op, no new revision), so `did_key` is unchanged
        // and the anchor is returned verbatim. Only the epoch pin is needed from the floor; the served head
        // is signature-verified by the restored identity inside `vault::recover`.
        let (min_rev, _key_id, _dek_hash) = Self::floor(floor)?;
        let r = vault::recover(
            anchor,
            keystore,
            recovery_code,
            new_passphrase,
            ctx.tree_id,
            ctx.replica_id,
            &vault::RecoverWatermark {
                min_revision: min_rev,
                write_key_id: &[],
                dek_hash: &[],
            },
        )?;
        Ok(Recovered {
            anchor: r.keyring,
            recovery_code: r.recovery_code,
            keystore: r.keystore,
            sealer: r.sealer,
            // The anchor is unchanged; re-pin the (unchanged) write epoch from the freshly-opened sealer.
            watermark: Self::watermark(r.revision, &r.write_key_id, &r.write_dek_hash),
            did_key: r.did_key,
            needs_reseal: false,
            needs_backfill: false,
        })
    }

    fn change_passphrase(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, VaultError> {
        // OPE-543 durable identity: chain passphrase-change is ACCOUNT-keystore-mediated — no on-tree op, so
        // the anchor and its anti-rollback watermark are UNCHANGED. The floor is carried forward verbatim as
        // the new watermark (a credential change does not advance the tree cursor).
        let (min_rev, _, _) = Self::floor(floor)?;
        let re = vault::change_passphrase(
            anchor,
            keystore,
            old_passphrase,
            new_passphrase,
            ctx.tree_id,
            ctx.member_id,
            min_rev,
        )?;
        Ok(Rekeyed {
            anchor: re.keyring,
            recovery_code: re.recovery_code,
            keystore: re.keystore,
            watermark: floor.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &[u8] = b"tree-uuid-16byte";

    fn ctx<'a>(tree: &'a TreeId, member: &'a MemberId, replica: &'a ReplicaId) -> VaultContext<'a> {
        VaultContext {
            tree_id: tree,
            member_id: member,
            replica_id: replica,
        }
    }

    /// A non-empty floor that isn't a 4-byte revision is refused, not silently treated as "no floor" —
    /// dropping a corrupt local cursor would drop rollback protection.
    #[test]
    fn a_malformed_floor_is_refused_not_dropped() {
        assert_eq!(
            ChainVault::floor(&[]).unwrap().0,
            0,
            "empty floor = no floor"
        );
        assert_eq!(ChainVault::floor(&7u32.to_be_bytes()).unwrap().0, 7);
        assert!(matches!(
            ChainVault::floor(&[1, 2, 3]),
            Err(VaultError::MalformedWatermark)
        ));
    }

    /// Regression (OPE-543): the chain OWNER path resolves its on-tree id from the VERIFIED account, NEVER the
    /// caller's `ctx.member_id` label. Provision under the real derived id, then unlock with a DELIBERATELY WRONG
    /// label — it must still open under the same identity (the label is advisory now). Pre-fix, the owner-path
    /// DEK unwrap keyed on the caller label, so a mismatched label produced
    /// `BadKeyring("write epoch not in the reachable set")` on reopen; this guards that regression.
    #[test]
    fn chain_owner_unlock_ignores_a_wrong_caller_member_label() {
        use crate::AccountKeystore;
        let tree = TreeId::new(TREE);
        let pass = Passphrase::new(b"correct horse");
        let (ks, _code, _u) = AccountKeystore::create(pass.expose()).unwrap();
        let real = MemberId::new(ks.unlock(pass.expose()).unwrap().member_id);
        let bogus = MemberId::new("acct-owner-not-self-certifying".to_string());
        assert_ne!(
            real.as_str(),
            bogus.as_str(),
            "the two ids must differ for the test to mean anything"
        );

        let p = ChainVault
            .provision(
                &ctx(&tree, &real, &ReplicaId::new(b"rA")),
                &ks.unlock(pass.expose()).unwrap(),
            )
            .unwrap();
        // Unlock passing the BOGUS label — the owner is resolved from the account, so it opens regardless.
        let u = ChainVault
            .unlock(
                &ctx(&tree, &bogus, &ReplicaId::new(b"rB")),
                &p.anchor,
                &ks.unlock(pass.expose()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            u.did_key, p.did_key,
            "resolved from the account identity, not the caller's label"
        );
    }

    /// The whole `KeyringLifecycle` contract, engine-agnostic (OPE-543 durable identity — BOTH engines are
    /// account-keystore-mediated): provision from the durable account then seal; unlock (from the opaque
    /// anchor plus the account) opens it; a credential change is a NO-OP on the tree (the watermark does NOT
    /// advance) that re-wraps the account keystore; unlock-under-the-new-passphrase (via the re-wrapped
    /// keystore) opens it; recover (with the ACCOUNT recovery code) restores the SAME identity and opens it.
    /// All over opaque anchors, watermarks and floors, so the body is identical for both engines.
    #[allow(clippy::too_many_lines)] // the full four-flow contract, exercised end-to-end in one body
    fn lifecycle_contract<E: KeyringLifecycle>(engine: &E) {
        use crate::AccountKeystore;
        let tree = TreeId::new(TREE);
        let pass = Passphrase::new(b"correct horse");
        // The durable ACCOUNT is the owner on BOTH engines (OPE-542/543). One keystore is the tree's single
        // owner across every lifecycle call; tree sessions borrow it and derive their own owned signing keys.
        let (ks, code, _u) = AccountKeystore::create(pass.expose()).unwrap();
        let ks_bytes = ks.to_bytes().unwrap();
        // OPE-543: the owner's on-tree id is SELF-CERTIFYING — the durable account's `member_id`
        // (`derive_member_id(account key)`), NOT the caller's label. Both engines record and resolve the owner
        // by this id, so the owner-path DEK lookups (chain) must be keyed by it.
        let member = MemberId::new(ks.unlock(pass.expose()).unwrap().member_id);

        let p = engine
            .provision(
                &ctx(&tree, &member, &ReplicaId::new(b"rA")),
                &ks.unlock(pass.expose()).unwrap(),
            )
            .unwrap();
        assert!(
            !p.watermark.is_empty(),
            "provision reports a genesis watermark, not a stub"
        );
        let sealed = p
            .sealer
            .seal_entry(
                &openom_sealer::SealContext::snapshot(0, Vec::new(), 0),
                b"parity data",
            )
            .unwrap()
            .envelope;

        // unlock from the anchor + the durable account opens the data, same owner identity.
        let u = engine
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"rB")),
                &p.anchor,
                &ks.unlock(pass.expose()).unwrap(),
            )
            .unwrap();
        assert_eq!(u.did_key, p.did_key);
        assert!(
            !u.watermark.is_empty(),
            "unlock reports an anti-rollback watermark, not a stub"
        );
        assert_eq!(
            u.sealer
                .open_entry(openom_sealer::EntryKind::Snapshot, &sealed)
                .unwrap(),
            b"parity data"
        );

        // change_passphrase — account-keystore-mediated — is a NO-OP on the tree: the watermark does NOT
        // advance, and the re-wrapped account keystore blob is returned.
        let new_pass = Passphrase::new(b"changed passphrase");
        let re = engine
            .change_passphrase(
                &ctx(&tree, &member, &ReplicaId::new(b"rA")),
                &p.anchor,
                &ks_bytes,
                &pass,
                &new_pass,
                &u.watermark,
            )
            .unwrap();
        assert_eq!(
            re.watermark, u.watermark,
            "a credential change is a no-op that does NOT advance the tree watermark"
        );
        assert!(
            !re.keystore.is_empty(),
            "the re-wrapped account keystore is returned"
        );

        // unlock under the new passphrase, via the re-wrapped keystore, opens the same data.
        let re_ks = AccountKeystore::from_bytes(&re.keystore).unwrap();
        let u2 = engine
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"rC")),
                &re.anchor,
                &re_ks.unlock(new_pass.expose()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            u2.sealer
                .open_entry(openom_sealer::EntryKind::Snapshot, &sealed)
                .unwrap(),
            b"parity data"
        );

        // recover (with the ACCOUNT recovery code, a fresh passphrase) restores the SAME identity and opens
        // the same data. The served anchor is the original, so its own frontier (`u.watermark`) is a
        // satisfiable floor; recovery does not advance it (no on-tree op).
        let r = engine
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"rD")),
                &p.anchor,
                &ks_bytes,
                &code,
                &Passphrase::new(b"recovered passphrase"),
                &u.watermark,
            )
            .unwrap();
        assert!(!r.watermark.is_empty(), "recovery reports a watermark");
        assert_eq!(
            r.did_key, p.did_key,
            "recovery restores the SAME durable identity"
        );
        assert!(
            !r.keystore.is_empty(),
            "recovery returns the re-wrapped account keystore"
        );
        assert_eq!(
            r.sealer
                .open_entry(openom_sealer::EntryKind::Snapshot, &sealed)
                .unwrap(),
            b"parity data"
        );
    }

    /// Parity: the chain and dag engines satisfy the SAME lifecycle contract behaviorally — OPE-267's
    /// parity matrix carried through the real vaults, behind the trait, now BOTH under durable identity.
    #[test]
    fn chain_and_dag_satisfy_the_same_lifecycle_contract() {
        lifecycle_contract(&ChainVault);
        lifecycle_contract(&crate::DagVault);
        // ...and the same contract holds through the AppVault enum for BOTH engines — the single dispatch
        // point (OPE-278) delegates identically, so the hosts can drive one type (OPE-276's "write once").
        lifecycle_contract(&crate::AppVault::Chain(ChainVault));
        lifecycle_contract(&crate::AppVault::Dag(crate::DagVault));
    }

    fn reusable_account_contract<E: KeyringLifecycle>(engine: &E) {
        use crate::AccountKeystore;

        let passphrase = Passphrase::new(b"one profile passphrase");
        let (_keystore, _recovery_code, account) =
            AccountKeystore::create(passphrase.expose()).unwrap();
        let member = MemberId::new(account.member_id.clone());
        let first_tree = TreeId::new(b"first-tree-id-01");
        let second_tree = TreeId::new(b"second-tree-id02");

        let first = engine
            .provision(
                &ctx(&first_tree, &member, &ReplicaId::new(b"first-create")),
                &account,
            )
            .unwrap();
        let second = engine
            .provision(
                &ctx(&second_tree, &member, &ReplicaId::new(b"second-create")),
                &account,
            )
            .unwrap();

        assert_eq!(
            first.did_key, second.did_key,
            "one profile account owns both trees"
        );
        let first_open = engine
            .unlock(
                &ctx(&first_tree, &member, &ReplicaId::new(b"first-open")),
                &first.anchor,
                &account,
            )
            .unwrap();
        let second_open = engine
            .unlock(
                &ctx(&second_tree, &member, &ReplicaId::new(b"second-open")),
                &second.anchor,
                &account,
            )
            .unwrap();
        assert_eq!(first_open.did_key, second_open.did_key);
    }

    #[test]
    fn one_unlocked_account_is_reusable_across_trees() {
        reusable_account_contract(&ChainVault);
        reusable_account_contract(&crate::DagVault);
    }
}
