//! The DAG keyring's vault (OPE-273).
//!
//! the dag-engine counterpart to [`crate::vault`], producing the same
//! [`openom_sealer::SealerSet`] through the shared sealing core (`vault_core`) while resolving membership +
//! recovery authority through the DAG keyring's client facade (`openom_keyring_dag::client`).
//!
//!
//! The trust anchor is engine-opaque bytes: the dag's pinned genesis config + op closure, with the DEK
//! epochs + recovery escrow riding the ops' `sealing` payloads (the design pass converged on this — one
//! signed channel, folded alongside membership). The membership + op-graph engine lives behind the
//! `dag_client` facade; the DEK epochs/wraps persisted in those payloads ARE keyeo's native key-material
//! types (`Epoch`/`Wrap`/`RecipientDescriptor`), the shared layer the sealing core is lifted onto (OPE-376).
//!
//! STATUS: all four [`KeyringLifecycle`] flows are built — provision, unlock, recover (RVK-authorized
//! `ReFound`), `change_passphrase` (current-key Retarget) — with membership authoring (add/remove with
//! member-unlock), the effective-op sealing fold (reset-merge carve-out / quorum-Commit), and the
//! anti-rollback watermark (the anchor's frontier op-id set; enforced as a floor on recover +
//! `change_passphrase`). `DagVault` is interchangeable with `ChainVault` behind the trait.

// Recovery key material uses intentionally-close domain abbreviations (rrk / rvk / rk, old_/new_) that
// clippy reads as typos; renaming would lose precision, so `similar_names` is off for this module.
#![allow(clippy::similar_names)]

use did::DidKey;
use openom_crypto::{
    derive_root, generate_dek, generate_salt, CryptoError, Passphrase, RecoveryCode, RootKeys,
};
use openom_keyring_api::derive_member_id;
use openom_keyring_dag::{client as dag_client, KeyringRole};
use serde::{Deserialize, Serialize};

use crate::account_keystore::{AccountKeystore, UnlockedAccount};
use crate::lifecycle::{KeyringLifecycle, Provisioned, Recovered, Rekeyed, Unlocked, VaultContext};
// OPE-543 2b: the escrow/RRK helpers (`build_recovery_escrow`/`open_rrk_secret`/`escrow_kek_wrap`/
// `rrk_wrap_keyeo`/`owner_secrets_reusing_pass_kdf`/`derive_rvk`/…) are no longer used by any dag flow — the
// dag credential flows are account-keystore-mediated. Those helpers stay in `vault_core` for the CHAIN vault
// (rewired in 2c). `RecoveryEscrow` is still referenced by the residual `SealingPayload`/`FoldState` escrow
// plumbing (checkpoint fidelity + fold fixtures only).
use crate::vault_core::{
    member_epoch_deks, member_wrap_keyeo, sealer_set_from_deks, validate_kdf,
    write_epoch_by_ordinal, RecoveryEscrow,
};
// The dag persists keyeo's native key-material: an epoch's DEK wraps ARE keyeo `Epoch`/`Wrap`, and coverage
// is keyeo's `covers_exact` / `missing` over `RecipientDescriptor`s (the shared key-material layer the
// sealing core is lifted onto, not the dag engine's op types behind the `dag_client` facade).
use crate::VaultError;
use keyeo_crypto::{
    KdfParams as KeyeoKdfParams, KeyId as KeyeoKeyId, RecipientDescriptor,
    WrapMethod as KeyeoWrapMethod, X25519PublicKey,
};
use openom_keyring_api::MembershipView;

/// The opaque **delta** an op carries in its `sealing` field. The vault folds these (in effective-op
/// order) into the current sealing state: `new_epochs` are inserted (genesis's epoch-0; a member removal's
/// forward-secret epoch) and `added_wraps` are appended to existing epochs (an add-member's per-epoch wraps
/// for the joiner). Deltas — not snapshots — so it stays CRDT-clean (concurrent additions both survive) and
/// compact. (JSON today, matching the dag op codec; a compact/binary form is a later perf task.)
///
/// OPE-543 (owner-as-member): the owner is an ordinary member whose epoch access rides a `MemberHpke` wrap to
/// their account HPKE key — there is no per-tree recovery root (RRK) escrow. The owner's identity is the durable
/// ACCOUNT identity (OPE-542 keystore), passed IN to `provision`/`unlock` and the owner-authored ops, so the
/// sealing no longer carries an owner passphrase KDF (the transitional `owner_kdf` field is gone). `escrow` is
/// retained ONLY so the not-yet-rewired credential-change flows (`recover`/`change_passphrase`/`rotate_recovery`)
/// still compile; the owner-as-member flows always set it `None` (finalize no longer requires it).
#[derive(Serialize, Deserialize)]
pub(crate) struct SealingPayload {
    new_epochs: Vec<keyeo_crypto::Epoch<String>>,
    added_wraps: Vec<AddedWrap>,
    escrow: Option<RecoveryEscrow>,
}

/// A wrap added to an EXISTING epoch (identified by `key_id`) — how an add-member gives the joiner access
/// to an epoch without minting a new one.
#[derive(Serialize, Deserialize)]
pub(crate) struct AddedWrap {
    key_id: Vec<u8>,
    wrap: keyeo_crypto::Wrap<String>,
}

impl SealingPayload {
    /// A payload that only sets/re-sets the escrow (used by the not-yet-rewired `recover` /
    /// `change_passphrase` re-escrow with no epoch change; retained for compilation).
    const fn escrow_only(escrow: RecoveryEscrow) -> Self {
        Self {
            new_epochs: vec![],
            added_wraps: vec![],
            escrow: Some(escrow),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SealingPayload serialization is infallible")
    }
}

/// The PRE-retain intermediate of the sealing fold: the tagged epochs (`added_wraps` already merged) BEFORE the
/// OPE-289 ordinal bound, the recovery escrow, and the effective minting-op count. Split out (OPE-348 step 2a)
/// so a checkpoint can capture the pre-retain state and a resolve-from-checkpoint can resume the fold from a
/// seeded baseline. The bound is deliberately NOT applied here — it is time-varying (`minting_ops` can shrink
/// when a minting op is voided, then grow again), so an epoch dropped now may be resurrected later; freezing it
/// early would permanently lose an epoch a full-history replica keeps.
#[derive(Default)]
struct FoldState {
    tagged: Vec<(
        keyeo_crypto::Epoch<String>,
        dag_client::SealingOrigin,
        [u8; 32],
        String,
    )>,
    escrow: Option<RecoveryEscrow>,
    minting_ops: u64,
}

/// The most HPKE `added_wraps` ANY single author may pile onto ONE epoch for ONE recipient (OPE-381 / F3,
/// re-scoped for OPE-543 owner-as-member). An honest author adds exactly one wrap per (epoch, recipient) on a
/// backfill/add/rotation; the excess is a junk flood, dropped here so a hostile member can't inflate a
/// recipient's per-unlock HPKE work by piling wraps addressed to them (the `dek_commitment` check rejects a
/// junk DEK, but the recipient still does the HPKE trial-decrypt on each). Scoped PER RECIPIENT so a legit
/// multi-member backfill (one wrap each to many distinct members) is never capped, while a flood targeting a
/// single victim (e.g. the owner's own member wrap, the A3 lockout vector) is bounded to cap per epoch. The
/// epoch's OWN minted wraps (in `new_epochs`, not `added_wraps`) are never counted, so baseline access is
/// untouched.
const MAX_ADDED_WRAPS_PER_AUTHOR_PER_EPOCH_PER_RECIPIENT: usize = 8;

/// Fold a run of sealing entries into `state`. `count_minting` = whether these entries increment the minting-op
/// count: `true` for real ops; `false` for a checkpoint segment whose mints are already reflected in the seeded
/// baseline (so they are NOT double-counted).
fn fold_into(
    state: &mut FoldState,
    sealing: &[dag_client::SealingEntry],
    count_minting: bool,
) -> Result<(), VaultError> {
    use dag_client::SealingOrigin;
    use std::collections::HashMap;
    // Per-(epoch, author, recipient) tally of HPKE wraps added THIS fold, for the F3 flood bound. Fold-local:
    // a checkpoint's below-cut wraps are already merged (and were capped below the cut), so an author gets a
    // fresh budget above each compaction — still bounded, and compaction is owner-gated.
    let mut added_by: HashMap<(Vec<u8>, String, String), usize> = HashMap::new();
    for entry in sealing {
        let payload: SealingPayload = serde_json::from_slice(&entry.bytes)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        // Only Genesis/Remove/Reseal ops may MINT an epoch — a new_epoch from any Other op is anomalous (a
        // self-Retarget/self-Remove smuggling a self-only epoch) and is dropped. Counting OPS not epochs means
        // one op stuffing many epochs can't inflate the bound (OPE-289).
        let mints = matches!(
            entry.origin,
            SealingOrigin::Genesis | SealingOrigin::Remove | SealingOrigin::Reseal
        );
        if count_minting && mints {
            state.minting_ops = state.minting_ops.saturating_add(1);
        }
        for e in payload.new_epochs {
            if mints {
                state.tagged.push((e, entry.origin, entry.op_id, entry.author.clone()));
            }
        }
        // added_wraps attach a member's wrap to an EXISTING epoch (an add-member's joiner wraps ride an
        // Other-origin Add op — legitimate, unlike minting) — applied during the fold so coverage sees them.
        // HPKE added wraps (member OR recovery-root) are capped per (epoch, author, recipient) to bound a
        // junk-flood DoS (F3); Kek wraps aren't epoch wraps and never appear here.
        for aw in payload.added_wraps {
            if let Some((ep, _, _, _)) = state
                .tagged
                .iter_mut()
                .find(|(e, _, _, _)| e.key_id.as_bytes() == aw.key_id.as_slice())
            {
                if matches!(
                    aw.wrap.method,
                    keyeo_crypto::WrapMethod::RrkHpke { .. }
                        | keyeo_crypto::WrapMethod::MemberHpke { .. }
                ) {
                    let n = added_by
                        .entry((aw.key_id.clone(), entry.author.clone(), aw.wrap.recipient.clone()))
                        .or_insert(0);
                    if *n >= MAX_ADDED_WRAPS_PER_AUTHOR_PER_EPOCH_PER_RECIPIENT {
                        continue; // this author's flood bound for this (epoch, recipient) is reached
                    }
                    *n += 1;
                }
                ep.wraps.push(aw.wrap);
            }
        }
        if payload.escrow.is_some() {
            state.escrow = payload.escrow;
        }
    }
    Ok(())
}

/// Apply the OPE-289 ordinal bound + select the deterministic write epoch → `FoldedSealing`.
fn finalize_sealing(
    state: FoldState,
    members: &MembershipView,
) -> Result<FoldedSealing, VaultError> {
    use dag_client::SealingOrigin;
    // `escrow` is dropped here (`..`): OPE-543 2b credential flows are account-keystore-mediated and no longer
    // read a folded escrow. `FoldState.escrow` still exists for the checkpoint author's escrow-preservation and
    // the fold-logic fixtures, but the finalized `FoldedSealing` no longer carries it.
    let FoldState {
        mut tagged,
        minting_ops,
        ..
    } = state;

    // Sanitize epoch ordinals (OPE-289). A legitimately-minted ordinal is `max(existing)+1`, so after M
    // epoch-minting ops the greatest possible ordinal is M-1; drop any epoch whose ordinal is >= M. A
    // member-authored Remove/Reseal grinding a huge ordinal (e.g. u32::MAX) would otherwise (a) BRICK every
    // future `max()+1` re-epoch with RevisionOverflow, a permanent DoS, and (b) permanently win the
    // write-epoch race. The bound never drops an honest epoch (its ordinal is always < M) and caps a hostile
    // one at M-1, so `checked_add` can only overflow after ~4e9 real ops.
    tagged.retain(|(e, _, _, _)| e.ordinal < minting_ops);

    // OPE-543 owner-as-member: every resolved member — INCLUDING the owner — is a `MemberHpke` recipient,
    // key-bound to their CURRENT HPKE key. There is no separate recovery-root (RRK) coverage descriptor: the
    // owner reads via their own per-epoch member wrap like anyone else. Built once for the winner's coverage
    // + the backfill checks, via a LOCAL owner-inclusive predicate (keyeo's `covers_exact`/`missing` still
    // require an `rrk` descriptor, so they are not reused here).
    let required = member_descriptors(members);
    let owner_id = members.owner().map(|o| o.member_id.clone());

    // The write epoch is the deterministic winner among ELIGIBLE epochs — genesis/remove are always
    // eligible (the legitimate baseline), a reseal only if it COVERS the resolved membership, so a
    // self-only or wrong-set reseal can never win regardless of ordinal grinding. Among eligible, the
    // greatest (ordinal, op-id). `needs_reseal` = the winner's wrap set is stale vs the resolved membership.
    let mut winner: Option<(u64, [u8; 32], Vec<u8>, bool)> = None;
    for (ep, origin, op_id, _author) in &tagged {
        let covers = owner_inclusive_covers_exact(ep, &required);
        let eligible = match origin {
            SealingOrigin::Genesis | SealingOrigin::Remove => true,
            SealingOrigin::Reseal => covers,
            SealingOrigin::Other => false,
        };
        if eligible
            && winner
                .as_ref()
                .is_none_or(|(we, wid, _, _)| (ep.ordinal, *op_id) > (*we, *wid))
        {
            winner = Some((ep.ordinal, *op_id, ep.key_id.as_bytes().to_vec(), covers));
        }
    }
    let (_, _, write_key_id, winner_covers) = winner.ok_or(VaultError::MissingWrap)?;

    let epochs: Vec<keyeo_crypto::Epoch<String>> =
        tagged.into_iter().map(|(e, _, _, _)| e).collect();
    // needs_backfill: some retained epoch lacks a current-key wrap for a resolved NON-OWNER member — the
    // historical-read gap the OWNER heals (they can open every epoch they reach and add the missing wrap).
    let needs_backfill = epochs.iter().any(|ep| {
        owner_inclusive_missing(ep, &required)
            .iter()
            .any(|id| Some(id) != owner_id.as_ref())
    });
    // needs_rrk_backfill: some retained epoch lacks the OWNER's own wrap — the owner is LOCKED OUT of it and
    // cannot self-heal (they can't open what they can't reach), so only another active member can add the
    // owner's missing wrap (the A3 member-authored heal). Keeps the field name the shared `Unlocked` struct
    // exposes; under owner-as-member its meaning is "the owner's read gap a member heals" (was: RRK orphan).
    let needs_rrk_backfill = owner_id.as_ref().is_some_and(|oid| {
        epochs
            .iter()
            .any(|ep| owner_inclusive_missing(ep, &required).iter().any(|id| id == oid))
    });
    Ok(FoldedSealing {
        epochs,
        write_key_id,
        needs_reseal: !winner_covers,
        needs_backfill,
        needs_rrk_backfill,
    })
}

/// Fold the effective ops' sealing deltas into the current epochs + escrow + the deterministic write epoch.
/// The non-checkpoint path: a fresh fold (baseline 0) over the whole stream, then finalize.
fn fold_sealing(
    sealing: &[dag_client::SealingEntry],
    members: &MembershipView,
) -> Result<FoldedSealing, VaultError> {
    let mut state = FoldState::default();
    fold_into(&mut state, sealing, true)?;
    finalize_sealing(state, members)
}

/// Author a checkpoint's preserved sealing from the pre-cut sealing stream (OPE-348 step 2a): fold to the
/// PRE-retain intermediate and re-express it as synthetic `SealingEntry`s — one per tagged epoch (its
/// `added_wraps` already merged, so a below-cut joiner wrap is NOT lost) carrying the epoch's real origin +
/// `op_id` (the winner tiebreak), plus one `Other`-origin escrow entry. Returns the segment (fold order
/// preserved) + the `minting_ops` baseline. PRE-retain, deliberately: the OPE-289 bound is time-varying, so
/// dropping epochs at author time would permanently lose an epoch a full-history replica later resurrects.
fn author_checkpoint_sealing(
    pre_cut_sealing: &[dag_client::SealingEntry],
) -> Result<(Vec<dag_client::SealingEntry>, u32), VaultError> {
    let mut state = FoldState::default();
    fold_into(&mut state, pre_cut_sealing, true)?;

    let mut segment = Vec::with_capacity(state.tagged.len() + 2);
    for (epoch, origin, op_id, author) in state.tagged {
        let payload = SealingPayload {
            new_epochs: vec![epoch],
            added_wraps: vec![],
            escrow: None,
        };
        // The synthetic entry carries the minting op's author. Its wraps are already merged (and were F3-capped
        // below the cut), and on re-fold it is a minting entry with no `added_wraps`, so the cap never re-touches
        // it — the author is preserved for fidelity, not re-bounding.
        segment.push(dag_client::SealingEntry {
            op_id,
            origin,
            author,
            bytes: payload.to_bytes(),
        });
    }
    // A pre-543 escrow (only the not-yet-rewired credential flows, and the fold-logic fixtures) likewise rides
    // an Other-origin entry so it survives the prune. Authored by the escrow's owner.
    if let Some(escrow) = state.escrow {
        let escrow_author = escrow.member_id.clone();
        segment.push(dag_client::SealingEntry {
            op_id: [0u8; 32],
            origin: dag_client::SealingOrigin::Other,
            author: escrow_author,
            bytes: SealingPayload::escrow_only(escrow).to_bytes(),
        });
    }
    // A count past u32::MAX is unreachable; saturate rather than truncate.
    Ok((
        segment,
        u32::try_from(state.minting_ops).unwrap_or(u32::MAX),
    ))
}

/// Resolve-from-checkpoint fold: seed the minting count from the checkpoint `baseline`, fold the checkpoint
/// `segment` WITHOUT counting its mints (they are already in the baseline), then fold the retained `tail`
/// normally, then finalize. The segment must be folded BEFORE the tail (fold order) so a retained `added_wrap`
/// targeting a pre-cut epoch attaches to the checkpoint entry — guaranteed because the compaction cut is
/// dominating (every pruned entry precedes every retained one).
fn fold_from_checkpoint(
    segment: &[dag_client::SealingEntry],
    baseline: u32,
    tail: &[dag_client::SealingEntry],
    members: &MembershipView,
) -> Result<FoldedSealing, VaultError> {
    let mut state = FoldState {
        minting_ops: u64::from(baseline),
        ..Default::default()
    };
    fold_into(&mut state, segment, false)?;
    fold_into(&mut state, tail, true)?;
    finalize_sealing(state, members)
}

/// Fold a resolved anchor's sealing → `FoldedSealing`, routing a CHECKPOINT anchor (with a preserved segment)
/// through `fold_from_checkpoint` and an un-compacted one through `fold_sealing`. The single seam every vault op
/// folds through, so checkpoint-awareness lives in one place.
fn fold_resolved(resolved: &dag_client::Resolved) -> Result<FoldedSealing, VaultError> {
    match &resolved.checkpoint_sealing {
        Some(segment) => fold_from_checkpoint(
            segment,
            resolved.minting_ops_baseline,
            &resolved.sealing,
            &resolved.members,
        ),
        None => fold_sealing(&resolved.sealing, &resolved.members),
    }
}

/// Resolve + fold a dag anchor into the three inputs the §B3 verify seam ([`crate::verify::dag`]) needs: the
/// CURRENT membership view, the sticky `has_been_shared` flag, and the FULL set of retained epoch `key_id`s.
///
/// The epoch set is the accept set for the epoch-consistency check — EVERY epoch the tree has folded, not just
/// the write-winner. A legitimate entry sealed under a prior epoch (the norm after any `Remove`/`Reseal`
/// rotation) must not be falsely `EpochMismatch`-rejected on a fresh replay; membership+role are still checked
/// against the current view, so this widening never admits an unauthorised author.
pub(crate) struct VerifyInputs {
    pub view: MembershipView,
    pub shared: bool,
    pub epoch_ids: Vec<Vec<u8>>,
    /// The ever-legitimately-a-member set (id → keys ever held + strongest role ever held) — for the self-heal
    /// covered-accept P6 gate (reader) and the cover-authoring sweep (writer).
    pub ever_members: std::collections::BTreeMap<String, openom_keyring_api::EverMemberInfo>,
}

pub(crate) fn verify_inputs(anchor: &[u8]) -> Result<VerifyInputs, VaultError> {
    let resolved =
        dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
    let folded = fold_resolved(&resolved)?;
    let epoch_ids = folded
        .epochs
        .iter()
        .map(|e| e.key_id.as_bytes().to_vec())
        .collect();
    Ok(VerifyInputs {
        view: resolved.members,
        shared: resolved.has_been_shared,
        epoch_ids,
        ever_members: resolved.ever_members,
    })
}

/// Build the sealing payload for a covering reseal: a fresh DEK as a single new epoch, wrapped to EVERY
/// resolved member — INCLUDING the owner (OPE-543 owner-as-member: the owner has no recovery-root wrap, they
/// hold a per-epoch member wrap like anyone else). Minting needs only PUBLIC keys (each member's HPKE key,
/// the owner's included), so both the owner (passphrase) and any active member (`member_kdf`) can produce it;
/// the caller appends it under their OWN identity (OPE-290).
fn covering_reseal_sealing(
    tree_id: &[u8],
    members: &MembershipView,
    epochs: &[keyeo_crypto::Epoch<String>],
) -> Result<Vec<u8>, VaultError> {
    let new_dek = generate_dek()?;
    let new_key_id = generate_salt()?.to_vec();
    let new_ordinal = epochs.iter().map(|e| e.ordinal).max().map_or(Ok(0), |m| {
        m.checked_add(1).ok_or(VaultError::RevisionOverflow)
    })?;
    let mut wraps = Vec::with_capacity(members.members.len());
    for m in &members.members {
        // A member (owner included) with an empty/malformed key can't be wrapped — excluded from coverage
        // too, so this doesn't leave a permanent needs_reseal (OPE-290).
        if m.hpke_public_key.is_empty() {
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
    Ok(SealingPayload {
        new_epochs: vec![keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(new_key_id),
            ordinal: new_ordinal,
            dek_commitment: keyeo_crypto::dek_commitment(&new_dek),
            wraps,
        }],
        added_wraps: vec![],
        escrow: None,
    }
    .to_bytes())
}

/// The resolved membership as keyeo coverage descriptors: EVERY member (the owner INCLUDED — OPE-543
/// owner-as-member — and empty-hpke-key members excluded), each KEY-BOUND to their CURRENT hpke key
/// (`expected_key = Some`), which is the OPE-290 stale-key guard: a wrap on a member's old key doesn't count
/// toward coverage. Fed to the local owner-inclusive coverage predicates below.
fn member_descriptors(members: &MembershipView) -> Vec<RecipientDescriptor<String>> {
    members
        .members
        .iter()
        .filter(|m| !m.hpke_public_key.is_empty())
        .map(|m| RecipientDescriptor {
            id: m.member_id.clone(),
            expected_key: X25519PublicKey::try_from(m.hpke_public_key.as_slice()).ok(),
        })
        .collect()
}

/// Does this `MemberHpke` wrap cover `d` (right recipient id AND, if bound, right key)? A local reimpl of
/// keyeo's private `member_covers` — needed because under owner-as-member there is no `rrk` descriptor to
/// feed keyeo's `covers_exact`/`missing`, so coverage is computed over member wraps alone (per the task:
/// add a local predicate rather than change `keyeo-crypto`).
fn member_covers_local(w: &keyeo_crypto::Wrap<String>, d: &RecipientDescriptor<String>) -> bool {
    match &w.method {
        KeyeoWrapMethod::MemberHpke { recipient_key, .. } => {
            w.recipient == d.id
                && d.expected_key
                    .as_ref()
                    .is_none_or(|k| recipient_key == k)
        }
        _ => false,
    }
}

/// The resolved members (owner included) an epoch does NOT cover with a current-key `MemberHpke` wrap
/// (OPE-288 read gap). Owner-inclusive analog of keyeo's `missing`, minus the recovery-root descriptor.
fn owner_inclusive_missing(
    epoch: &keyeo_crypto::Epoch<String>,
    required: &[RecipientDescriptor<String>],
) -> Vec<String> {
    required
        .iter()
        .filter(|d| !epoch.wraps.iter().any(|w| member_covers_local(w, d)))
        .map(|d| d.id.clone())
        .collect()
}

/// Does this epoch cover EXACTLY the resolved membership (owner included) — no lockout and no leak? A
/// lockout = some required member is `missing`; a leak = a `MemberHpke` wrap to an id outside `required` (a
/// since-removed member who can still open it). Owner-inclusive analog of keyeo's `covers_exact`.
fn owner_inclusive_covers_exact(
    epoch: &keyeo_crypto::Epoch<String>,
    required: &[RecipientDescriptor<String>],
) -> bool {
    if !owner_inclusive_missing(epoch, required).is_empty() {
        return false; // a lockout
    }
    let required_ids: std::collections::HashSet<&String> = required.iter().map(|d| &d.id).collect();
    !epoch.wraps.iter().any(|w| {
        matches!(w.method, KeyeoWrapMethod::MemberHpke { .. })
            && !required_ids.contains(&w.recipient)
    })
}

/// The result of folding the sealing deltas: the retained epochs (for reads), the deterministic write-epoch
/// `key_id` (the winner), and whether the winner is stale vs the resolved membership (`needs_reseal`).
///
/// OPE-543 2b: there is no folded `escrow` field. Recovery/passphrase-change are account-keystore-mediated and
/// never read an on-tree escrow; the residual escrow plumbing in `SealingPayload`/`FoldState` survives only for
/// the checkpoint author's fidelity and the fold-logic fixtures (always `None` on a real owner-as-member tree).
struct FoldedSealing {
    epochs: Vec<keyeo_crypto::Epoch<String>>,
    write_key_id: Vec<u8>,
    needs_reseal: bool,
    /// Some retained epoch lacks a wrap for a resolved NON-OWNER member — they can't read that slice of
    /// history until the OWNER backfills it (OPE-288). Orthogonal to `needs_reseal` (a write-epoch issue).
    needs_backfill: bool,
    /// Some retained epoch lacks the OWNER's own member wrap — the owner is locked out of it and cannot
    /// self-heal (they can't open what they can't reach), so another active member adds the owner's wrap via
    /// `backfill_rrk` (OPE-543 A3). The owner-read counterpart of `needs_backfill`.
    needs_rrk_backfill: bool,
}

/// When a [`DagVault::reseal`] / [`DagVault::reseal_as_member`] actually mints a covering epoch.
///
/// `WhenStale` is the ordinary idempotent self-heal — reseal iff the resolved keyring `needs_reseal`, else a
/// no-op — so racing devices converge. `Force` mints unconditionally, past that gate. The force path exists
/// because `needs_reseal` is derived from the author-DECLARED recipient key, which is UNAUTHENTICATED: a
/// malicious op can wrap the DEK to garbage while declaring the victim's real current key, so coverage
/// reports "clean" and the automatic repair is suppressed. A member/owner who unlocks and finds they can't
/// actually reach the write epoch ([`Unlocked::write_epoch_unreachable`]) forces a covering reseal regardless
/// of what the hint claims — repairing the lockout the coverage signal can't see (OPE-299).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResealTrigger {
    /// Reseal only if the resolved keyring is stale (`needs_reseal`); otherwise a no-op. The idempotent path.
    WhenStale,
    /// Reseal unconditionally, past the `needs_reseal` gate — the local-write-unreachability escape hatch.
    Force,
}

/// The result of [`DagVault::reseal`]: the (possibly unchanged) anchor to publish + its watermark, and
/// whether a repair was actually appended (`false` = nothing was stale, a no-op).
pub struct Resealed {
    pub anchor: Vec<u8>,
    pub watermark: Vec<u8>,
    pub resealed: bool,
}

/// The result of [`DagVault::backfill`]: the (possibly unchanged) anchor + its watermark, and whether
/// historical-read wraps were actually added (`false` = nothing was missing, a no-op).
pub struct Backfilled {
    pub anchor: Vec<u8>,
    pub watermark: Vec<u8>,
    pub backfilled: bool,
}

/// Map a facade anti-rollback failure onto the sealer's error vocabulary: a rolled-back anchor and a
/// corrupt floor stay distinct (mirroring the chain's `RevisionRollback` / `MalformedWatermark`); anything
/// else (a bad anchor) is a `BadKeyring`.
fn map_floor_err(e: dag_client::ClientError) -> VaultError {
    match e {
        dag_client::ClientError::RolledBack(detail) => VaultError::WatermarkRollback { detail },
        dag_client::ClientError::BadWatermark(_) => VaultError::MalformedWatermark,
        other => VaultError::BadKeyring(other.to_string()),
    }
}

/// The DAG engine's vault — a zero-sized selector, like [`crate::lifecycle::ChainVault`].
///
/// Its anchor is the
/// dag keyring's pinned-config + op-closure bytes; each flow resolves membership through the facade and DEK
/// material through the shared core.
pub struct DagVault;

/// Open a dag tree with an already-unlocked durable ACCOUNT identity (OPE-543 owner-as-member): resolve the
/// membership, fold the sealing, check the account IS the resolved Owner (anti-substitution + self-cert), and
/// open every epoch's DEK via the owner's own per-epoch `MemberHpke` wrap. Shared by the trait [`DagVault::unlock`]
/// (which unwraps the caller's account `Option`) and [`DagVault::recover`] (which supplies the account it just
/// restored from the keystore) — so recovery unlocks the tree by EXACTLY the normal owner path, not a special one.
fn unlock_with_account(
    ctx: &VaultContext,
    anchor: &[u8],
    account: &UnlockedAccount,
) -> Result<Unlocked, VaultError> {
    let tree_id = ctx.tree_id.as_bytes();
    let replica_id = ctx.replica_id.as_bytes();

    let resolved = dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
    let founder = resolved
        .members
        .owner()
        .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
    // The ON-TREE owner id is the self-certifying derived id, not `ctx.member_id`.
    let owner_id = founder.member_id.clone();

    let FoldedSealing {
        epochs,
        write_key_id,
        needs_reseal,
        needs_backfill,
        needs_rrk_backfill,
        ..
    } = fold_resolved(&resolved)?;

    let root = account.tree_root();
    // Anti-substitution: the account identity must be the RESOLVED Owner's key, so a swapped owner — or an
    // account that isn't this tree's owner — fails here. And self-cert: the key must bind the resolved owner id.
    let derived = root.identity.verifying_key().to_bytes();
    if derived.as_slice() != founder.author_public_key.as_slice()
        || derive_member_id(&derived) != owner_id
    {
        return Err(CryptoError::Signature.into());
    }

    let deks = member_epoch_deks(&epochs, tree_id, &owner_id, &root.hpke_secret);
    // Local reachability (OPE-299): did our own DEK bag actually reach the winning write epoch? Derived here,
    // not from the author-declared coverage hint, so a malicious wrap-to-garbage can't hide the lockout.
    let write_epoch_unreachable = !deks.iter().any(|(k, _, _)| *k == write_key_id);
    let mut sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id);

    let owner_key: [u8; 32] = founder
        .author_public_key
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::BadKeyring("owner key is not 32 bytes".into()))?;
    let watermark = dag_client::watermark(anchor).map_err(map_floor_err)?;
    // Sign entries once the tree HAS BEEN SHARED; a never-shared solo dag stays unattributed (Phase C, OPE-351).
    if resolved.has_been_shared {
        sealer = sealer.with_author(root.identity, owner_id.clone(), watermark.clone());
    }
    Ok(Unlocked {
        sealer,
        watermark,
        did_key: DidKey::from_public_key(&owner_key),
        needs_reseal,
        needs_backfill,
        needs_rrk_backfill,
        write_epoch_unreachable,
    })
}

impl KeyringLifecycle for DagVault {
    /// Create a brand-new dag-backed tree: mint a fresh DEK (epoch 0), a recovery root key escrowing it,
    /// and a content-addressed genesis op naming the founder as Owner + carrying epoch-0 and the escrow in
    /// its `sealing` payload, with the derived RVK pinned as the recovery authority.
    fn provision(
        &self,
        ctx: &VaultContext,
        account: &UnlockedAccount,
    ) -> Result<Provisioned, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let replica_id = ctx.replica_id.as_bytes();

        // OPE-543 owner-as-member + OPE-542 durable identity: the owner is an ORDINARY member whose identity is
        // the durable ACCOUNT (the app unlocked its keystore and passes the `UnlockedAccount` in). The owner's
        // account Ed25519 key signs the genesis and their account HPKE key receives epoch-0's DEK via a
        // `MemberHpke` wrap — NOT a recovery-root (RRK) wrap. Their `member_id` self-certifies that identity key
        // (the engine enforces `member_id == derive_member_id(author_key)` at admission). There is no per-tree
        // recovery escrow and no pinned recovery authority (`reset_authority = None`) — recovery lives in the
        // account keystore, not the tree — and no owner passphrase KDF rides the sealing (the `_passphrase` here
        // is the chain's credential; the dag path ignores it). `ctx.member_id` is the app's notion; the ON-TREE
        // identity is the derived one, which must match or resolve() would reject the genesis.
        let root = &account.root;

        let dek = generate_dek()?;
        let key_id = generate_salt()?.to_vec();
        let author_public = root.identity.verifying_key().to_bytes();
        let member_id = derive_member_id(&author_public);

        let owner_wrap = member_wrap_keyeo(&root.hpke_public, &dek, tree_id, &member_id, &key_id)?;
        let epoch0 = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(key_id.clone()),
            ordinal: 0,
            dek_commitment: keyeo_crypto::dek_commitment(&dek),
            wraps: vec![owner_wrap],
        };

        let did_key = DidKey::from_public_key(&author_public);

        let sealing = SealingPayload {
            new_epochs: vec![epoch0],
            added_wraps: vec![],
            escrow: None,
        }
        .to_bytes();
        let anchor = dag_client::provision_anchor(
            tree_id,
            &member_id,
            root.identity.verifying_key(),
            X25519PublicKey::from_bytes(root.hpke_public),
            None,
            sealing,
            &root.identity,
        );

        let sealer =
            sealer_set_from_deks(tree_id, replica_id, vec![(key_id.clone(), 0, dek)], key_id);
        let watermark = dag_client::watermark(&anchor).map_err(map_floor_err)?;
        // The per-tree recovery code is gone under owner-as-member — recovery is the account keystore's, minted
        // by the app when it created the account. Provision reports an EMPTY code; the app shows the keystore's.
        Ok(Provisioned {
            anchor,
            recovery_code: RecoveryCode::new(String::new()),
            sealer,
            did_key,
            watermark,
        })
    }

    /// Re-open a dag-backed tree from its anchor + the durable account identity: resolve the membership, fold
    /// the sealing state, check the account identity IS the resolved Owner, and open every epoch's DEK via the
    /// owner's own per-epoch `MemberHpke` wrap (their account HPKE secret) into a sealer.
    fn unlock(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
    ) -> Result<Unlocked, VaultError> {
        // OPE-543 owner-as-member + OPE-542 durable identity: the owner reads via the MEMBER path using their
        // durable ACCOUNT identity (the app unlocked the keystore and passes it in) — NOT a passphrase re-derive
        // off a sealing-carried KDF. The `_passphrase` here is the chain's credential; the dag path takes the
        // identity from `account`. All the resolve/verify/open work lives in the shared `unlock_with_account`.
        unlock_with_account(ctx, anchor, account)
    }

    /// Recover with the recovery code — ACCOUNT-keystore-mediated (OPE-543 2b durable identity). The account
    /// recovery code restores the SAME durable identity the tree already trusts (`AccountKeystore::
    /// unlock_with_recovery`); we re-wrap the account blob under `new_passphrase` and open the tree by the
    /// NORMAL owner path with that restored identity. There is NO on-tree op: no `ReFound`, so the tree anchor
    /// is UNCHANGED, the resolved owner is UNCHANGED, and `did_key` is preserved — recovery therefore introduces
    /// no takeover surface and no rollback, it merely re-derives the local wrapping of the durable account.
    ///
    /// The only new durable output is the re-wrapped `keystore` blob; the per-tree `recovery_code` is empty
    /// (the account's recovery code is not consumed/rotated by a recovery — the SAME code keeps working).
    fn recover(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Recovered, VaultError> {
        // Anti-rollback: the served anchor is untrusted on recovery, so refuse one that dropped a frontier op
        // below the caller's floor before doing any work. (The anchor is not mutated; this guards the read.)
        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        // Restore the durable account identity from the keystore via the recovery code (SAME member_id / keys),
        // then re-wrap it under the new passphrase. `from_bytes`+`change_passphrase` never touch the tree.
        let ks = AccountKeystore::from_bytes(keystore)?;
        let unlocked = ks.unlock_with_recovery(recovery_code)?;
        let new_ks = ks.change_passphrase(&unlocked, new_passphrase.expose())?;

        // Open the tree with the restored identity by the ordinary owner path — the anchor is unchanged, so the
        // resolved owner is exactly this identity (anti-substitution inside `unlock_with_account` enforces it).
        let u = unlock_with_account(ctx, anchor, &unlocked)?;
        Ok(Recovered {
            anchor: anchor.to_vec(),
            recovery_code: RecoveryCode::new(String::new()),
            keystore: new_ks.to_bytes()?,
            sealer: u.sealer,
            watermark: u.watermark,
            did_key: u.did_key,
            needs_reseal: u.needs_reseal,
            needs_backfill: u.needs_backfill,
        })
    }

    /// Change the passphrase — ACCOUNT-keystore-mediated (OPE-543 2b). NO on-tree keyring op: the durable
    /// identity the tree trusts is unchanged, so this is purely an `AccountKeystore::change_passphrase` re-wrap
    /// of the account blob under the new KEK. The tree `anchor` + `watermark` are UNCHANGED and the running
    /// sealer keeps working (the DEKs are untouched). Returns the new keystore blob; the per-tree recovery code
    /// is empty (a passphrase change does not rotate the account's recovery code).
    fn change_passphrase(
        &self,
        _ctx: &VaultContext,
        anchor: &[u8],
        keystore: &[u8],
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
        floor: &[u8],
    ) -> Result<Rekeyed, VaultError> {
        // Anti-rollback symmetry with the chain: refuse a rolled-back served anchor before the re-wrap. The
        // anchor itself is not mutated — the change lives entirely in the account keystore.
        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let ks = AccountKeystore::from_bytes(keystore)?;
        let unlocked = ks.unlock(old_passphrase.expose())?; // a wrong current passphrase fails closed here
        let new_ks = ks.change_passphrase(&unlocked, new_passphrase.expose())?;

        let watermark = dag_client::watermark(anchor).map_err(map_floor_err)?;
        Ok(Rekeyed {
            anchor: anchor.to_vec(),
            recovery_code: RecoveryCode::new(String::new()),
            keystore: new_ks.to_bytes()?,
            watermark,
        })
    }
}

impl DagVault {
    /// Merge a remote anchor of the SAME tree into the local one — the causal set-union of their op closures
    /// (the op-DAG is a set-union CRDT), so concurrent membership branches both survive and resolve
    /// deterministically. The host calls this to fold in a peer's anchor before persisting + re-watermarking;
    /// a following `unlock` reports `needs_reseal` if the merged write epoch is stale (see [`Self::reseal`]).
    ///
    /// # Errors
    /// Returns [`VaultError`] if either anchor is malformed.
    pub fn merge(&self, local: &[u8], remote: &[u8]) -> Result<Vec<u8>, VaultError> {
        dag_client::merge(local, remote).map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    // OPE-543 2b: `rotate_recovery` was REMOVED for the dag. Under durable identity there is no per-tree
    // recovery root (RRK) to rotate — the account keystore owns recovery, and account-level rotation is
    // `AccountKeystore::rotate_account_root` (wired by OPE-549), not an on-tree op. The two-phase
    // rotation-confirm observers below remain as read-only anchor queries over the engine's still-supported
    // reset ops (harmless: on an owner-as-member tree `reset_authority` is `None`).

    /// The resolved recovery authority (RVK) at `anchor`'s frontier — `None` for a group with no recovery
    /// authority. The observable half of the two-phase rotation gate ([`Self::rotation_confirmed`]): a caller
    /// reads this on the rotation's OWN anchor to learn the authority it established, then re-reads it on the
    /// synced anchor to confirm the rotation survived the merge.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed.
    pub fn resolved_reset_authority(&self, anchor: &[u8]) -> Result<Option<[u8; 32]>, VaultError> {
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        Ok(resolved.reset_authority)
    }

    /// Two-phase rotation confirmation (OPE-381 / §11.2). A [`Self::rotate_recovery`] is COMPLETE only once
    /// its new authority is observed in the MERGED/synced anchor. The append-only log admits a concurrent
    /// rotation (or, in the loser's frame, a superseding one): two rotations forked from the same frontier
    /// merge to a single deterministic winner, so the LOSER's freshly-minted recovery code never becomes the
    /// resolved authority. So the caller records the authority its rotation established — from the rotation's
    /// own anchor via [`Self::resolved_reset_authority`] — and, after syncing, calls this against the synced
    /// anchor. `false` means the rotation did NOT survive the merge: the returned recovery code is void and
    /// the caller must re-rotate, and — critically — must keep treating the OLD code as live until a rotation
    /// it authored is confirmed. `true` means the new code is now the sole recovery authority. Until this
    /// returns `true` the recovery code from `rotate_recovery` is PROVISIONAL.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed.
    pub fn rotation_confirmed(
        &self,
        synced_anchor: &[u8],
        expected: &[u8; 32],
    ) -> Result<bool, VaultError> {
        Ok(self.resolved_reset_authority(synced_anchor)? == Some(*expected))
    }

    /// The resolved Owner's identity key at `anchor`'s frontier — `None` on a malformed roster with no owner.
    /// The observable half of the superseded-recovery signal ([`Self::recovery_confirmed`]).
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed.
    pub fn resolved_owner_key(&self, anchor: &[u8]) -> Result<Option<Vec<u8>>, VaultError> {
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        Ok(resolved
            .members
            .owner()
            .map(|o| o.author_public_key.clone()))
    }

    /// The superseded-recovery signal (OPE-381 / §11.2), symmetric to [`Self::rotation_confirmed`]. A
    /// [`KeyringLifecycle::recover`] establishes a NEW owner identity via a `ReFound`, but a rotation — or
    /// another recovery — concurrent with it VOIDS that `ReFound` on merge (the resolver's carve-out can't
    /// arbitrate a shared old code between two holders), reverting the owner key. So the recovering owner's
    /// new access can be silently superseded. The caller records the owner key its recovery established (from
    /// the recovery's own anchor via [`Self::resolved_owner_key`], or its returned `did_key`) and, after
    /// syncing, calls this against the synced anchor. `false` means the recovery did NOT survive — the owner
    /// is no longer the resolved Owner and must recover again — so a locked-out owner gets a signal instead of
    /// believing they are in control. Until it returns `true`, a recovery is PROVISIONAL, like a rotation.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed.
    pub fn recovery_confirmed(
        &self,
        synced_anchor: &[u8],
        expected_owner_key: &[u8],
    ) -> Result<bool, VaultError> {
        Ok(self.resolved_owner_key(synced_anchor)?.as_deref() == Some(expected_owner_key))
    }

    /// The anchor's opaque anti-rollback watermark (its frontier op-id set) — the cursor the host persists
    /// alongside the anchor and passes back as the floor on the next mutation. Opaque bytes to every caller.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed.
    pub fn watermark(&self, anchor: &[u8]) -> Result<Vec<u8>, VaultError> {
        dag_client::watermark(anchor).map_err(map_floor_err)
    }

    /// Add `new_member_id` (at `role`, with their OOB-verified keys) to a dag tree. The owner unwraps the
    /// RRK via their passphrase, reaches every epoch's DEK, wraps each to the new member's HPKE key, and
    /// appends an `Add` op carrying those per-epoch wraps in its sealing. Returns the new anchor. Inherent,
    /// not a [`KeyringLifecycle`] flow — membership authoring stays engine-specific (OPE-277 gate, Q2=B).
    ///
    /// # Errors
    /// Returns [`VaultError`] if the author isn't authorized, the anchor is malformed, or sealing the joiner's wraps fails.
    pub fn add_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        joiner: &crate::vault::Joiner<KeyringRole>,
    ) -> Result<Vec<u8>, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let new_member_id = joiner.member_id.as_str();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        // The ON-TREE owner id is the self-certifying derived id.
        let owner_id = founder.member_id.clone();
        let FoldedSealing { epochs, .. } = fold_resolved(&resolved)?;

        // OPE-543 owner-as-member + OPE-542 durable identity: the owner authorizes with their durable ACCOUNT
        // identity (passed in) — anti-substitution vs the resolved Owner key + self-cert on the id — then opens
        // every epoch's DEK via their OWN per-epoch member wrap (not a recovery-root wrap).
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        // Reach every epoch's DEK and wrap each to the new member's HPKE key. The joiner's keys were
        // narrowed once (in `Joiner::from_bytes`); the SAME values wrap every DEK and register the member,
        // so the wrapped key and the stored key are provably identical.
        let hpke_public_key = joiner.hpke_public_key.to_bytes();
        let deks = member_epoch_deks(&epochs, tree_id, &owner_id, &root.hpke_secret);
        let added_wraps: Vec<AddedWrap> = deks
            .iter()
            .map(|(key_id, _epoch, dek)| {
                member_wrap_keyeo(&hpke_public_key, dek, tree_id, new_member_id, key_id).map(
                    |wrap| AddedWrap {
                        key_id: key_id.clone(),
                        wrap,
                    },
                )
            })
            .collect::<Result<_, _>>()?;

        let sealing = SealingPayload {
            new_epochs: vec![],
            added_wraps,
            escrow: None,
        }
        .to_bytes();
        // Infallible narrowing to keyeo's owned genesis-shaped init at the engine boundary (the typed keys
        // are already validated); `append_add` keeps taking `KeyringMemberInit`.
        let member = openom_keyring_dag::KeyringMemberInit {
            id: joiner.member_id.clone(),
            role: joiner.role,
            author_public_key: joiner.author_public_key.to_bytes(),
            hpke_public_key,
        };
        dag_client::append_add(anchor, &owner_id, &member, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    /// Unlock as an ORDINARY member (not the owner): resolve the keyring, find `ctx.member_id`, derive their
    /// identity from their passphrase + their account `member_kdf`, check it against their resolved key
    /// (anti-substitution), and reach the DEKs via their OWN per-epoch HPKE wraps (join-epoch-onward) — not
    /// the RRK, which only the owner holds. Inherent (the trait `unlock` is the owner/RRK path).
    ///
    /// # Errors
    /// Returns [`VaultError`] if the member reaches no epoch or the anchor is malformed.
    pub fn unlock_as_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
        member_kdf: &KeyeoKdfParams,
    ) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
        validate_kdf(member_kdf)?;
        let root = derive_root(passphrase.expose(), member_kdf)?;
        Self::unlock_as_member_with_root(ctx, anchor, root)
    }

    /// Unlock an ordinary member through the profile's durable account identity.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the account is not the requested member, is absent/removed, or reaches no
    /// current epoch.
    pub fn unlock_as_account_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
    ) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
        if ctx.member_id.as_str() != account.member_id {
            return Err(VaultError::NotAuthorized);
        }
        Self::unlock_as_member_with_root(ctx, anchor, account.tree_root())
    }

    fn unlock_as_member_with_root(
        ctx: &VaultContext,
        anchor: &[u8],
        root: RootKeys,
    ) -> Result<(Unlocked, openom_crypto::HpkePrivate), VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();
        let replica_id = ctx.replica_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| VaultError::BadKeyring("not a member of this tree".into()))?;
        let FoldedSealing {
            epochs,
            write_key_id,
            needs_reseal,
            needs_backfill,
            needs_rrk_backfill,
            ..
        } = fold_resolved(&resolved)?;

        if root.identity.verifying_key().to_bytes().as_slice() != me.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        let deks = member_epoch_deks(&epochs, tree_id, member_id, &root.hpke_secret);
        // Local reachability (OPE-299): did our per-member wraps actually reach the winning write epoch? See
        // the owner path — this is the local, author-declaration-independent lockout signal that un-gates a
        // forced reseal when a malicious wrap suppresses `needs_reseal`.
        let write_epoch_unreachable = !deks.iter().any(|(k, _, _)| *k == write_key_id);
        let mut sealer = sealer_set_from_deks(tree_id, replica_id, deks, write_key_id);
        let my_key: [u8; 32] = me
            .author_public_key
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::BadKeyring("member key is not 32 bytes".into()))?;
        // A member unlock reports the same frontier watermark as the owner path (anti-rollback is not
        // owner-specific): the member persists it and passes it back as their floor.
        let watermark = dag_client::watermark(anchor).map_err(map_floor_err)?;
        // Member writer gate: sign iff the tree has been shared. Always true on a member unlock — a member
        // only exists once shared — but gate on `has_been_shared` for symmetry with the owner path, stamping the
        // unlock-time frontier as governing_ref (Phase C, OPE-351).
        if resolved.has_been_shared {
            sealer = sealer.with_author(root.identity, member_id.to_string(), watermark.clone());
        }
        // A member unlock ALWAYS carries the HPKE secret (a member exists only on a shared tree): the running
        // core retains it to adopt a later (post-removal) epoch on sync without the passphrase (OPE-393) — a
        // first-class second value, not an `Option` on the shared `Unlocked` (the owner path has none).
        Ok((
            Unlocked {
                sealer,
                watermark,
                did_key: DidKey::from_public_key(&my_key),
                needs_reseal,
                needs_backfill,
                needs_rrk_backfill,
                write_epoch_unreachable,
            },
            root.hpke_secret,
        ))
    }

    /// Re-derive a member's reachable epoch DEKs from a freshly-synced dag anchor, using the HPKE secret the
    /// core retained at unlock — the crypto behind a member's epoch ADOPT on a rotation (OPE-393). No
    /// passphrase, no re-verification (the sync path already verified the anchor): resolve, fold the sealing,
    /// and unwrap the member's per-epoch wraps, like [`Self::unlock_as_member`] over an already-trusted anchor.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed or the member reaches no epoch.
    pub fn adopt_member_epochs(
        &self,
        anchor: &[u8],
        hpke_secret: &openom_crypto::HpkePrivate,
        tree_id: &[u8],
        member_id: &str,
    ) -> Result<crate::sharing::AdoptedEpochs, VaultError> {
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let FoldedSealing { epochs, .. } = fold_resolved(&resolved)?;
        let deks = member_epoch_deks(&epochs, tree_id, member_id, hpke_secret);
        let write_key_id = write_epoch_by_ordinal(&deks)?;
        let governing_ref = if resolved.has_been_shared {
            dag_client::watermark(anchor).map_err(map_floor_err)?
        } else {
            Vec::new()
        };
        let epochs_out = deks.into_iter().map(|(k, _e, d)| (k, d.into_inner())).collect();
        Ok(crate::sharing::AdoptedEpochs {
            epochs: epochs_out,
            write_key_id,
            governing_ref,
        })
    }

    /// Remove `remove_member_id` from a dag tree with forward secrecy: the owner mints a FRESH DEK the
    /// removed member can't reach, wraps it to the RRK (owner) + each REMAINING ordinary member's HPKE key,
    /// and appends a `Remove` op carrying that new epoch in its sealing. Future entries seal under the new
    /// epoch, so the removed member — who has no wrap for it — can't read them. Returns the new anchor.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the author isn't authorized, the anchor is malformed, or the reseal fails.
    pub fn remove_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        remove_member_id: &str,
    ) -> Result<Vec<u8>, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let owner_id = founder.member_id.clone();
        let FoldedSealing { epochs, .. } = fold_resolved(&resolved)?;

        // The owner authorizes via their durable ACCOUNT signing identity (anti-substitution + self-cert).
        // Removing needs only PUBLIC keys — the fresh DEK is wrapped to each remaining member's HPKE public.
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        // Forward-secret re-epoch (OPE-543 owner-as-member): a fresh DEK wrapped to each REMAINING member —
        // the OWNER INCLUDED, as an ordinary member wrap. The removed member gets no wrap.
        let new_dek = generate_dek()?;
        let new_key_id = generate_salt()?.to_vec();
        let new_ordinal = epochs.iter().map(|e| e.ordinal).max().map_or(Ok(0), |m| {
            m.checked_add(1).ok_or(VaultError::RevisionOverflow)
        })?;
        let mut wraps = Vec::with_capacity(resolved.members.members.len());
        for m in &resolved.members.members {
            if m.member_id == remove_member_id || m.hpke_public_key.is_empty() {
                continue; // the removed member gets no wrap; an empty-keyed member can't be wrapped
            }
            wraps.push(member_wrap_keyeo(
                &m.hpke_public_key,
                &new_dek,
                tree_id,
                &m.member_id,
                &new_key_id,
            )?);
        }
        let sealing = SealingPayload {
            new_epochs: vec![keyeo_crypto::Epoch {
                key_id: KeyeoKeyId::new(new_key_id),
                ordinal: new_ordinal,
                dek_commitment: keyeo_crypto::dek_commitment(&new_dek),
                wraps,
            }],
            added_wraps: vec![],
            escrow: None,
        }
        .to_bytes();
        dag_client::append_remove(anchor, &owner_id, remove_member_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    /// Change an existing member's role (OPE-364) — promote to co-owner (signer) / demote a co-owner to a
    /// non-signer role. Founder-authorized: the owner's passphrase-derived signing identity must be the pinned
    /// owner key, and a `ChangeRole` touching a signer requires OWNER authority (enforced verifier-side). NO
    /// re-epoch / no sealing — a role change touches signing authority, not keys, so read access + the running
    /// sealer are unchanged; the resolver's `StrongDemote` rule voids a demoted member's concurrent
    /// over-authority ops. Returns the new anchor bytes; the caller re-watermarks from it.
    ///
    /// # Errors
    /// Returns [`VaultError`] on a malformed anchor, a wrong owner passphrase, an unknown target, or an
    /// attempt to change the owner's own role.
    pub fn change_role(
        &self,
        _ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        target_member_id: &str,
        new_role: KeyringRole,
    ) -> Result<Vec<u8>, VaultError> {
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let owner_id = founder.member_id.clone();

        // The owner's role is fixed; and the target must exist. (A signer-touching ChangeRole is authorized
        // OWNER-only verifier-side; these author-side guards keep an ineffective op from being persisted.)
        if target_member_id == owner_id {
            return Err(VaultError::BadKeyring(
                "the owner's role cannot be changed".into(),
            ));
        }
        if !resolved
            .members
            .members
            .iter()
            .any(|m| m.member_id == target_member_id)
        {
            return Err(VaultError::MemberNotFound);
        }

        // The owner authorizes via their durable ACCOUNT signing identity (anti-substitution + self-cert) — the
        // same gate `remove_member` applies (OPE-543 owner-as-member). No sealing: the role change re-wraps no
        // keys, so it reads no epochs.
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        dag_client::append_change_role(anchor, &owner_id, target_member_id, new_role, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    /// Repair a stale write epoch (OPE-282): if the resolved keyring `needs_reseal` — a concurrent
    /// membership merge left the write epoch wrapping a removed member (a leak) or missing an added one (a
    /// lockout) — mint a FRESH DEK wrapped to the RRK (owner) + each resolved ordinary member and append a
    /// membership-inert `Reseal` op. Idempotent: a no-op (anchor unchanged, `resealed = false`) when nothing
    /// is stale, so racing devices converge (a covering reseal makes `needs_reseal` false everywhere).
    /// Owner-authored via passphrase (a locked-out member's self-heal via `member_kdf` is a follow-up).
    /// Enforces the anti-rollback `floor`; returns the new anchor + watermark.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed or the reseal sealing fails.
    pub fn reseal(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        floor: &[u8],
        trigger: ResealTrigger,
    ) -> Result<Resealed, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let owner_id = founder.member_id.clone();
        let FoldedSealing {
            epochs,
            needs_reseal,
            ..
        } = fold_resolved(&resolved)?;

        // Idempotent: nothing stale → return the anchor unchanged, no op appended. `Force` bypasses this gate
        // for the local-write-unreachability self-heal, where the coverage signal is untrustworthy (OPE-299).
        if trigger == ResealTrigger::WhenStale && !needs_reseal {
            return Ok(Resealed {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                resealed: false,
            });
        }

        // The owner authorizes via their durable ACCOUNT identity (anti-substitution + self-cert, OPE-543
        // owner-as-member); the fresh DEK is wrapped to every member's HPKE public (owner included), so no
        // secret beyond the owner's identity is needed to reseal.
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        // Mint a covering epoch; the OWNER both authors and signs it (author == owner).
        let sealing = covering_reseal_sealing(tree_id, &resolved.members, &epochs)?;
        let new_anchor = dag_client::append_reseal(anchor, &owner_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Resealed {
            anchor: new_anchor,
            watermark,
            resealed: true,
        })
    }

    /// Author a checkpoint-rooted anchor at a SUPPLIED dominating `frontier` (OPE-348 step 2a): the ops at/below
    /// the frontier are pruned into a signed [`Checkpoint`]. The owner authorizes via their passphrase-derived
    /// identity (the checkpoint author == owner, anti-substitution as in [`Self::reseal`]), and the sealing
    /// preservation is folded in via `author_checkpoint_sealing` (keyring-dag never interprets sealing). Returns
    /// the new anchor bytes. Choosing the frontier automatically over active members is OPE-371; this takes it
    /// as a parameter.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed or authoring the checkpoint fails.
    pub fn compact(
        &self,
        anchor: &[u8],
        account: &UnlockedAccount,
        frontier: &[[u8; 32]],
        prev_snapshot: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, VaultError> {
        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let owner_id = founder.member_id.clone();
        // Owner authorizes via their durable ACCOUNT identity (anti-substitution + self-cert, OPE-543
        // owner-as-member) — the checkpoint is Owner-signed.
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        dag_client::compact_to_checkpoint(
            anchor,
            frontier,
            prev_snapshot,
            owner_id,
            &root.identity,
            |pre| author_checkpoint_sealing(pre).map_err(|e| format!("{e:?}")),
        )
        .map_err(|e| VaultError::BadKeyring(e.to_string()))
    }

    /// Member-authored self-heal of a stale write epoch (OPE-290). Identical repair to [`Self::reseal`], but any
    /// ACTIVE member — not just the owner — can drive it: minting a covering epoch needs only PUBLIC keys
    /// (the RRK public in the escrow + each resolved member's HPKE key), and keyeo authorizes a Reseal by any
    /// member, so a member locked out by a stale merge no longer has to wait for the owner's device to come
    /// online. Authorizes via the member's `passphrase` + account `member_kdf` (their identity signs the op),
    /// mirroring [`Self::unlock_as_member`]. The RRK wrap stays keyed to the OWNER (its holder). Idempotent + floor
    /// enforced, exactly like the owner path.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the member can't author the reseal or the anchor is malformed.
    pub fn reseal_as_member(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
        member_kdf: &KeyeoKdfParams,
        floor: &[u8],
        trigger: ResealTrigger,
    ) -> Result<Resealed, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| VaultError::BadKeyring("not a member of this tree".into()))?;
        let FoldedSealing {
            epochs,
            needs_reseal,
            ..
        } = fold_resolved(&resolved)?;

        // Idempotent: nothing stale → return the anchor unchanged, no op appended. `Force` bypasses this gate
        // for the local-write-unreachability self-heal, where the coverage signal is untrustworthy (OPE-299).
        if trigger == ResealTrigger::WhenStale && !needs_reseal {
            return Ok(Resealed {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                resealed: false,
            });
        }

        // The member authorizes via their passphrase + account kdf-derived identity (anti-substitution vs
        // their resolved key). The fresh DEK is wrapped to every member's HPKE public (owner included), so no
        // secret beyond the member's identity is needed (OPE-543 owner-as-member).
        validate_kdf(member_kdf)?;
        let root = derive_root(passphrase.expose(), member_kdf)?;
        if root.identity.verifying_key().to_bytes().as_slice() != me.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // The member authors + signs the op.
        let sealing = covering_reseal_sealing(tree_id, &resolved.members, &epochs)?;
        let new_anchor = dag_client::append_reseal(anchor, member_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Resealed {
            anchor: new_anchor,
            watermark,
            resealed: true,
        })
    }

    /// Member-side heal of a rotation-orphaned epoch (OPE-381 / F3). A recovery rotation re-wraps every epoch
    /// it resolves to the new recovery root, but an epoch minted CONCURRENTLY (a remove/reseal racing the
    /// rotation) is missed: its only RRK wrap targets the retired escrow key, so the owner — who no longer
    /// holds the old recovery secret — can't open it, and coverage reports `needs_rrk_backfill`. Any active
    /// member still holds a per-epoch member wrap, so they open the DEK and add a fresh RRK wrap to the
    /// CURRENT escrow public key, restoring the owner's cross-epoch read. Authorizes via the member's
    /// `passphrase` + account `member_kdf` (their identity signs the op; Reseal-class, any active member may
    /// author it), exactly like [`Self::reseal_as_member`]. Tolerant: an orphan this member can't open is left
    /// for another member. Idempotent (`backfilled = false` when no orphan is reachable) + floor-enforced.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the member can't be authorized or the anchor is malformed.
    pub fn backfill_rrk(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        passphrase: &Passphrase,
        member_kdf: &KeyeoKdfParams,
        floor: &[u8],
    ) -> Result<Backfilled, VaultError> {
        validate_kdf(member_kdf)?;
        let root = derive_root(passphrase.expose(), member_kdf)?;
        Self::backfill_rrk_with_root(ctx, anchor, &root, floor)
    }

    /// Heal missing member wraps with the already-unlocked durable account identity.
    ///
    /// # Errors
    /// Returns [`VaultError`] if the account is not the context member, cannot be authorized by the anchor,
    /// or the anchor is malformed.
    pub fn backfill_rrk_as_account(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        floor: &[u8],
    ) -> Result<Backfilled, VaultError> {
        if ctx.member_id.as_str() != account.member_id {
            return Err(VaultError::NotAuthorized);
        }
        let root = account.tree_root();
        Self::backfill_rrk_with_root(ctx, anchor, &root, floor)
    }

    fn backfill_rrk_with_root(
        ctx: &VaultContext,
        anchor: &[u8],
        root: &RootKeys,
        floor: &[u8],
    ) -> Result<Backfilled, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();
        let member_id = ctx.member_id.as_str();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let me = resolved
            .members
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| VaultError::BadKeyring("not a member of this tree".into()))?;
        let FoldedSealing {
            epochs,
            needs_backfill,
            needs_rrk_backfill,
            ..
        } = fold_resolved(&resolved)?;

        let unchanged = || -> Result<Backfilled, VaultError> {
            Ok(Backfilled {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                backfilled: false,
            })
        };
        // Idempotent: no epoch is missing any resolved member (owner OR non-owner) → nothing to do. This
        // member-authored heal is the ONLY one that can repair the owner's OWN gap (`needs_rrk_backfill`),
        // the A3 lockout an owner-authored `backfill` cannot fix.
        if !needs_backfill && !needs_rrk_backfill {
            return unchanged();
        }

        // The member authorizes via their account identity (anti-substitution vs their resolved key), and
        // that same durable account yields the HPKE secret they open epochs with.
        if root.identity.verifying_key().to_bytes().as_slice() != me.author_public_key.as_slice() {
            return Err(CryptoError::Signature.into());
        }

        // Open every epoch this member can reach; for each, add a `MemberHpke` wrap for ANY resolved member
        // (the OWNER INCLUDED — OPE-543 A3) not already covered by a wrap to their CURRENT key.
        // `member_epoch_deks` verifies each DEK against the epoch commitment (F3), so a member can only ever
        // backfill a wrap of the epoch's REAL DEK — a corrupt wrap fails to open and is skipped, never
        // re-wrapped. The fold-side per-(epoch, author, recipient) cap bounds a flood.
        let deks = member_epoch_deks(&epochs, tree_id, member_id, &root.hpke_secret);
        let mut added_wraps: Vec<AddedWrap> = Vec::new();
        for (key_id, _ordinal, dek) in &deks {
            let epoch_wraps = epochs
                .iter()
                .find(|e| e.key_id.as_bytes() == key_id.as_slice())
                .map_or(&[][..], |e| e.wraps.as_slice());
            for m in &resolved.members.members {
                if m.hpke_public_key.is_empty() {
                    continue;
                }
                // Covered = a MemberHpke wrap addressed to this member AND bound to their CURRENT key.
                let covered = epoch_wraps.iter().any(|w| {
                    w.recipient == m.member_id
                        && matches!(&w.method,
                            KeyeoWrapMethod::MemberHpke { recipient_key, .. }
                                if recipient_key.as_ref() == m.hpke_public_key.as_slice())
                });
                if covered {
                    continue;
                }
                let wrap =
                    member_wrap_keyeo(&m.hpke_public_key, dek, tree_id, &m.member_id, key_id)?;
                added_wraps.push(AddedWrap {
                    key_id: key_id.clone(),
                    wrap,
                });
            }
        }

        // Every gap was in an epoch this member can't open (skipped) → nothing we can repair here; another
        // member with a wrap heals it. No-op rather than an empty op.
        if added_wraps.is_empty() {
            return unchanged();
        }

        let sealing = SealingPayload {
            new_epochs: vec![],
            added_wraps,
            escrow: None,
        }
        .to_bytes();
        let new_anchor = dag_client::append_backfill(anchor, member_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Backfilled {
            anchor: new_anchor,
            watermark,
            backfilled: true,
        })
    }

    /// Backfill historical READ access (OPE-288). A member added on one branch has no wrap for epochs minted
    /// concurrently on another branch before the merge, so after resolution they can't read history sealed
    /// under those epochs. The owner — who reaches every DEK via the RRK — re-wraps each retained epoch for
    /// every resolved member missing from it, appending an `added_wraps`-only op (no new epoch, membership
    /// inert; keyeo sees only an authored Reseal-kind op). Owner-authored (only the RRK opens the old DEKs).
    /// Idempotent: a no-op (`backfilled = false`) when no epoch is missing any resolved member. Enforces the
    /// anti-rollback `floor`; returns the new anchor + watermark. Orthogonal to `reseal` (forward secrecy).
    ///
    /// # Errors
    /// Returns [`VaultError`] if the anchor is malformed or authoring the backfill fails.
    pub fn backfill(
        &self,
        ctx: &VaultContext,
        anchor: &[u8],
        account: &UnlockedAccount,
        floor: &[u8],
    ) -> Result<Backfilled, VaultError> {
        let tree_id = ctx.tree_id.as_bytes();

        dag_client::check_floor(anchor, floor).map_err(map_floor_err)?;

        let resolved =
            dag_client::resolve(anchor).map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let founder = resolved
            .members
            .owner()
            .ok_or_else(|| VaultError::BadKeyring("no owner in the resolved dag keyring".into()))?;
        let owner_id = founder.member_id.clone();
        let FoldedSealing {
            epochs,
            needs_backfill,
            ..
        } = fold_resolved(&resolved)?;

        // Idempotent: every retained epoch already wraps every resolved non-owner member → nothing to do.
        let unchanged = || -> Result<Backfilled, VaultError> {
            Ok(Backfilled {
                watermark: dag_client::watermark(anchor).map_err(map_floor_err)?,
                anchor: anchor.to_vec(),
                backfilled: false,
            })
        };
        if !needs_backfill {
            return unchanged();
        }

        // The owner authorizes via their durable ACCOUNT identity (anti-substitution + self-cert) and opens
        // every epoch via their OWN member wrap (OPE-543 owner-as-member) — the same open-all-DEKs path as
        // `add_member`.
        let root = &account.root;
        let derived = root.identity.verifying_key().to_bytes();
        if derived.as_slice() != founder.author_public_key.as_slice()
            || derive_member_id(&derived) != owner_id
        {
            return Err(CryptoError::Signature.into());
        }

        // Open every epoch the owner can reach; for each, add a wrap for any resolved NON-OWNER member not
        // already covered by a wrap addressed to their CURRENT key (OPE-290: key-bound, so a member left on a
        // STALE key after a rekey race is re-wrapped too). (`member_epoch_deks` skips an un-openable epoch
        // rather than failing, so a corrupt epoch can't brick this.) The owner cannot heal its OWN gap here
        // (it can't open an epoch it lacks a wrap for) — that is `backfill_rrk`'s job (A3). Empty-key members
        // are skipped — nothing to wrap.
        let deks = member_epoch_deks(&epochs, tree_id, &owner_id, &root.hpke_secret);
        let mut added_wraps: Vec<AddedWrap> = Vec::new();
        for (key_id, _epoch, dek) in &deks {
            let epoch_wraps = epochs
                .iter()
                .find(|e| e.key_id.as_bytes() == key_id.as_slice())
                .map_or(&[][..], |e| e.wraps.as_slice());
            for m in &resolved.members.members {
                if m.member_id == owner_id || m.hpke_public_key.is_empty() {
                    continue;
                }
                // Covered = a MemberHpke wrap addressed to this member AND bound to their CURRENT key.
                let covered = epoch_wraps.iter().any(|w| {
                    w.recipient == m.member_id
                        && matches!(&w.method,
                            KeyeoWrapMethod::MemberHpke { recipient_key, .. }
                                if recipient_key.as_ref() == m.hpke_public_key.as_slice())
                });
                if covered {
                    continue;
                }
                let wrap =
                    member_wrap_keyeo(&m.hpke_public_key, dek, tree_id, &m.member_id, key_id)?;
                added_wraps.push(AddedWrap {
                    key_id: key_id.clone(),
                    wrap,
                });
            }
        }

        // Every missing epoch was un-openable (skipped by `member_epoch_deks`) → nothing we can repair; no-op.
        if added_wraps.is_empty() {
            return unchanged();
        }

        let sealing = SealingPayload {
            new_epochs: vec![],
            added_wraps,
            escrow: None,
        }
        .to_bytes();
        let new_anchor = dag_client::append_backfill(anchor, &owner_id, sealing, &root.identity)
            .map_err(|e| VaultError::BadKeyring(e.to_string()))?;
        let watermark = dag_client::watermark(&new_anchor).map_err(map_floor_err)?;
        Ok(Backfilled {
            anchor: new_anchor,
            watermark,
            backfilled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // OPE-543 2b: these RRK/escrow-era helpers are no longer used by any dag flow (the credential flows are
    // account-keystore-mediated), but the fold/opener fixtures + membership scenarios still exercise them.
    use crate::vault_core::{epoch_deks, open_epoch_dek, rrk_wrap_keyeo};
    use openom_crypto::{
        default_kdf_params, generate_hpke_keypair, HpkeKeypair, RootKeys, RrkSecret,
    };

    /// A member's derived identity + their account KDF params — the test-only bundle the membership scenarios
    /// admit (replacing the retired `vault_core::new_owner_secrets` owner-credential helper; the dag now takes
    /// the owner from a durable account keystore, so this mints only an ORDINARY member's passphrase identity).
    struct MemberSecrets {
        root: RootKeys,
        pass_kdf: KeyeoKdfParams,
    }
    fn member_secrets(pass: &Passphrase) -> MemberSecrets {
        let pass_kdf = default_kdf_params(generate_salt().unwrap().to_vec());
        let root = derive_root(pass.expose(), &pass_kdf).unwrap();
        MemberSecrets { root, pass_kdf }
    }

    use crate::AccountKeystore;
    use openom_keyring_api::MemberView;
    use openom_keyring_dag::KeyringRole;
    use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
    use openom_sealer::{EntryKind, SealContext};

    const TREE: &[u8] = b"tree-uuid-16byte";
    const MEMBER: &str = "acct-1";

    /// A test owner's durable ACCOUNT keystore (OPE-542) — created once per scenario. The app holds the blob
    /// and re-derives a fresh [`UnlockedAccount`] per owner-authored op ([`acct`]); the derived identity is
    /// stable, so provision + every later unlock/mutation resolve the SAME owner.
    fn owner_ks(pass: &Passphrase) -> AccountKeystore {
        AccountKeystore::create(pass.expose()).unwrap().0
    }
    /// A fresh [`UnlockedAccount`] for an owner-authored op, from the owner's keystore + passphrase.
    fn acct(ks: &AccountKeystore, pass: &Passphrase) -> UnlockedAccount {
        ks.unlock(pass.expose()).unwrap()
    }
    /// Provision a dag tree owned by a freshly-minted account keystore; returns the keystore (for later owner
    /// ops) and the provisioned result.
    fn provision_owned(
        tree: &TreeId,
        member: &MemberId,
        replica: &ReplicaId,
        pass: &Passphrase,
    ) -> (AccountKeystore, Provisioned) {
        let ks = owner_ks(pass);
        let p = DagVault
            .provision(&ctx(tree, member, replica), &acct(&ks, pass))
            .unwrap();
        (ks, p)
    }

    fn ctx<'a>(tree: &'a TreeId, member: &'a MemberId, replica: &'a ReplicaId) -> VaultContext<'a> {
        VaultContext {
            tree_id: tree,
            member_id: member,
            replica_id: replica,
        }
    }

    /// The self-certifying member id of an account's identity key (OPE-543): every admitted member's id must
    /// be `derive_member_id(author_pubkey)` or the engine refuses the Add.
    fn member_id_of(secrets: &MemberSecrets) -> String {
        derive_member_id(&secrets.root.identity.verifying_key().to_bytes())
    }

    /// Admit `secrets` as an EDITOR onto `anchor`, returning `(new anchor, the joiner's self-cert member id)`
    /// — the verbose `add_member` + `Joiner::from_bytes` preamble shared by the membership scenarios. The
    /// owner ctx member id is irrelevant (the owner authors under their resolved, self-certifying id).
    fn admit_editor(
        tree: &TreeId,
        owner_ks: &AccountKeystore,
        owner_pass: &Passphrase,
        anchor: &[u8],
        secrets: &MemberSecrets,
    ) -> (Vec<u8>, String) {
        let mid = member_id_of(secrets);
        let owner = MemberId::new(MEMBER);
        let anchor = DagVault
            .add_member(
                &ctx(tree, &owner, &ReplicaId::new(b"r1")),
                anchor,
                &acct(owner_ks, owner_pass),
                &crate::vault::Joiner::from_bytes(
                    &MemberId::new(&mid),
                    KeyringRole::EDITOR,
                    &secrets.root.identity.verifying_key().to_bytes(),
                    &secrets.root.hpke_public,
                )
                .unwrap(),
            )
            .unwrap();
        (anchor, mid)
    }

    /// The DAG vault provisions a tree's recovery-verification key via `openom_crypto::derive_rvk` (the
    /// shared vault derivation, also used by the chain vault), but the DAG *engine* verifies a `ReFound`
    /// against its own `openom_keyring_dag::recovery::derive_rvk`. Since OPE-279 those two live in different crates —
    /// openom-crypto and the now-openom-free openom-keyring-dag — sharing only `edsign`'s HKDF and the frozen
    /// `keyeo:rvk:v1` label. They MUST stay byte-identical or a validly recovered tree would fail admission;
    /// this pins them against drift (the guard the recovery.rs / root.rs doc-comments point to).
    #[test]
    fn vault_and_engine_derive_the_same_recovery_key() {
        for secret in [
            [0u8; 32],
            [7u8; 32],
            [255u8; 32],
            *b"a-32-byte-recovery-root-secret!!",
        ] {
            let vault_rvk = openom_crypto::derive_rvk(&secret)
                .verifying_key()
                .to_bytes();
            let engine_rvk = openom_keyring_dag::recovery::rvk_public(&secret);
            assert_eq!(
                vault_rvk, engine_rvk,
                "the vault's provisioning RVK and the dag engine's verifying RVK must match byte-for-byte"
            );
        }
    }

    /// Pad/truncate arbitrary test bytes into a 32-byte X25519 key. Real HPKE keys are already 32 bytes; the
    /// tests use short readable labels, so this makes them well-formed (keyeo's `X25519PublicKey` is fixed
    /// 32) yet distinct — the coverage checks are key-bound (OPE-290), so the byte value carries meaning.
    fn key32(bytes: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 32];
        let n = bytes.len().min(32);
        k[..n].copy_from_slice(&bytes[..n]);
        k
    }
    fn x25519(bytes: &[u8]) -> X25519PublicKey {
        X25519PublicKey::from_bytes(key32(bytes))
    }

    /// A member's deterministic HPKE public key, so `membership` (the resolved view) and `member_wrap` (the
    /// epoch wrap) agree on what "the current key" is for the coverage checks (OPE-290).
    fn hpke_key(member: &str) -> Vec<u8> {
        key32(format!("hpke-{member}").as_bytes()).to_vec()
    }

    /// A resolved membership: `owner` (role 1) plus each of `members` as an Editor (role 4).
    fn membership(owner: &str, members: &[&str]) -> MembershipView {
        let mv = |id: &str, role: i16| MemberView {
            member_id: id.to_string(),
            role,
            author_public_key: vec![],
            hpke_public_key: hpke_key(id),
        };
        let mut v = vec![mv(owner, 1)];
        v.extend(members.iter().map(|m| mv(m, 4)));
        MembershipView::new(v, false)
    }

    /// A placeholder wrap ciphertext — the fold-logic fixtures never open a wrap, only inspect its
    /// recipient/method/key, so the DEK bytes are irrelevant (a real open is exercised by the opener tests).
    fn placeholder_ct() -> keyeo_crypto::WrappedDek {
        keyeo_crypto::WrappedDek::from_bytes([0u8; 48])
    }
    fn placeholder_encapped() -> keyeo_crypto::EncappedKey {
        keyeo_crypto::EncappedKey::from_bytes([0u8; 32])
    }

    /// An HPKE wrap addressed to `member`'s CURRENT key (matches `membership`).
    fn member_wrap(member: &str) -> keyeo_crypto::Wrap<String> {
        member_wrap_keyed(member, &hpke_key(member))
    }
    /// The OWNER's per-epoch member wrap (OPE-543 owner-as-member: the owner is an ordinary `MemberHpke`
    /// recipient, not a recovery-root wrap). Its recipient id is `"owner"`, matching the `membership` fixture.
    fn owner_wrap() -> keyeo_crypto::Wrap<String> {
        member_wrap("owner")
    }
    /// An HPKE wrap for `member` addressed to an explicit `recipient` key — pass a non-current key to model a
    /// STALE-key wrap left after a rekey race (OPE-290).
    fn member_wrap_keyed(member: &str, recipient: &[u8]) -> keyeo_crypto::Wrap<String> {
        keyeo_crypto::Wrap {
            recipient: member.to_string(),
            method: KeyeoWrapMethod::MemberHpke {
                encapped: placeholder_encapped(),
                recipient_key: x25519(recipient),
            },
            ciphertext: placeholder_ct(),
        }
    }
    /// A residual pre-543 recovery-escrow public key — retained only so the `escrow()` fixture (fed to the
    /// not-yet-rewired credential-flow fold paths) resolves against a real X25519 key.
    fn escrow_key() -> Vec<u8> {
        x25519(&hpke_key("owner")).to_bytes().to_vec()
    }
    fn sealing_entry(
        op_id: u8,
        key_id: &[u8],
        ordinal: u64,
        origin: dag_client::SealingOrigin,
        wraps: Vec<keyeo_crypto::Wrap<String>>,
        escrow: Option<RecoveryEscrow>,
    ) -> dag_client::SealingEntry {
        let payload = SealingPayload {
            new_epochs: vec![keyeo_crypto::Epoch {
                key_id: KeyeoKeyId::new(key_id.to_vec()),
                ordinal,
                // Fold/coverage fixtures use placeholder wraps that never open, so the commitment is unused.
                dek_commitment: [0u8; 32],
                wraps,
            }],
            added_wraps: vec![],
            escrow,
        };
        dag_client::SealingEntry {
            op_id: [op_id; 32],
            origin,
            author: "owner".into(),
            bytes: payload.to_bytes(),
        }
    }
    fn escrow() -> RecoveryEscrow {
        RecoveryEscrow {
            public_key: escrow_key(),
            member_id: "owner".into(),
            wraps: vec![],
            recovery_verifying_key: vec![2],
        }
    }

    /// Test lens over the production coverage: does this epoch cover the resolved membership exactly (the
    /// winner/`needs_reseal` predicate)? Mirrors `finalize_sealing`'s owner-inclusive coverage.
    fn epoch_covers(ep: &keyeo_crypto::Epoch<String>, members: &MembershipView) -> bool {
        owner_inclusive_covers_exact(ep, &member_descriptors(members))
    }
    /// Test lens over the `needs_backfill` check: does any epoch lock a resolved NON-OWNER member out (the
    /// owner-heals gap, exactly as `finalize_sealing` computes `needs_backfill`)?
    fn any_epoch_missing_a_member(
        epochs: &[keyeo_crypto::Epoch<String>],
        members: &MembershipView,
    ) -> bool {
        let required = member_descriptors(members);
        let owner_id = members.owner().map(|o| o.member_id.clone());
        epochs.iter().any(|ep| {
            owner_inclusive_missing(ep, &required)
                .iter()
                .any(|id| Some(id) != owner_id.as_ref())
        })
    }

    fn assert_folded_eq(a: &FoldedSealing, b: &FoldedSealing) {
        assert_eq!(a.epochs, b.epochs, "epochs differ");
        assert_eq!(a.write_key_id, b.write_key_id, "write_key_id differs");
        assert_eq!(a.needs_reseal, b.needs_reseal, "needs_reseal differs");
        assert_eq!(a.needs_backfill, b.needs_backfill, "needs_backfill differs");
    }

    /// The load-bearing claim: folding an authored checkpoint segment + the retained tail reproduces the EXACT
    /// `FoldedSealing` that folding the full history does.
    #[test]
    fn checkpoint_sealing_folds_identically_to_full_history() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &[]);
        let genesis = sealing_entry(1, b"k0", 0, Genesis, vec![], Some(escrow()));
        let removed = sealing_entry(2, b"k1", 1, Remove, vec![], None);

        // Cut after genesis: author from [genesis], retained tail = [removed].
        let (segment, baseline) = author_checkpoint_sealing(std::slice::from_ref(&genesis)).unwrap();
        let from_cp =
            fold_from_checkpoint(&segment, baseline, std::slice::from_ref(&removed), &members).unwrap();
        let full = fold_sealing(&[genesis, removed], &members).unwrap();
        assert_folded_eq(&from_cp, &full);
    }

    /// Pre-retain preservation (review F1): an epoch transiently dropped by the time-varying OPE-289 bound must
    /// be RESURRECTED when the minting count grows — exactly as full history does. A checkpoint that stored
    /// POST-retain epochs would lose it permanently; storing PRE-retain preserves it.
    #[test]
    fn checkpoint_preserves_a_transiently_dropped_then_resurrected_epoch() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &[]);
        // 2 minting entries below the cut, but a Remove carries ordinal 2 (models a post-void state where a
        // minting op was voided, so its ordinal momentarily exceeds the shrunk count). The bound drops it at
        // the cut (2 >= minting_ops 2). A retained mint grows the count to 3, resurrecting ordinal 2 (2 < 3).
        let genesis = sealing_entry(1, b"k0", 0, Genesis, vec![], Some(escrow()));
        let removed_hi = sealing_entry(2, b"k2", 2, Remove, vec![], None);
        let retained = sealing_entry(3, b"k3", 3, Remove, vec![], None);

        let (segment, baseline) =
            author_checkpoint_sealing(&[genesis.clone(), removed_hi.clone()]).unwrap();
        assert_eq!(baseline, 2, "two minting entries below the cut");

        let from_cp =
            fold_from_checkpoint(&segment, baseline, std::slice::from_ref(&retained), &members).unwrap();
        let full = fold_sealing(&[genesis, removed_hi, retained], &members).unwrap();

        assert!(
            from_cp.epochs.iter().any(|e| e.key_id.as_bytes() == b"k2"),
            "the transiently-dropped epoch (ordinal 2) is resurrected"
        );
        assert_folded_eq(&from_cp, &full);
    }

    /// End-to-end: author a checkpoint-rooted anchor from a real provisioned anchor (the vault supplies the
    /// sealing authoring as the callback), then resolve BOTH the checkpoint anchor and the full anchor and
    /// assert they fold to the identical `FoldedSealing` + the same membership. Exercises the whole wired path:
    /// `compact_to_checkpoint` → adopt → `fold_from_checkpoint`.
    #[test]
    fn compact_to_checkpoint_round_trips_through_resolve() {
        let sk = edsign::SigningKey::from_seed(&[9u8; 32]);
        let pk = sk.verifying_key();
        // OPE-543: the founder id must self-certify the author key (the engine's admission check).
        let owner = derive_member_id(&pk.to_bytes());
        let seal = |key: &[u8], ord: u64| {
            SealingPayload {
                new_epochs: vec![keyeo_crypto::Epoch {
                    key_id: KeyeoKeyId::new(key.to_vec()),
                    ordinal: ord,
                    dek_commitment: [0u8; 32],
                    wraps: vec![],
                }],
                added_wraps: vec![],
                escrow: None,
            }
            .to_bytes()
        };
        // Provision (genesis epoch-0), then two reseals (epoch 1, then 2).
        let a1 = dag_client::provision_anchor(
            b"tree",
            &owner,
            pk,
            X25519PublicKey::from_bytes([0xaa; 32]),
            None,
            seal(b"k0", 0),
            &sk,
        );
        let a2 = dag_client::append_reseal(&a1, &owner, seal(b"k1", 1), &sk).unwrap();
        let a3 = dag_client::append_reseal(&a2, &owner, seal(b"k2", 2), &sk).unwrap();

        // Cut at reseal1 (a2's single frontier tip): genesis + reseal1 are pruned into the checkpoint; reseal2
        // is retained above the cut.
        let wm = dag_client::watermark(&a2).unwrap();
        let cut: [u8; 32] = wm[..32].try_into().unwrap();

        let cp_anchor =
            dag_client::compact_to_checkpoint(&a3, &[cut], None, owner.clone(), &sk, |pre| {
                author_checkpoint_sealing(pre).map_err(|e| format!("{e:?}"))
            })
            .unwrap();

        let full = dag_client::resolve(&a3).unwrap();
        let cp = dag_client::resolve(&cp_anchor).unwrap();
        assert_folded_eq(&fold_resolved(&cp).unwrap(), &fold_resolved(&full).unwrap());
        assert_eq!(
            cp.members.members.len(),
            full.members.members.len(),
            "the checkpoint anchor resolves the same membership"
        );
    }

    /// The write epoch is the deterministic `(ordinal, minting op-id)` winner: among concurrent same-ordinal
    /// epochs the greater op-id wins, and the choice is independent of fold order — so every replica agrees
    /// without coordination (OPE-282). Fable's flagged `max_by_key` last-on-tie fragility is now explicit.
    #[test]
    fn fold_sealing_picks_the_ordinal_then_op_id_winner() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &[]);
        // Genesis epoch 0 (carries escrow) + two CONCURRENT Remove epoch-1 ops contend for the winner.
        let entries = vec![
            sealing_entry(0, b"k0", 0, Genesis, vec![], Some(escrow())),
            sealing_entry(5, b"kA", 1, Remove, vec![], None),
            sealing_entry(9, b"kB", 1, Remove, vec![], None),
        ];
        let wk = fold_sealing(&entries, &members).unwrap().write_key_id;
        assert_eq!(
            wk,
            b"kB".to_vec(),
            "the greater op-id wins the same-ordinal tie"
        );

        // Order-independent: reorder the input, same winner.
        let reordered = vec![
            sealing_entry(9, b"kB", 1, Remove, vec![], None),
            sealing_entry(0, b"k0", 0, Genesis, vec![], Some(escrow())),
            sealing_entry(5, b"kA", 1, Remove, vec![], None),
        ];
        let wk2 = fold_sealing(&reordered, &members).unwrap().write_key_id;
        assert_eq!(
            wk2,
            b"kB".to_vec(),
            "the winner is independent of fold order"
        );
    }

    /// Coverage drives `needs_reseal`, and origin gates eligibility: a winner that still wraps a removed
    /// member is flagged stale; an exactly-covering winner is clean; and an epoch smuggled through an
    /// `Other`-origin op (a self-Retarget/self-Remove carrying a self-only epoch) can never win, no matter
    /// how high its ordinal. (OPE-282.)
    #[test]
    fn coverage_flags_stale_winner_and_origin_blocks_smuggling() {
        use dag_client::SealingOrigin::{Genesis, Other};
        // Resolved membership = owner + bob; carol was removed.
        let members = membership("owner", &["bob"]);

        // A winner still wrapping the removed carol (a concurrent-merge leak) → stale.
        let stale = vec![sealing_entry(
            0,
            b"k0",
            0,
            Genesis,
            vec![owner_wrap(), member_wrap("bob"), member_wrap("carol")],
            Some(escrow()),
        )];
        assert!(
            fold_sealing(&stale, &members).unwrap().needs_reseal,
            "a winner wrapping a removed member is stale"
        );

        // A winner wrapping exactly {RRK, bob} → clean.
        let clean = vec![sealing_entry(
            0,
            b"k0",
            0,
            Genesis,
            vec![owner_wrap(), member_wrap("bob")],
            Some(escrow()),
        )];
        assert!(
            !fold_sealing(&clean, &members).unwrap().needs_reseal,
            "an exactly-covering winner is clean"
        );

        // Smuggling: an Other-origin op carries a self-only epoch at a huge ordinal — dropped, cannot win.
        let smuggle = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![owner_wrap(), member_wrap("bob")],
                Some(escrow()),
            ),
            sealing_entry(9, b"evil", 999, Other, vec![member_wrap("attacker")], None),
        ];
        let folded = fold_sealing(&smuggle, &members).unwrap();
        assert_eq!(
            folded.write_key_id,
            b"k0".to_vec(),
            "a smuggled Other-origin epoch cannot win the write epoch"
        );
        assert!(
            !folded.needs_reseal,
            "the covering genesis epoch is the clean winner"
        );
    }

    /// Coverage key-binds the OWNER's member wrap to their CURRENT key (OPE-543 owner-as-member + OPE-290): an
    /// epoch whose only owner wrap is on a stale key does NOT cover — the owner is treated exactly like any
    /// other member. (Replaces the pre-543 RRK-recipient-key-binding test; there is no recovery-root wrap.)
    #[test]
    fn coverage_binds_the_owner_recipient_key() {
        let members = membership("owner", &["bob"]);

        // The owner's wrap is on a STALE key; bob's is current → the owner is missing → no cover.
        let ep = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k0".to_vec()),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps: vec![member_wrap_keyed("owner", b"old-owner-key"), member_wrap("bob")],
        };
        let required = member_descriptors(&members);
        assert!(
            !owner_inclusive_covers_exact(&ep, &required),
            "a stale-key owner wrap must not count as coverage"
        );
        assert_eq!(
            owner_inclusive_missing(&ep, &required),
            vec!["owner".to_string()],
            "the owner is the sole missing recipient (bob is covered)"
        );

        // With the owner's CURRENT-key wrap present, the epoch covers.
        let ok = keyeo_crypto::Epoch {
            wraps: vec![owner_wrap(), member_wrap("bob")],
            ..ep.clone()
        };
        assert!(owner_inclusive_covers_exact(&ok, &required));
    }

    /// Ordinal-inflation `DoS` defense (OPE-289): an ELIGIBLE (Remove-origin) epoch grinding an implausible
    /// ordinal is dropped by the plausibility bound (ordinal < minting-op count) — so it can neither win the
    /// write epoch nor sit in the retained set where a later `max()+1` re-epoch would `RevisionOverflow` and
    /// permanently brick removals/reseals. A plausible higher ordinal still wins, so the bound never
    /// over-rejects.
    #[test]
    fn fold_sealing_drops_an_epoch_with_an_implausible_ordinal() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &["bob"]);

        // A Remove op grinds an epoch at u64::MAX. Two minting ops → bound 2, so u64::MAX (>= 2) is dropped:
        // without the guard it is eligible and its huge ordinal would win AND brick every future re-epoch.
        let attack = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![owner_wrap(), member_wrap("bob")],
                Some(escrow()),
            ),
            sealing_entry(
                9,
                b"evil",
                u64::MAX,
                Remove,
                vec![owner_wrap(), member_wrap("bob")],
                None,
            ),
        ];
        let folded = fold_sealing(&attack, &members).unwrap();
        assert_eq!(
            folded.write_key_id,
            b"k0".to_vec(),
            "an implausible-ordinal epoch cannot win"
        );
        assert!(
            folded.epochs.iter().all(|e| e.ordinal < 2),
            "the u64::MAX epoch is dropped from the retained set, so max()+1 cannot overflow"
        );

        // Boundary: a legit Remove epoch at ordinal 1 (bound 2, 1 < 2) is retained and legitimately wins.
        let legit = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![owner_wrap(), member_wrap("bob")],
                Some(escrow()),
            ),
            sealing_entry(
                9,
                b"k1",
                1,
                Remove,
                vec![owner_wrap(), member_wrap("bob")],
                None,
            ),
        ];
        assert_eq!(
            fold_sealing(&legit, &members).unwrap().write_key_id,
            b"k1".to_vec(),
            "a plausible higher ordinal is retained and wins — the bound does not over-reject"
        );
    }

    /// `needs_backfill` flags a resolved member missing a wrap in some RETAINED epoch (OPE-288) — the
    /// historical-READ gap a concurrent add leaves — and is ORTHOGONAL to `needs_reseal` (a write-epoch
    /// forward-secrecy signal): here the write epoch covers everyone, yet an older epoch doesn't. An extra
    /// (removed) member still wrapped in an old epoch does NOT trip it (removal is forward-only).
    #[test]
    fn needs_backfill_flags_a_member_missing_from_an_older_epoch() {
        use dag_client::SealingOrigin::{Genesis, Remove};
        let members = membership("owner", &["bob", "carol"]); // resolved = owner + bob + carol

        // Genesis epoch 0 predates carol (wraps owner+bob only); the newer epoch 1 covers owner+bob+carol.
        // The WRITE epoch (1) covers the resolved set → no reseal — but carol can't read epoch-0 history.
        let gap = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![owner_wrap(), member_wrap("bob")],
                Some(escrow()),
            ),
            sealing_entry(
                5,
                b"k1",
                1,
                Remove,
                vec![owner_wrap(), member_wrap("bob"), member_wrap("carol")],
                None,
            ),
        ];
        let folded = fold_sealing(&gap, &members).unwrap();
        assert!(
            !folded.needs_reseal,
            "the write epoch (k1) covers the resolved membership"
        );
        assert!(
            folded.needs_backfill,
            "carol lacks a wrap in the older epoch k0"
        );

        // Backfilled: every retained epoch wraps every resolved member → no gap.
        let complete = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![owner_wrap(), member_wrap("bob"), member_wrap("carol")],
                Some(escrow()),
            ),
            sealing_entry(
                5,
                b"k1",
                1,
                Remove,
                vec![owner_wrap(), member_wrap("bob"), member_wrap("carol")],
                None,
            ),
        ];
        assert!(
            !fold_sealing(&complete, &members).unwrap().needs_backfill,
            "all epochs cover all members"
        );

        // An EXTRA member (a removed dave still wrapped in the old epoch) is NOT a backfill gap.
        let extra = vec![
            sealing_entry(
                0,
                b"k0",
                0,
                Genesis,
                vec![
                    owner_wrap(),
                    member_wrap("bob"),
                    member_wrap("carol"),
                    member_wrap("dave"),
                ],
                Some(escrow()),
            ),
            sealing_entry(
                5,
                b"k1",
                1,
                Remove,
                vec![owner_wrap(), member_wrap("bob"), member_wrap("carol")],
                None,
            ),
        ];
        assert!(
            !fold_sealing(&extra, &members).unwrap().needs_backfill,
            "an extra removed member is not a gap"
        );
    }

    /// Recipient-key binding in coverage (OPE-290): a wrap left on a member's STALE key (a rekey race) is
    /// detected via the exists-current-key clause, while a benign COEXISTING old+new wrap is NOT flagged —
    /// exists-form, not pair-set equality, so the leftover doesn't force spurious churn.
    #[test]
    fn epoch_covers_binds_the_recipient_key() {
        let members = membership("owner", &["bob"]); // bob's current key = hpke_key("bob")

        let ok = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k".to_vec()),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps: vec![owner_wrap(), member_wrap("bob")],
        };
        assert!(
            epoch_covers(&ok, &members),
            "a wrap to bob's current key covers"
        );

        let stale = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k".to_vec()),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps: vec![owner_wrap(), member_wrap_keyed("bob", b"old-key")],
        };
        assert!(
            !epoch_covers(&stale, &members),
            "a wrap on bob's STALE key does not cover"
        );

        let both = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k".to_vec()),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps: vec![
                owner_wrap(),
                member_wrap_keyed("bob", b"old-key"),
                member_wrap("bob"),
            ],
        };
        assert!(
            epoch_covers(&both, &members),
            "a coexisting current-key wrap covers; the old one is ignored"
        );

        // needs_backfill uses the same key-bound test: a stale-key-only wrap counts as missing.
        let entries = vec![sealing_entry(
            0,
            b"k0",
            0,
            dag_client::SealingOrigin::Genesis,
            vec![owner_wrap(), member_wrap_keyed("bob", b"old-key")],
            Some(escrow()),
        )];
        assert!(
            fold_sealing(&entries, &members).unwrap().needs_backfill,
            "a member wrapped only under a stale key needs a backfill"
        );
    }

    /// A resolved member with an empty/malformed HPKE key is EXCLUDED from coverage (OPE-290) — it can be
    /// neither wrapped nor matched, so it must not wedge `needs_reseal`/`needs_backfill` permanently true.
    #[test]
    fn coverage_excludes_an_empty_keyed_member() {
        use openom_keyring_api::MemberView;
        let members = MembershipView::new(
            vec![
                MemberView {
                    member_id: "owner".into(),
                    role: 1,
                    author_public_key: vec![],
                    hpke_public_key: hpke_key("owner"),
                },
                MemberView {
                    member_id: "ghost".into(),
                    role: 4,
                    author_public_key: vec![],
                    hpke_public_key: vec![],
                },
            ],
            false,
        );
        let ep = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k".to_vec()),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps: vec![owner_wrap()],
        };
        assert!(
            epoch_covers(&ep, &members),
            "an empty-keyed member is excluded, so an RRK-only epoch covers"
        );
        assert!(
            !any_epoch_missing_a_member(&[ep], &members),
            "and it isn't reported as a backfill gap"
        );
    }

    /// OPE-290 companion: `member_epoch_deks` tries EVERY wrap addressed to the member, not just the first —
    /// so a DEAD stale-key wrap listed before the live one doesn't wrongly skip an epoch the member can open
    /// (without this, a key-bound backfill would be cosmetic).
    #[test]
    fn member_epoch_deks_opens_via_the_live_wrap_past_a_dead_one() {
        let tree = TREE;
        let kdf = KeyeoKdfParams {
            salt: generate_salt().unwrap().to_vec(),
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let root = derive_root(b"member pass", &kdf).unwrap();
        let dek = generate_dek().unwrap();
        let (member, key_id) = ("bob", b"k0");
        // A dead wrap to a DIFFERENT key, listed FIRST; then the live wrap to bob's real key.
        let other = generate_hpke_keypair().unwrap();
        let dead = member_wrap_keyeo(&other.public, &dek, tree, member, key_id).unwrap();
        let live = member_wrap_keyeo(&root.hpke_public, &dek, tree, member, key_id).unwrap();
        let ep = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(key_id.to_vec()),
            ordinal: 0,
            dek_commitment: keyeo_crypto::dek_commitment(&dek),
            wraps: vec![dead, live],
        };
        let deks = member_epoch_deks(&[ep], tree, member, &root.hpke_secret);
        assert_eq!(
            deks.len(),
            1,
            "the epoch opens via the live wrap despite a dead wrap first"
        );
    }

    /// OPE-287: a garbage epoch (a malicious member could append one) whose RRK wrap won't open is SKIPPED
    /// by `epoch_deks`, not fatal — so one junk epoch can't brick unlock for the owner, who still reaches
    /// every legitimate epoch.
    #[test]
    fn epoch_deks_skips_an_unopenable_epoch_instead_of_bricking() {
        let tree: &[u8] = b"tree-uuid-16byte";
        let HpkeKeypair { secret, public } = generate_hpke_keypair().unwrap();
        let rrk_secret = RrkSecret::from(secret);
        let dek = generate_dek().unwrap();
        let good = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"good".to_vec()),
            ordinal: 0,
            dek_commitment: keyeo_crypto::dek_commitment(&dek),
            wraps: vec![rrk_wrap_keyeo(&public, &dek, tree, "owner", b"good").unwrap()],
        };
        // A garbage epoch: an RRK-method wrap the owner's RRK secret cannot open (well-formed bytes, junk DEK).
        let garbage = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"evil".to_vec()),
            ordinal: 1,
            dek_commitment: [0u8; 32],
            wraps: vec![keyeo_crypto::Wrap {
                recipient: "owner".into(),
                method: KeyeoWrapMethod::RrkHpke {
                    encapped: keyeo_crypto::EncappedKey::from_bytes([9u8; 32]),
                    recipient_key: X25519PublicKey::from_bytes([9u8; 32]),
                },
                ciphertext: keyeo_crypto::WrappedDek::from_bytes([9u8; 48]),
            }],
        };
        let deks = epoch_deks(&[good, garbage], tree, "owner", &rrk_secret);
        assert_eq!(
            deks.len(),
            1,
            "the un-openable garbage epoch is skipped, not fatal"
        );
        assert_eq!(
            deks[0].0,
            b"good".to_vec(),
            "the legitimate epoch still opens"
        );
    }

    /// OPE-381 / F3: the DEK commitment rejects a wrap that OPENS but reproduces the WRONG DEK — not just an
    /// un-decryptable one. A hostile member (who holds the current escrow key, so their RRK wrap decrypts for
    /// the owner) plants a well-formed RRK wrap of a BOGUS DEK on an epoch committed to the real one. Without
    /// the commitment the owner would accept that DEK and read garbage / be censored; with it, the bogus wrap
    /// is skipped and the owner still reaches the real DEK from a legitimate wrap on the same epoch.
    #[test]
    fn open_epoch_dek_rejects_a_wrap_that_opens_to_the_wrong_dek() {
        let tree: &[u8] = b"tree-uuid-16byte";
        let HpkeKeypair { secret, public } = generate_hpke_keypair().unwrap();
        let rrk_secret = RrkSecret::from(secret);
        let real = generate_dek().unwrap();
        let bogus = generate_dek().unwrap();
        // The epoch commits to `real`; both wraps open under the owner's RRK secret (same recipient key), but
        // one carries `bogus`. Order the bogus wrap FIRST to prove try-all keeps looking past it.
        let ep = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k0".to_vec()),
            ordinal: 0,
            dek_commitment: keyeo_crypto::dek_commitment(&real),
            wraps: vec![
                rrk_wrap_keyeo(&public, &bogus, tree, "owner", b"k0").unwrap(),
                rrk_wrap_keyeo(&public, &real, tree, "owner", b"k0").unwrap(),
            ],
        };
        let dek = open_epoch_dek(&ep, tree, "owner", &rrk_secret).unwrap();
        assert!(
            ep.dek_matches_commitment(&dek),
            "open returns the committed (real) DEK, skipping the bogus wrap"
        );

        // With ONLY the bogus wrap, open must FAIL closed rather than hand back the wrong DEK.
        let bogus_only = keyeo_crypto::Epoch {
            key_id: KeyeoKeyId::new(b"k0".to_vec()),
            ordinal: 0,
            dek_commitment: keyeo_crypto::dek_commitment(&real),
            wraps: vec![rrk_wrap_keyeo(&public, &bogus, tree, "owner", b"k0").unwrap()],
        };
        assert!(
            open_epoch_dek(&bogus_only, tree, "owner", &rrk_secret).is_err(),
            "a wrap that opens to a non-committed DEK is rejected, not accepted"
        );
    }

    /// Provision on device A, seal data, then unlock from the anchor alone on device B and open it —
    /// the dag vault produces a working `SealerSet` through the shared core, end to end.
    #[test]
    fn dag_provision_then_unlock_opens_the_same_data() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");

        let (ks, p) = provision_owned(&tree, &member, &ReplicaId::new(b"replica-A"), &pass);
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"the family tree")
            .unwrap()
            .envelope;

        // Device B: unlock from the anchor bytes alone, a fresh replica, with the same durable account.
        let u = DagVault
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"replica-B")),
                &p.anchor,
                &acct(&ks, &pass),
            )
            .unwrap();
        assert_eq!(
            u.did_key, p.did_key,
            "same owner identity across provision + unlock"
        );
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"the family tree",
            "device B opens what device A sealed"
        );
    }

    /// OPE-543 2b — account-keystore-mediated recovery (durable identity). The account recovery code restores
    /// the SAME durable identity, re-wraps the account blob under a new passphrase, and the tree unlocks
    /// NORMALLY with that identity: the tree anchor is UNCHANGED, `did_key` is PRESERVED (no fresh identity, no
    /// `ReFound`), the recovered sealer opens pre-recovery data, and the re-wrapped keystore opens under the new
    /// passphrase but NOT the old one. This is the property that makes recovery safe with no on-tree takeover.
    #[test]
    fn dag_recover_then_unlock_with_the_new_passphrase_opens_the_same_data() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");
        let new_pass = Passphrase::new(b"a whole new passphrase");

        // The app creates the durable account (keeping its recovery code), then provisions the tree from it.
        let (ks, account_code, _u) = AccountKeystore::create(old_pass.expose()).unwrap();
        let p = DagVault
            .provision(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &ks.unlock(old_pass.expose()).unwrap(),
            )
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"heirloom")
            .unwrap()
            .envelope;

        // Recover: the account recovery code restores the SAME identity; the account is re-wrapped under the new
        // passphrase (the returned keystore blob) and the tree opens with the restored identity.
        let r = DagVault
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"r2")),
                &p.anchor,
                &ks.to_bytes().unwrap(),
                &account_code,
                &new_pass,
                &p.watermark,
            )
            .unwrap();
        assert_eq!(
            r.did_key, p.did_key,
            "recovery restores the SAME durable identity (no fresh owner, no ReFound)"
        );
        assert_eq!(r.anchor, p.anchor, "the tree anchor is unchanged by recovery");
        assert!(!r.keystore.is_empty(), "recovery returns the re-wrapped account keystore blob");
        assert_eq!(
            r.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"heirloom",
            "the recovered sealer opens pre-recovery data (the DEK is unchanged)"
        );

        // Unlock the (unchanged) anchor on a fresh device using the re-wrapped account under the NEW passphrase.
        let new_ks = AccountKeystore::from_bytes(&r.keystore).unwrap();
        let u = DagVault
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"r3")),
                &p.anchor,
                &new_ks.unlock(new_pass.expose()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            u.did_key, p.did_key,
            "unlock resolves the same durable owner identity"
        );
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"heirloom"
        );

        // The OLD passphrase no longer opens the re-wrapped account (the passphrase was rotated by recovery).
        assert!(
            new_ks.unlock(old_pass.expose()).is_err(),
            "the pre-recovery passphrase no longer opens the re-wrapped account"
        );
    }

    /// OPE-543 A3 end-to-end: a hostile co-owner mints a forward-secret (Remove-origin) epoch wrapping ONLY
    /// themselves — OMITTING the owner. The owner is locked out of that write epoch and CANNOT self-heal (they
    /// can't open an epoch they have no wrap for), so `backfill` (owner-authored) is powerless. Another member
    /// who holds a wrap heals it with `backfill_rrk`, adding the owner's missing `MemberHpke` wrap and restoring
    /// the owner's read.
    #[test]
    fn dag_backfill_rrk_lets_a_member_heal_the_owners_locked_out_epoch() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"correct horse");

        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);

        // bob is a CO-OWNER (authorized to author a Remove); carol is an editor bob will remove.
        let bob_pass = Passphrase::new(b"bobs own passphrase");
        let bob = member_secrets(&bob_pass);
        let bob_id = member_id_of(&bob);
        let a1 = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &acct(&ks, &owner_pass),
                &crate::vault::Joiner::from_bytes(
                    &MemberId::new(&bob_id),
                    KeyringRole::CO_OWNER,
                    &bob.root.identity.verifying_key().to_bytes(),
                    &bob.root.hpke_public,
                )
                .unwrap(),
            )
            .unwrap();
        let carol = member_secrets(&Passphrase::new(b"carol pass"));
        let (a2, carol_id) = admit_editor(&tree, &ks, &owner_pass, &a1, &carol);

        // Hostile co-owner: remove carol, but mint the forward-secret epoch wrapping ONLY bob — the owner is
        // OMITTED. A Remove-origin epoch is always eligible, so (highest ordinal) it becomes the write epoch.
        let new_dek = generate_dek().unwrap();
        let key_id = generate_salt().unwrap().to_vec();
        let bob_only =
            member_wrap_keyeo(&bob.root.hpke_public, &new_dek, TREE, &bob_id, &key_id).unwrap();
        let sealing = SealingPayload {
            new_epochs: vec![keyeo_crypto::Epoch {
                key_id: KeyeoKeyId::new(key_id.clone()),
                ordinal: 1,
                dek_commitment: keyeo_crypto::dek_commitment(&new_dek),
                wraps: vec![bob_only],
            }],
            added_wraps: vec![],
            escrow: None,
        }
        .to_bytes();
        let hostile =
            dag_client::append_remove(&a2, &bob_id, &carol_id, sealing, &bob.root.identity).unwrap();

        // The owner is missing from the write epoch → `needs_rrk_backfill` (the member-heal signal).
        assert!(
            fold_resolved(&dag_client::resolve(&hostile).unwrap())
                .unwrap()
                .needs_rrk_backfill,
            "the owner is missing from the hostile forward-secret epoch"
        );

        // bob seals data under the new write epoch he minted.
        let bob_mid = MemberId::new(&bob_id);
        let bob_rid = ReplicaId::new(b"rb");
        let bob_ctx = ctx(&tree, &bob_mid, &bob_rid);
        let (bob_u, _hp) = DagVault
            .unlock_as_member(&bob_ctx, &hostile, &bob_pass, &bob.pass_kdf)
            .unwrap();
        let data1 = bob_u
            .sealer
            .seal_entry(&SealContext::snapshot(1, Vec::new(), 0), b"post-removal, owner locked out")
            .unwrap()
            .envelope;

        // The owner unlocks but CANNOT reach the write epoch — locked out, cannot self-heal.
        let u_before = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &hostile, &acct(&ks, &owner_pass))
            .unwrap();
        assert!(
            u_before.write_epoch_unreachable,
            "the owner cannot reach the epoch that omitted their wrap"
        );
        assert!(
            u_before.sealer.open_entry(EntryKind::Snapshot, &data1).is_err(),
            "before the heal, the owner can't read the locked-out epoch"
        );

        // bob heals it: opens the epoch via his member wrap, adds the OWNER's missing `MemberHpke` wrap.
        let floor = dag_client::watermark(&hostile).unwrap();
        let healed = DagVault
            .backfill_rrk(&bob_ctx, &hostile, &bob_pass, &bob.pass_kdf, &floor)
            .unwrap();
        assert!(healed.backfilled, "the member backfilled the owner's missing wrap");
        assert!(
            !fold_resolved(&dag_client::resolve(&healed.anchor).unwrap())
                .unwrap()
                .needs_rrk_backfill,
            "the owner-lockout signal clears after the member heal"
        );

        // Now the owner reaches the once-locked-out epoch.
        let u_after = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r3")), &healed.anchor, &acct(&ks, &owner_pass))
            .unwrap();
        assert!(!u_after.write_epoch_unreachable, "the owner now reaches the write epoch");
        assert_eq!(
            u_after.sealer.open_entry(EntryKind::Snapshot, &data1).unwrap(),
            b"post-removal, owner locked out",
            "after the member heal, the owner reads the once-locked-out epoch"
        );
    }

    /// OPE-381 / F3 `DoS` bound, re-scoped for OPE-543 owner-as-member: one author may add at most
    /// `MAX_ADDED_WRAPS_PER_AUTHOR_PER_EPOCH_PER_RECIPIENT` HPKE wraps to a single epoch FOR A SINGLE RECIPIENT.
    /// A hostile member piling junk `MemberHpke` wraps addressed to the OWNER (to inflate the owner's per-unlock
    /// HPKE work — the A3 vector) is capped at fold time; the epoch's OWN minted owner wrap (in `new_epochs`,
    /// not `added_wraps`) is never counted, so baseline access is untouched.
    #[test]
    fn fold_caps_added_wraps_per_author_per_epoch_per_recipient() {
        let members = membership("owner", &["bob"]);
        // Genesis epoch k0 with the owner's minted member wrap + bob's member wrap.
        let genesis = sealing_entry(
            0,
            b"k0",
            0,
            dag_client::SealingOrigin::Genesis,
            vec![owner_wrap(), member_wrap("bob")],
            None,
        );
        // A single hostile op by "bob" piling on far more owner-addressed member wraps than the cap.
        let flood_count = MAX_ADDED_WRAPS_PER_AUTHOR_PER_EPOCH_PER_RECIPIENT * 3;
        let flood = dag_client::SealingEntry {
            op_id: [5u8; 32],
            origin: dag_client::SealingOrigin::Other,
            author: "bob".into(),
            bytes: SealingPayload {
                new_epochs: vec![],
                added_wraps: (0..flood_count)
                    .map(|_| AddedWrap {
                        key_id: b"k0".to_vec(),
                        wrap: owner_wrap(),
                    })
                    .collect(),
                escrow: None,
            }
            .to_bytes(),
        };
        let folded = fold_sealing(&[genesis, flood], &members).unwrap();
        let k0 = folded
            .epochs
            .iter()
            .find(|e| e.key_id.as_bytes() == b"k0")
            .unwrap();
        let owner_wraps = k0
            .wraps
            .iter()
            .filter(|w| {
                w.recipient == "owner" && matches!(w.method, KeyeoWrapMethod::MemberHpke { .. })
            })
            .count();
        assert_eq!(
            owner_wraps,
            1 + MAX_ADDED_WRAPS_PER_AUTHOR_PER_EPOCH_PER_RECIPIENT,
            "the genesis owner wrap plus bob's capped flood — the excess is dropped"
        );
    }

    /// OPE-543 2b — account-keystore-mediated passphrase change (durable identity). The change re-wraps the
    /// account blob under a new KEK with NO on-tree op: the tree anchor + watermark are unchanged, the running
    /// sealer keeps working, the new passphrase opens the tree via the re-wrapped keystore while the old one no
    /// longer opens the account, and the account recovery code (unchanged by a passphrase change) still recovers.
    #[test]
    fn dag_change_passphrase_then_unlock_and_still_recover() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");
        let new_pass = Passphrase::new(b"battery staple unicorn");

        let (ks, account_code, _u) = AccountKeystore::create(old_pass.expose()).unwrap();
        let p = DagVault
            .provision(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &ks.unlock(old_pass.expose()).unwrap(),
            )
            .unwrap();
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"keepsake")
            .unwrap()
            .envelope;

        // Change the passphrase = re-wrap the account keystore blob; the tree anchor + watermark are unchanged.
        let re = DagVault
            .change_passphrase(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &p.anchor,
                &ks.to_bytes().unwrap(),
                &old_pass,
                &new_pass,
                &p.watermark,
            )
            .unwrap();
        assert_eq!(re.anchor, p.anchor, "a passphrase change does not touch the tree anchor");
        assert_eq!(re.watermark, p.watermark, "nor the anti-rollback watermark");
        assert!(!re.keystore.is_empty(), "it returns the re-wrapped account keystore blob");

        // The NEW passphrase opens the tree via the re-wrapped account (DEK unchanged); the OLD one does not.
        let new_ks = AccountKeystore::from_bytes(&re.keystore).unwrap();
        let u = DagVault
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"r2")),
                &p.anchor,
                &new_ks.unlock(new_pass.expose()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"keepsake"
        );
        assert!(
            new_ks.unlock(old_pass.expose()).is_err(),
            "the pre-change passphrase no longer opens the account"
        );

        // Recovery still works via the account recovery code — a passphrase change does NOT rotate it.
        let r = DagVault
            .recover(
                &ctx(&tree, &member, &ReplicaId::new(b"r4")),
                &p.anchor,
                &re.keystore,
                &account_code,
                &Passphrase::new(b"a third passphrase"),
                &p.watermark,
            )
            .unwrap();
        assert_eq!(
            r.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"keepsake"
        );
    }

    /// The anti-rollback watermark is wired (OPE-284): unlock reports the anchor's frontier, a mutation past
    /// that floor advances the watermark, and serving the now-stale original anchor — whose op set is behind
    /// the advanced floor — is refused as a rollback.
    #[test]
    fn dag_watermark_advances_and_a_stale_anchor_is_refused() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let old_pass = Passphrase::new(b"correct horse");

        let (ks, p) = provision_owned(&tree, &member, &ReplicaId::new(b"r1"), &old_pass);
        let u = DagVault
            .unlock(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &p.anchor,
                &acct(&ks, &old_pass),
            )
            .unwrap();
        assert!(
            !u.watermark.is_empty(),
            "unlock reports the frontier watermark, not a stub"
        );

        // A floor-enforcing mutation (a forced reseal) gated on the unlock floor advances the watermark.
        // (OPE-543: the anti-rollback wiring is engine-level and orthogonal to the owner-as-member sealing —
        // exercised via `reseal`, a green flow, since credential-change is deferred to the durable-identity
        // increment.)
        let re = DagVault
            .reseal(
                &ctx(&tree, &member, &ReplicaId::new(b"r1")),
                &p.anchor,
                &acct(&ks, &old_pass),
                &u.watermark,
                ResealTrigger::Force,
            )
            .unwrap();
        assert!(re.resealed, "the forced reseal appended an op");
        assert_ne!(
            re.watermark, u.watermark,
            "a keyring change advances the watermark"
        );

        // Serving the ORIGINAL anchor now — its op set is behind the advanced floor — is a rollback.
        let rolled_back = DagVault.reseal(
            &ctx(&tree, &member, &ReplicaId::new(b"r1")),
            &p.anchor,
            &acct(&ks, &old_pass),
            &re.watermark,
            ResealTrigger::Force,
        );
        assert!(
            matches!(rolled_back, Err(VaultError::WatermarkRollback { .. })),
            "a stale anchor below the floor is refused"
        );

        // A corrupt floor (not a multiple of 32 bytes) is refused, not silently ignored.
        let bad_floor = DagVault.reseal(
            &ctx(&tree, &member, &ReplicaId::new(b"r1")),
            &re.anchor,
            &acct(&ks, &old_pass),
            &[1, 2, 3],
            ResealTrigger::Force,
        );
        assert!(
            matches!(bad_floor, Err(VaultError::MalformedWatermark)),
            "a corrupt floor is refused"
        );
    }

    /// The owner adds a member: the joiner appears in the resolved keyring, their per-epoch wrap is minted,
    /// and the owner's own access is unaffected (they still unlock + open the data).
    #[test]
    fn dag_add_member_wraps_the_dek_and_the_owner_still_unlocks() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");

        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &pass);
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"shared secret")
            .unwrap()
            .envelope;

        // bob's OOB-verified keys: a real HPKE public key so the wrap succeeds, and a real Ed25519 author
        // key so `Joiner::from_bytes` accepts it. His member id SELF-CERTIFIES that author key (OPE-543).
        let HpkeKeypair {
            public: bob_hpke, ..
        } = generate_hpke_keypair().unwrap();
        let bob_author = edsign::SigningKey::from_seed(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let bob_id = derive_member_id(&bob_author);

        let new_anchor = DagVault
            .add_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &p.anchor,
                &acct(&ks, &pass),
                &crate::vault::Joiner::from_bytes(
                    &MemberId::new(&bob_id),
                    KeyringRole::EDITOR,
                    &bob_author,
                    &bob_hpke,
                )
                .unwrap(),
            )
            .unwrap();

        // bob is now a member of the resolved keyring.
        let resolved = dag_client::resolve(&new_anchor).unwrap();
        assert!(
            resolved
                .members
                .members
                .iter()
                .any(|m| m.member_id == bob_id),
            "the added member appears in the resolved keyring"
        );

        // The owner's own access is unaffected: they still unlock the new anchor and open the data.
        let u = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &new_anchor,
                &acct(&ks, &pass),
            )
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"shared secret"
        );
    }

    /// Phase C (OPE-351): the dag writer attaches an author to every entry once the tree HAS BEEN SHARED —
    /// the write side of attributed writes, mirroring the chain. A never-shared solo dag writes unattributed;
    /// once a member is admitted both the owner and the member sign, each attributed to their own member id.
    #[test]
    fn dag_writer_signs_iff_the_tree_has_been_shared() {
        use openom_protocol::{v1::Envelope, Message};
        use openom_sealer::SealerSet;
        let seal_header = |sealer: &SealerSet, plaintext: &[u8]| {
            Envelope::decode(
                sealer
                    .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), plaintext)
                    .unwrap()
                    .envelope
                    .as_slice(),
            )
            .unwrap()
            .header
            .unwrap()
        };

        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");

        // Solo (never shared): the sealer attaches no author → entries are unattributed.
        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);
        assert!(
            seal_header(&p.sealer, b"solo edit")
                .author_signature
                .is_empty(),
            "a never-shared dag writes unattributed"
        );

        // First share — admit bob (self-cert member id).
        let bob_pass = Passphrase::new(b"bobs own passphrase");
        let bob = member_secrets(&bob_pass);
        let (new_anchor, bob_id) = admit_editor(&tree, &ks, &owner_pass, &p.anchor, &bob);
        // The owner's ON-TREE attribution id is their SELF-CERTIFYING derived id (not `ctx.member_id`).
        let owner_id = dag_client::resolve(&new_anchor)
            .unwrap()
            .members
            .owner()
            .unwrap()
            .member_id
            .clone();

        // Owner unlock on the shared anchor: now signs, attributed to the owner's derived id.
        let u_owner = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &new_anchor,
                &acct(&ks, &owner_pass),
            )
            .unwrap();
        let owner_h = seal_header(&u_owner.sealer, b"owner edit");
        assert!(
            !owner_h.author_signature.is_empty(),
            "shared dag: owner signs"
        );
        assert_eq!(owner_h.author_member_id, owner_id);

        // Member unlock: bob signs as himself.
        let bob_mid = MemberId::new(&bob_id);
        let (u_member, _) = DagVault
            .unlock_as_member(
                &ctx(&tree, &bob_mid, &ReplicaId::new(b"r-bob")),
                &new_anchor,
                &bob_pass,
                &bob.pass_kdf,
            )
            .unwrap();
        let member_h = seal_header(&u_member.sealer, b"member edit");
        assert!(
            !member_h.author_signature.is_empty(),
            "shared dag: member signs"
        );
        assert_eq!(member_h.author_member_id, bob_id);
    }

    /// §B3 verify-on-ingest over the dag engine (OPE-382 / §8.2): a real shared-dag `DagMembershipResolver` accepts a
    /// signed owner entry, rejects a forged unsigned one, and — the epoch-set fix — STILL accepts an entry
    /// sealed under a PRIOR epoch after a forward-secret rotation, rather than `EpochMismatch`-rejecting it.
    #[test]
    fn dag_verify_ingest_accepts_signed_and_prior_epoch_entries_rejects_forgeries() {
        use crate::verify::dag::DagMembershipResolver;
        use crate::{verify_ingest, Disposition, MembershipResolver};
        use openom_protocol::{v1::Envelope, Message};
        use openom_sealer::SealContext;

        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");

        // Provision, then SHARE (add bob) so the tree requires attribution and the owner signs.
        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);
        let bob_pass = Passphrase::new(b"bobs own passphrase");
        let bob = member_secrets(&bob_pass);
        let (shared, bob_id) = admit_editor(&tree, &ks, &owner_pass, &p.anchor, &bob);

        // The owner seals an entry under the CURRENT (first) epoch.
        let u = DagVault
            .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"r2")), &shared, &acct(&ks, &owner_pass))
            .unwrap();
        let sealed = u
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"owner edit")
            .unwrap()
            .envelope;
        let env = Envelope::decode(sealed.as_slice()).unwrap();
        let header = env.header.clone().unwrap();
        assert!(!header.author_signature.is_empty(), "the shared-tree owner signs");

        let verify = |m: &DagMembershipResolver, h: &openom_protocol::v1::Header| {
            verify_ingest(env.version, m, h, &h.governing_ref, &h.key_id, || {
                Ok::<_, ()>(b"owner edit".to_vec())
            })
        };

        // Verified against the shared anchor it was sealed under: ACCEPT.
        let m0 = DagMembershipResolver::new(&shared).unwrap();
        assert!(m0.shared());
        assert_eq!(verify(&m0, &header), Disposition::Accept);

        // A forged UNSIGNED entry on the shared tree is REJECTED.
        let mut forged = header.clone();
        forged.author_signature.clear();
        assert_eq!(verify(&m0, &forged), Disposition::Reject);

        // Remove bob → a forward-secret re-epoch rotates the write epoch, but the entry's PRIOR epoch stays
        // retained. The old signed entry must STILL verify against the new anchor (accept any retained epoch),
        // where a single-current-epoch resolver would wrongly EpochMismatch-reject it.
        let rotated = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r3")),
                &shared,
                &acct(&ks, &owner_pass),
                &bob_id,
            )
            .unwrap();
        let m1 = DagMembershipResolver::new(&rotated).unwrap();
        assert_eq!(
            verify(&m1, &header),
            Disposition::Accept,
            "a prior-epoch entry is accepted after a rotation, not EpochMismatch-rejected"
        );
    }

    /// The full shared-tree cycle: the owner adds bob, and bob unlocks with HIS OWN passphrase + account
    /// KDF (reaching the DEK through his member HPKE wrap, not the RRK) and reads the shared data.
    #[test]
    fn dag_added_member_unlocks_with_their_own_account_and_reads() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");

        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);
        let sealed = p
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"family data")
            .unwrap()
            .envelope;

        // bob's account: identity + HPKE + KDF derived from his own passphrase.
        let bob_pass = Passphrase::new(b"bobs own passphrase");
        let bob = member_secrets(&bob_pass);
        let bob_author = bob.root.identity.verifying_key().to_bytes();
        let (new_anchor, bob_id_str) = admit_editor(&tree, &ks, &owner_pass, &p.anchor, &bob);

        // bob unlocks with his own passphrase + account KDF and reads the shared data.
        let bob_id = MemberId::new(&bob_id_str);
        let (u, _) = DagVault
            .unlock_as_member(
                &ctx(&tree, &bob_id, &ReplicaId::new(b"r-bob")),
                &new_anchor,
                &bob_pass,
                &bob.pass_kdf,
            )
            .unwrap();
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"family data"
        );
        assert_eq!(u.did_key, DidKey::from_public_key(&bob_author));
        assert!(
            !u.watermark.is_empty(),
            "a member unlock reports the frontier watermark too"
        );

        // A wrong passphrase for bob is rejected (anti-substitution against his resolved key).
        assert!(DagVault
            .unlock_as_member(
                &ctx(&tree, &bob_id, &ReplicaId::new(b"r-bob")),
                &new_anchor,
                &Passphrase::new(b"not bobs passphrase"),
                &bob.pass_kdf,
            )
            .is_err());
    }

    /// Removing a member mints a forward-secret epoch: the removed member can no longer unlock, and the
    /// owner reads post-removal data sealed under the new epoch.
    #[test]
    fn dag_remove_member_forward_secret_epoch_locks_them_out() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");
        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);

        let bob_pass = Passphrase::new(b"bobs passphrase");
        let bob = member_secrets(&bob_pass);
        let (a1, bob_id_str) = admit_editor(&tree, &ks, &owner_pass, &p.anchor, &bob);
        let bob_id = MemberId::new(&bob_id_str);
        assert!(
            DagVault
                .unlock_as_member(
                    &ctx(&tree, &bob_id, &ReplicaId::new(b"rb")),
                    &a1,
                    &bob_pass,
                    &bob.pass_kdf
                )
                .is_ok(),
            "bob can read before removal"
        );

        let a2 = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a1,
                &acct(&ks, &owner_pass),
                &bob_id_str,
            )
            .unwrap();

        assert!(
            DagVault
                .unlock_as_member(
                    &ctx(&tree, &bob_id, &ReplicaId::new(b"rb")),
                    &a2,
                    &bob_pass,
                    &bob.pass_kdf
                )
                .is_err(),
            "a removed member can no longer unlock"
        );

        // The owner unlocks the new anchor and reads post-removal data sealed under the forward-secret epoch.
        let u = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &a2,
                &acct(&ks, &owner_pass),
            )
            .unwrap();
        let post = u
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"post-removal")
            .unwrap()
            .envelope;
        assert_eq!(
            u.sealer.open_entry(EntryKind::Snapshot, &post).unwrap(),
            b"post-removal"
        );
    }

    /// End-to-end OPE-282: two CONCURRENT removals leave the merged write epoch stale (it still wraps the
    /// member the losing branch removed); unlock flags `needs_reseal`; `reseal` mints a covering fresh epoch
    /// so the flag clears and the owner keeps working; and a second reseal is an idempotent no-op.
    #[test]
    fn reseal_repairs_a_stale_write_epoch_after_concurrent_removals() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let owner_pass = Passphrase::new(b"owner passphrase");
        let (ks, p) = provision_owned(&tree, &owner, &ReplicaId::new(b"r1"), &owner_pass);

        // Add bob + carol as editors (self-cert member ids derived from their keys).
        let bob = member_secrets(&Passphrase::new(b"bob pass"));
        let carol = member_secrets(&Passphrase::new(b"carol pass"));
        let (a1, bob_id) = admit_editor(&tree, &ks, &owner_pass, &p.anchor, &bob);
        let (a2, carol_id) = admit_editor(&tree, &ks, &owner_pass, &a1, &carol);

        // Two CONCURRENT removals from a2 (both parent on the same frontier): A removes bob, B removes carol.
        let branch_a = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a2,
                &acct(&ks, &owner_pass),
                &bob_id,
            )
            .unwrap();
        let branch_b = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a2,
                &acct(&ks, &owner_pass),
                &carol_id,
            )
            .unwrap();
        let merged = dag_client::merge(&branch_a, &branch_b).unwrap();

        // The merged write epoch is stale — it still wraps whichever member the losing branch removed.
        let u = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &merged,
                &acct(&ks, &owner_pass),
            )
            .unwrap();
        assert!(
            u.needs_reseal,
            "concurrent removals leave the write epoch stale"
        );

        // Reseal mints a covering fresh epoch; the flag clears and the owner writes + reads under it.
        let r = DagVault
            .reseal(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &merged,
                &acct(&ks, &owner_pass),
                &[],
                ResealTrigger::WhenStale,
            )
            .unwrap();
        assert!(r.resealed, "a stale write epoch is repaired");
        let u2 = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &r.anchor,
                &acct(&ks, &owner_pass),
            )
            .unwrap();
        assert!(
            !u2.needs_reseal,
            "after reseal the write epoch covers the resolved membership"
        );
        let sealed = u2
            .sealer
            .seal_entry(&SealContext::snapshot(0, Vec::new(), 0), b"after reseal")
            .unwrap()
            .envelope;
        assert_eq!(
            u2.sealer.open_entry(EntryKind::Snapshot, &sealed).unwrap(),
            b"after reseal"
        );

        // Idempotent: a second reseal finds nothing stale and is a no-op.
        let r2 = DagVault
            .reseal(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &r.anchor,
                &acct(&ks, &owner_pass),
                &[],
                ResealTrigger::WhenStale,
            )
            .unwrap();
        assert!(!r2.resealed, "nothing stale -> reseal is a no-op");

        // Force: past the idempotent gate a covering reseal still fires (the local-unreachability escape
        // hatch, OPE-299) — nothing is stale, yet Force mints a fresh covering epoch the owner can write under.
        let r3 = DagVault
            .reseal(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &r.anchor,
                &acct(&ks, &owner_pass),
                &[],
                ResealTrigger::Force,
            )
            .unwrap();
        assert!(r3.resealed, "Force reseals even when nothing is stale");
        let u3 = DagVault
            .unlock(
                &ctx(&tree, &owner, &ReplicaId::new(b"r2")),
                &r3.anchor,
                &acct(&ks, &owner_pass),
            )
            .unwrap();
        assert!(
            !u3.needs_reseal && !u3.write_epoch_unreachable,
            "the forced reseal leaves a clean, locally-reachable write epoch"
        );
    }

    /// OPE-543 owner-as-member: unlock authenticates via the durable ACCOUNT identity — the passphrase gates the
    /// keystore at the APP layer (not the vault), so the vault-level rejection is of a FOREIGN account: an
    /// account whose identity is not the resolved owner's can't open the tree, even though it is itself valid.
    #[test]
    fn dag_unlock_rejects_a_foreign_account() {
        let tree = TreeId::new(TREE);
        let member = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"correct horse");
        let (_ks, p) = provision_owned(&tree, &member, &ReplicaId::new(b"r"), &pass);
        // A DIFFERENT account (a stranger): its identity is not the resolved owner's, so unlock fails closed at
        // the anti-substitution check.
        let stranger_pass = Passphrase::new(b"stranger");
        let stranger = owner_ks(&stranger_pass);
        assert!(
            DagVault
                .unlock(
                    &ctx(&tree, &member, &ReplicaId::new(b"r")),
                    &p.anchor,
                    &acct(&stranger, &stranger_pass),
                )
                .is_err(),
            "a foreign account does not open the dag vault"
        );
    }

    /// OPE-543 A4 regression — the OWNER-COVERAGE LOCKSTEP safety net (the flagged trap). The owner is a
    /// resolved member whose id is in `required` AND is wrapped in EVERY retained (minted) epoch at provision,
    /// `add_member`, reseal, and a member removal's forward-secret epoch — so a freshly-provisioned or -mutated
    /// tree NEVER leaves the owner `write_epoch_unreachable` or flagged `needs_rrk_backfill`, and the owner
    /// opens every epoch. If ANY owner-exclusion site were missed the owner would be silently, permanently
    /// locked out — this test would then fail at that stage.
    #[test]
    fn a4_owner_is_covered_in_every_minted_epoch_and_never_unreachable() {
        let tree = TreeId::new(TREE);
        let owner = MemberId::new(MEMBER);
        let pass = Passphrase::new(b"owner passphrase");
        // The owner's durable account keystore, created once; every owner-authored op below re-derives a fresh
        // `UnlockedAccount` from it (the app-layer pattern).
        let ks = owner_ks(&pass);

        // At `stage`: the owner id is in `required`; the owner has a current-key `MemberHpke` wrap in EVERY
        // retained epoch; the fold does not flag the owner locked out; `unlock` reaches the write epoch and
        // opens every epoch DEK; and `reset_authority` is None.
        let assert_owner_covered = |anchor: &[u8], stage: &str| {
            let resolved = dag_client::resolve(anchor).unwrap();
            let owner_id = resolved.members.owner().unwrap().member_id.clone();
            let owner_key = resolved.members.owner().unwrap().hpke_public_key.clone();
            let folded = fold_resolved(&resolved).unwrap();

            let required = member_descriptors(&resolved.members);
            assert!(
                required.iter().any(|d| d.id == owner_id),
                "{stage}: the owner is in `required`"
            );
            for ep in &folded.epochs {
                assert!(
                    ep.wraps.iter().any(|w| w.recipient == owner_id
                        && matches!(&w.method,
                            KeyeoWrapMethod::MemberHpke { recipient_key, .. }
                                if recipient_key.as_ref() == owner_key.as_slice())),
                    "{stage}: the owner is wrapped (current key) in every minted epoch"
                );
            }
            assert!(
                !folded.needs_rrk_backfill,
                "{stage}: the owner is not locked out of any retained epoch"
            );
            let u = DagVault
                .unlock(&ctx(&tree, &owner, &ReplicaId::new(b"ra")), anchor, &acct(&ks, &pass))
                .unwrap();
            assert!(
                !u.write_epoch_unreachable,
                "{stage}: unlock never reports write_epoch_unreachable"
            );
            assert_eq!(
                DagVault.resolved_reset_authority(anchor).unwrap(),
                None,
                "{stage}: reset_authority stays None (owner-as-member has no recovery authority)"
            );
        };

        // provision
        let p = DagVault
            .provision(&ctx(&tree, &owner, &ReplicaId::new(b"r1")), &acct(&ks, &pass))
            .unwrap();
        assert_eq!(
            DagVault.resolved_reset_authority(&p.anchor).unwrap(),
            None,
            "provision yields reset_authority == None"
        );
        assert_owner_covered(&p.anchor, "provision");

        // add_member
        let bob = member_secrets(&Passphrase::new(b"bob pass"));
        let (a1, bob_id) = admit_editor(&tree, &ks, &pass, &p.anchor, &bob);
        assert_owner_covered(&a1, "add_member");

        // reseal (forced, mints a fresh covering epoch)
        let re = DagVault
            .reseal(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &a1,
                &acct(&ks, &pass),
                &[],
                ResealTrigger::Force,
            )
            .unwrap();
        assert!(re.resealed, "the forced reseal minted an epoch");
        assert_owner_covered(&re.anchor, "reseal");

        // remove_member forward-secret epoch
        let a2 = DagVault
            .remove_member(
                &ctx(&tree, &owner, &ReplicaId::new(b"r1")),
                &re.anchor,
                &acct(&ks, &pass),
                &bob_id,
            )
            .unwrap();
        assert_owner_covered(&a2, "remove_member");
    }
}
