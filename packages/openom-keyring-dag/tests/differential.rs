//! Differential oracle: the DAG keyring (openom-keyring-dag / keyeo) vs the legacy CAS keyring
//! (openom-keyring / chain.rs), on a fork-free sequence — the "CAS = degenerate DAG" acceptance gate.
//!
//! For a shared cast + a single logical mutation, we drive BOTH systems and compare — chain.rs builds
//! the successor `Keyring` + `verify_transition` (accept/reject), keyeo `sign_op`s the equivalent
//! `MembershipAction` + `apply`s it (did the target member change?) — and assert they AGREE, except at
//! the two documented v1 divergences (self-removal widen; unanimity is v2), which are asserted as
//! *expected* divergences so the oracle stays honest.
//!
//! OPE-543: a member id is the self-certifying `uuid8` of its author key, so every id is derived from its
//! seed via [`mid`] (both engines carry the same id — the chain treats it as an opaque label). Recovery is
//! no longer an on-tree op for openom (a `ReFound` is unauthorized at the openom layer), so the recovery
//! differential rows are retired; the generic recovery machinery is proven in keyeo-dag's `reset_defense`.

use keyeo_dag::{Keyeo, MemberInit, MembershipAction, StrongRemove};
use openom_keyring_chain::{keyring_hash, sign_keyring, verify_transition, KeyringAnchor};
use openom_keyring_dag::{
    derive_member_id, sign_op, KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringRole,
    KeyringState,
};
use openom_protocol::v1::MemberRole;
use openom_keyring_chain::wire::{Keyring, Member};
use keyeo_crypto::{
    codec, Epoch as KeyeoEpoch, EncappedKey, KeyId, Wrap as KeyeoWrap,
    WrapMethod as KeyeoWrapMethod, WrappedDek, X25519PublicKey,
};
use openom_roles::{MEMBER_CO_OWNER, MEMBER_OWNER};
use edsign::SigningKey;

const TREE: &[u8] = b"tree-uuid-16byte";
const RRK_HPKE: i32 = KeyeoWrapMethod::TAG_RRK_HPKE;
const HPKE: i32 = KeyeoWrapMethod::TAG_MEMBER_HPKE;
const MAINTAINER: i32 = MemberRole::Admin as i32; // UI: "Maintainer"
const EDITOR: i32 = MemberRole::Editor as i32;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}
fn pubv(k: &SigningKey) -> Vec<u8> {
    k.verifying_key().to_bytes().to_vec()
}
fn pk32(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
/// The self-certifying member id for a seed's author key.
fn mid(seed: u8) -> String {
    derive_member_id(&pk32(&sk(seed)))
}

// ── one cast description, projected into both systems ──
struct Cast {
    seed: u8,
    /// Proto `MemberRole` value (drives both the chain member role and the keyeo `KeyringRole`). The chain
    /// signer set is DERIVED from this (a member at `CO_OWNER` or stronger is a signer, OPE-309), so there is
    /// no separate signer-role axis.
    member_role: i32,
}

fn keyed_member(seed: u8, role: i32) -> Member {
    Member { member_id: mid(seed), role, author_public_key: pubv(&sk(seed)), hpke_public_key: vec![9; 32] }
}
fn wrap(id: &str, method: i32) -> KeyeoWrap<String> {
    let encapped = EncappedKey::from_bytes([0u8; 32]);
    let recipient_key = X25519PublicKey::from_bytes([9u8; 32]);
    let m = if method == RRK_HPKE {
        KeyeoWrapMethod::RrkHpke { encapped, recipient_key }
    } else {
        KeyeoWrapMethod::MemberHpke { encapped, recipient_key }
    };
    KeyeoWrap { recipient: id.into(), method: m, ciphertext: WrappedDek::from_bytes([1u8; 48]) }
}

/// The chain.rs genesis keyring for a cast (cast[0] is the founder: RRK-wrapped, FOUNDER signer).
fn chain_genesis(cast: &[Cast]) -> Keyring {
    let mut members = Vec::new();
    let mut wraps = Vec::new();
    for (i, c) in cast.iter().enumerate() {
        members.push(keyed_member(c.seed, c.member_role));
        wraps.push(wrap(&mid(c.seed), if i == 0 { RRK_HPKE } else { HPKE }));
    }
    let mut g = Keyring {
        tree_id: TREE.to_vec(),
        revision: 1,
        layout_version: 1,
        prev_keyring_hash: vec![],
        members,
        signatures: vec![],
        recovery_keys: vec![],
        epochs: codec::encode_epochs(&[KeyeoEpoch { key_id: KeyId::new(vec![0]), ordinal: 0, dek_commitment: [0u8; 32], wraps }]),
        ..Default::default()
    };
    sign_keyring(&mut g, &sk(cast[0].seed)); // founder signs genesis
    g
}

/// A well-formed chain.rs successor: revision+1, chained hash, `mutate` applied, signed by `sign_with`.
fn chain_next(prior: &Keyring, mutate: impl FnOnce(&mut Keyring), sign_with: &[u8]) -> Keyring {
    let mut k = prior.clone();
    k.revision = prior.revision + 1;
    k.prev_keyring_hash = keyring_hash(prior).to_vec();
    mutate(&mut k);
    k.signatures.clear();
    for &seed in sign_with {
        sign_keyring(&mut k, &sk(seed));
    }
    k
}

/// The keyeo engine for the same cast (constructor genesis; the single-axis `KeyringRole` = `MemberRole`).
fn keyeo_engine(cast: &[Cast]) -> KeyringEngine {
    let inits: Vec<KeyringMemberInit> = cast
        .iter()
        .map(|c| MemberInit {
            id: mid(c.seed),
            role: KeyringRole(i16::try_from(c.member_role).unwrap()),
            author_public_key: pk32(&sk(c.seed)),
            hpke_public_key: [c.seed; 32],
        })
        .collect();
    Keyeo::new(KeyringState::create(keyeo_dag::GroupId::unscoped(), &inits), KeyringAccess, StrongRemove)
}

fn keyeo_has(k: &KeyringEngine, seed: u8) -> bool {
    let id = mid(seed);
    k.state().active_members().iter().any(|(m, _)| *m == id)
}

/// The keyeo `Add` action for a seed at a role (the member id self-certifies against seed's key).
fn dag_add(seed: u8, role: KeyringRole) -> MembershipAction<String, KeyringRole, openom_keyring_dag::Ed25519> {
    MembershipAction::Add {
        member: mid(seed),
        role,
        author_public_key: pk32(&sk(seed)),
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}

fn founder() -> Cast {
    Cast { seed: 1, member_role: MEMBER_OWNER }
}
fn co_owner(seed: u8) -> Cast {
    Cast { seed, member_role: MEMBER_CO_OWNER }
}
fn plain(seed: u8, role: i32) -> Cast {
    Cast { seed, member_role: role }
}

// ────────────────────────────── AGREEMENT cases ──────────────────────────────

#[test]
fn founder_adds_a_co_owner_agrees() {
    // A founder-signed signer-set change: both accept and both gain the co-owner.
    let cast = [founder()];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            // A CO_OWNER-role member IS a signer (derived from members) — no separate roster push.
            k.members.push(keyed_member(5, MEMBER_CO_OWNER));
            push_wrap(k, wrap(&mid(5), HPKE));
        },
        &[1], // founder signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], mid(1), dag_add(5, KeyringRole::CO_OWNER), &sk(1)))
        .unwrap();

    assert!(chain_ok, "chain.rs accepts a founder-signed co-owner add");
    assert!(keyeo_has(&k, 5), "keyeo adds the co-owner");
}

#[test]
fn a_co_owner_adds_an_ordinary_member_agrees() {
    // Ordinary change (signer set unchanged) signed by a co-owner: both accept.
    let cast = [founder(), co_owner(2)];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.push(keyed_member(3, EDITOR));
            push_wrap(k, wrap(&mid(3), HPKE));
        },
        &[2], // co-owner bob signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], mid(2), dag_add(3, KeyringRole::EDITOR), &sk(2)))
        .unwrap();

    assert!(chain_ok, "chain.rs accepts a co-owner-signed ordinary add");
    assert!(keyeo_has(&k, 3), "keyeo adds the ordinary member");
}

#[test]
fn a_non_signer_cannot_write_agrees() {
    // dave is a keyed Maintainer member but NOT a signer. His attempt to add a member is rejected by
    // chain.rs (UnendorsedOrdinaryChange) and is a no-op in keyeo (unauthorized). Both: carol absent.
    let cast = [founder(), plain(4, MAINTAINER)];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.push(keyed_member(3, EDITOR));
            push_wrap(k, wrap(&mid(3), HPKE));
        },
        &[4], // dave (a non-signer) signs
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], mid(4), dag_add(3, KeyringRole::EDITOR), &sk(4)))
        .unwrap();

    assert!(!chain_ok, "chain.rs rejects a non-signer's change");
    assert!(!keyeo_has(&k, 3), "keyeo: a non-signer's add has no effect");
}

#[test]
fn founder_cannot_self_remove_agrees() {
    // Removing the sole founder empties the founder slot → chain.rs check_structure rejects; keyeo
    // forbids the Owner leaving. Both: the founder remains.
    let cast = [founder()];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            // Removing the owner member removes the derived founder signer too.
            k.members.retain(|m| m.member_id != mid(1));
            retain_wraps(k, |w| w.recipient != mid(1));
        },
        &[1],
    );
    let chain_ok = verify_transition(&anchor, &cand).is_ok();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], mid(1), MembershipAction::Remove { member: mid(1) }, &sk(1)))
        .unwrap();

    assert!(!chain_ok, "chain.rs rejects removing the sole founder");
    assert!(keyeo_has(&k, 1), "keyeo: the Owner cannot self-remove");
}

// ────────────────────────────── DOCUMENTED DIVERGENCE ──────────────────────────────

#[test]
fn ordinary_self_removal_is_the_documented_v1_widen() {
    // An ordinary member self-removing: chain.rs treats it as an ordinary change needing a SIGNER's
    // endorsement (the member's own key isn't a signer) → REJECT. keyeo v1 deliberately WIDENS this:
    // any non-Owner may self-remove (BYO/offline). Asserted as an EXPECTED divergence (decision B.2).
    let cast = [founder(), plain(6, EDITOR)];
    let g = chain_genesis(&cast);
    let anchor = KeyringAnchor::from_keyring(&g);
    let cand = chain_next(
        &g,
        |k| {
            k.members.retain(|m| m.member_id != mid(6));
            retain_wraps(k, |w| w.recipient != mid(6));
        },
        &[6], // ed signs their own removal — but ed is not a signer
    );
    let chain_rejects = verify_transition(&anchor, &cand).is_err();

    let mut k = keyeo_engine(&cast);
    k.apply(sign_op([2u8; 32], vec![], mid(6), MembershipAction::Remove { member: mid(6) }, &sk(6)))
        .unwrap();
    let keyeo_removed = !keyeo_has(&k, 6);

    assert!(chain_rejects, "chain.rs requires a signer to endorse an ordinary member's removal");
    assert!(keyeo_removed, "keyeo v1 widens self-removal to any non-Owner");
}

// ── chain epoch-wrap helpers (used by the mutations above) ──

fn epochs_of(k: &Keyring) -> Vec<KeyeoEpoch<String>> {
    k.key_material().unwrap()
}
fn set_epochs(k: &mut Keyring, epochs: &[KeyeoEpoch<String>]) {
    k.epochs = codec::encode_epochs(epochs);
}
fn push_wrap(k: &mut Keyring, w: KeyeoWrap<String>) {
    let mut eps = epochs_of(k);
    eps[0].wraps.push(w);
    set_epochs(k, &eps);
}
fn retain_wraps(k: &mut Keyring, keep: impl Fn(&KeyeoWrap<String>) -> bool) {
    let mut eps = epochs_of(k);
    eps[0].wraps.retain(|w| keep(w));
    set_epochs(k, &eps);
}
