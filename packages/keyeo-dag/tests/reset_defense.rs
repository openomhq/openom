//! Generic resolver-defense regression: the reset-merge carve-out + the OPE-381 recovery-rotation takeover
//! defense (the key-provenance taint), exercised at the **keyeo-dag layer** with a permissive test
//! [`AccessControl`].
//!
//! These invariants used to be covered only by openom-keyring-dag's `KeyringAccess` tests. Under durable
//! identity (OPE-543) the openom domain policy stops AUTHORIZING `ReFound`/`RotateRecoveryAuthority`/`Retarget`
//! entirely, so those openom-level tests are removed — but the generic machinery they exercised
//! (`reset_merge_carveout` + `propagate_key_taint` in `strong_remove.rs`, and the `key_matches_registration`
//! recovery/rotation branches in `resolver.rs`) STAYS in keyeo-dag for reuse by future work and MUST stay
//! covered. This file is that coverage, moved down to the engine with a policy that still authorizes the
//! recovery ops (what a permissive consumer would do), so the carve-out and taint keep being proven.
//!
//! The generic model: member id == its author public key ([`pk`]); the "founder" is an `Admin` (the sole
//! signer role for these tests). `ReFound` is authorized by the pinned `reset_authority` (resolver-side);
//! `RotateRecoveryAuthority`/`Retarget` by the author's current registered key. The permissive
//! [`PermissiveAccess`] mirrors openom's `is_privileged` classification (authority-structure ops are
//! privileged) so the carve-out fires exactly as it did at the openom layer.

use keyeo_dag::dag::resolver::{GroupState, MembershipAction};
use keyeo_dag::dag::strong_remove::StrongRemove;
use keyeo_dag::{AccessControl, Ed25519, GroupId, Keyeo, MemberInit, Op, Role};
use proptest::prelude::*;

/// Three-role test lattice; `Admin` is the sole signer (openom's Owner/CoOwner collapse to it here).
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
enum TestRole {
    Admin,
    Editor,
    Viewer,
}
impl Role for TestRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        use TestRole::{Admin, Editor, Viewer};
        matches!(
            (self, other),
            (Admin, _) | (Editor, Editor | Viewer) | (Viewer, Viewer)
        )
    }
}
impl TestRole {
    const fn is_signer(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

type Action = MembershipAction<[u8; 32], TestRole, Ed25519>;
type TestOp = Op<u64, [u8; 32], TestRole, Ed25519>;
type Engine = Keyeo<TestOp, PermissiveAccess, StrongRemove>;

/// A permissive policy: any active `Admin` may author, and the authority-structure ops are `is_privileged`
/// (so the reset-merge carve-out voids one that is concurrent with a surviving recovery). It intentionally
/// authorizes `ReFound`/`Rotate`/`Retarget` — the resolver's `key_matches_registration` does the real
/// recovery/rotation gating — so the generic carve-out + taint stay exercised, exactly as they were under
/// openom's pre-OPE-543 `KeyringAccess`.
struct PermissiveAccess;

impl AccessControl<[u8; 32], TestRole, Ed25519> for PermissiveAccess {
    fn is_authorized(
        &self,
        state: &GroupState<[u8; 32], TestRole, Ed25519>,
        author: &[u8; 32],
        action: &Action,
    ) -> bool {
        match action {
            MembershipAction::Create { initial_members } => {
                initial_members.iter().any(|m| &m.id == author)
            }
            // A `ReFound` is authored as the (member) owner id but signed by the recovery key; the owner id is
            // an active Admin, so it clears the domain gate and the resolver's reset_authority branch decides.
            _ => state.has_access(author, &TestRole::Admin),
        }
    }

    fn is_privileged(
        &self,
        state: &GroupState<[u8; 32], TestRole, Ed25519>,
        action: &Action,
    ) -> bool {
        let role_of = |id: &[u8; 32]| {
            state
                .members
                .get(id)
                .map_or(TestRole::Viewer, |m| m.role.clone())
        };
        match action {
            MembershipAction::Add { role, .. } => role.is_signer(),
            MembershipAction::ChangeRole { member, new_role } => {
                new_role.is_signer() || role_of(member).is_signer()
            }
            MembershipAction::Remove { member } | MembershipAction::Retarget { member, .. } => {
                role_of(member).is_signer()
            }
            MembershipAction::Propose { .. }
            | MembershipAction::Approve { .. }
            | MembershipAction::Commit { .. }
            | MembershipAction::ReFound { .. }
            | MembershipAction::RotateRecoveryAuthority { .. } => true,
            MembershipAction::Reseal | MembershipAction::Create { .. } => false,
        }
    }
}

fn kp(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> [u8; 32] {
    kp(seed).verifying_key().to_bytes()
}
fn minit(seed: u8, role: TestRole) -> MemberInit<[u8; 32], TestRole, Ed25519> {
    MemberInit {
        id: pk(seed),
        role,
        author_public_key: pk(seed),
        hpke_public_key: [seed; 32],
    }
}

/// Mint an op whose MEMBER-id author is `author` but which is SIGNED by `signer` (they differ for a
/// recovery `ReFound`, where the owner id is the author and the recovery key is the signer). The op carries
/// the signer's public key as `author_public_key`, exactly as the transport would.
fn op(id: u64, parents: Vec<u64>, author: [u8; 32], signer: &ed25519_dalek::SigningKey, action: Action) -> TestOp {
    Op::new(
        id,
        GroupId::unscoped(),
        parents,
        author,
        action,
        [0u8; 64],
        signer.verifying_key().to_bytes(),
    )
    .sign(signer)
}

fn refound(new_seed: u8) -> Action {
    MembershipAction::ReFound {
        member: pk(1),
        new_author_public_key: pk(new_seed),
        new_hpke_public_key: [new_seed; 32],
        era: 1,
    }
}
fn add(seed: u8, role: TestRole) -> Action {
    MembershipAction::Add {
        member: pk(seed),
        role,
        author_public_key: pk(seed),
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}
fn rotate(new_authority: &ed25519_dalek::SigningKey) -> Action {
    MembershipAction::RotateRecoveryAuthority {
        new_reset_authority: new_authority.verifying_key().to_bytes(),
    }
}

/// A `StrongRemove` engine seeded with `genesis` + the RVK pinned, plus the (inert) genesis `Create` op.
fn engine(genesis: &[MemberInit<[u8; 32], TestRole, Ed25519>], rvk_pub: [u8; 32]) -> Engine {
    let mut k = Keyeo::new(
        GroupState::create(GroupId::unscoped(), genesis).with_reset_authority(Some(rvk_pub)),
        PermissiveAccess,
        StrongRemove,
    );
    k.apply(op(
        1,
        vec![],
        pk(1),
        &kp(1),
        MembershipAction::Create { initial_members: genesis.to_vec() },
    ))
    .unwrap();
    k
}

fn owner_key(k: &Engine) -> [u8; 32] {
    k.state().members.get(&pk(1)).unwrap().author_public_key
}
fn is_member(k: &Engine, seed: u8) -> bool {
    k.state().members.contains_key(&pk(seed))
}

// ── reset-merge carve-out ──

#[test]
fn an_ordinary_member_add_concurrent_with_recovery_auto_merges() {
    // Never lose an innocent edit: an ordinary (non-signer) add concurrent with a recovery re-founding is
    // NOT privileged, so it is not carved out — both survive.
    let rvk = kp(42);
    let mut k = engine(&[minit(1, TestRole::Admin), minit(2, TestRole::Admin)], rvk.verifying_key().to_bytes());
    k.apply(op(2, vec![1], pk(2), &kp(2), add(5, TestRole::Editor))).unwrap();
    k.apply(op(3, vec![1], pk(1), &rvk, refound(7))).unwrap();
    assert!(is_member(&k, 5), "an ordinary add concurrent with recovery auto-merges");
    assert_eq!(owner_key(&k), pk(7), "the owner is recovered");
}

#[test]
fn a_privileged_op_concurrent_with_recovery_is_voided_but_a_later_owner_op_stands() {
    // The carve-out: a signer add (privileged) concurrent with a surviving recovery is voided — precisely the
    // escalation a recovery defends against. A post-recovery signer add on the NEW key still stands.
    let rvk = kp(42);
    let mut k = engine(&[minit(1, TestRole::Admin), minit(2, TestRole::Admin)], rvk.verifying_key().to_bytes());
    k.apply(op(2, vec![1], pk(1), &kp(1), add(9, TestRole::Admin))).unwrap();
    k.apply(op(3, vec![1], pk(1), &rvk, refound(7))).unwrap();
    assert!(!is_member(&k, 9), "a signer add concurrent with the recovery is carve-out-voided");
    assert_eq!(owner_key(&k), pk(7), "the owner is recovered");
    assert!(is_member(&k, 2), "the innocent co-owner is untouched");
    // Post-recovery, the recovered owner (new key sk(7)) adds a signer — not concurrent with the recovery.
    k.apply(op(4, vec![3], pk(1), &kp(7), add(3, TestRole::Admin))).unwrap();
    assert!(is_member(&k, 3), "the recovered owner governs normally on the new key");
}

#[test]
fn reset_merge_converges_regardless_of_arrival_order() {
    // BEC: two replicas seeing the thief-add and the recovery in opposite orders converge identically.
    let rvk = kp(42);
    let rvk_pub = rvk.verifying_key().to_bytes();
    let genesis = [minit(1, TestRole::Admin), minit(2, TestRole::Admin)];
    let thief = op(2, vec![1], pk(1), &kp(1), add(9, TestRole::Admin));
    let recovery = op(3, vec![1], pk(1), &rvk, refound(7));

    let mut k1 = engine(&genesis, rvk_pub);
    k1.apply(thief.clone()).unwrap();
    k1.apply(recovery.clone()).unwrap();

    let mut k2 = engine(&genesis, rvk_pub);
    k2.apply(recovery).unwrap();
    k2.apply(thief).unwrap();

    assert_eq!(k1.state().active_members(), k2.state().active_members(), "converges regardless of order");
    assert_eq!(owner_key(&k1), owner_key(&k2), "the recovered owner key converges");
    assert!(!is_member(&k1, 9), "the carve-out held in both orders");
}

// ── OPE-381 recovery-rotation takeover defense (key-provenance taint) ──

#[test]
fn a_concurrent_refound_ladder_cannot_hijack_a_rotation() {
    // An attacker holding ONLY the leaked recovery key rvk1 cannot take over: (F) a concurrent ReFound
    // retargeting the founder to the attacker key, then (R_att) a child rotation signed by that just-registered
    // key. The owner's identity-gated rotation R survives and voids F (carve-out rule b); the key-provenance
    // taint then voids R_att (its key-registrar is the voided F).
    let rvk1 = kp(42); // leaked recovery key the attacker holds
    let rvk2 = kp(43); // the owner's fresh authority
    let rvk_att = kp(44); // the authority the attacker tries to install
    let mut k = engine(&[minit(1, TestRole::Admin)], rvk1.verifying_key().to_bytes());
    // R — owner's identity-gated rotation to rvk2 (signed by the owner's member key sk(1)).
    k.apply(op(2, vec![1], pk(1), &kp(1), rotate(&rvk2))).unwrap();
    // F — attacker ReFound → vk(9), CONCURRENT with R, signed by the leaked rvk1.
    k.apply(op(3, vec![1], pk(1), &rvk1, refound(9))).unwrap();
    // R_att — attacker rotation to rvk_att, authored as the founder, signed by vk(9)=sk(9) (F's registered key).
    k.apply(op(4, vec![3], pk(1), &kp(9), rotate(&rvk_att))).unwrap();

    assert_eq!(owner_key(&k), pk(1), "F is carve-out-voided — the founder key is unchanged");
    assert_eq!(
        k.state().reset_authority,
        Some(rvk2.verifying_key().to_bytes()),
        "the owner's rotation stands; R_att is taint-voided"
    );
    assert_ne!(
        k.state().reset_authority,
        Some(rvk_att.verifying_key().to_bytes()),
        "the attacker never installs its own recovery authority"
    );
}

proptest! {
    /// Grinding resistance: for NO assignment of the three ops' ids does the ladder win (the winner tiebreak
    /// is `(depth, op-id)`, and an attacker controls their ops' ids).
    #[test]
    fn no_op_id_lets_the_rotation_ladder_win(
        r_id in 2u64..1_000_000,
        f_id in 2u64..1_000_000,
        ratt_id in 2u64..1_000_000,
    ) {
        prop_assume!(r_id != f_id && r_id != ratt_id && f_id != ratt_id);
        let rvk1 = kp(42);
        let rvk2 = kp(43);
        let rvk_att = kp(44);
        let mut k = engine(&[minit(1, TestRole::Admin)], rvk1.verifying_key().to_bytes());
        k.apply(op(r_id, vec![1], pk(1), &kp(1), rotate(&rvk2))).unwrap();
        k.apply(op(f_id, vec![1], pk(1), &rvk1, refound(9))).unwrap();
        k.apply(op(ratt_id, vec![f_id], pk(1), &kp(9), rotate(&rvk_att))).unwrap();

        prop_assert_eq!(owner_key(&k), pk(1), "attacker never captures the founder key");
        prop_assert_eq!(
            k.state().reset_authority,
            Some(rvk2.verifying_key().to_bytes()),
            "the owner's rotation stands for any id assignment"
        );
        prop_assert_ne!(
            k.state().reset_authority,
            Some(rvk_att.verifying_key().to_bytes()),
            "the attacker never installs its authority for any id assignment"
        );
    }

    /// Determinism (K2): the defense is order-INDEPENDENT and holds for a DEEPER ladder — R (owner rotation),
    /// F (attacker concurrent ReFound), then a 3-level ladder off F: G (a self-Retarget signed by F's key),
    /// then H (a rotation signed by G's key). Applied in ANY arrival order (buffer then flush), the attacker
    /// loses: F is carve-out-voided and the taint fixpoint voids G (registrar F) and H (registrar G). This is
    /// the deepest taint ladder — the coverage that disappears from the openom layer with `Retarget`.
    #[test]
    fn the_ladder_defense_is_order_independent(
        order in Just((0..5usize).collect::<Vec<usize>>()).prop_shuffle(),
    ) {
        let rvk1 = kp(42);
        let rvk2 = kp(43);
        let rvk_att = kp(44);
        let ops = [
            op(1, vec![], pk(1), &kp(1), MembershipAction::Create { initial_members: vec![minit(1, TestRole::Admin)] }),
            // R — owner rotation to rvk2, identity-signed.
            op(2, vec![1], pk(1), &kp(1), rotate(&rvk2)),
            // F — attacker ReFound (founder → vk(9)), concurrent with R, signed by leaked rvk1.
            op(3, vec![1], pk(1), &rvk1, refound(9)),
            // G — attacker self-Retarget (founder → vk(10)), signed by vk(9)=sk(9), child of F.
            op(4, vec![3], pk(1), &kp(9), MembershipAction::Retarget {
                member: pk(1),
                new_author_public_key: pk(10),
                new_hpke_public_key: [10; 32],
            }),
            // H — attacker rotation to rvk_att, signed by vk(10)=sk(10), child of G.
            op(5, vec![4], pk(1), &kp(10), rotate(&rvk_att)),
        ];
        let mut k = Keyeo::new(
            GroupState::create(GroupId::unscoped(), &[minit(1, TestRole::Admin)])
                .with_reset_authority(Some(rvk1.verifying_key().to_bytes())),
            PermissiveAccess,
            StrongRemove,
        );
        for &i in &order {
            let _ = k.apply(ops[i].clone());
        }
        let _ = k.flush();

        prop_assert_eq!(owner_key(&k), pk(1), "founder key is owner-controlled under every arrival order");
        prop_assert_eq!(
            k.state().reset_authority,
            Some(rvk2.verifying_key().to_bytes()),
            "the owner's rotation stands under every arrival order (3-level ladder voided)"
        );
        prop_assert_ne!(
            k.state().reset_authority,
            Some(rvk_att.verifying_key().to_bytes()),
            "the attacker's ladder never installs its authority under any order"
        );
    }
}
