//! Feature-parity capability matrix: the linear chain keyring (openom-keyring / chain.rs) vs the DAG
//! keyring (openom-keyring-dag / keyeo), across both backend classes (OPE-267).
//!
//! The honest answer to "what does each version actually offer" is a MATRIX, not prose. Both keyrings
//! ride the same `store_blob::Blob` seam, so the backend axis is {managed-CAS, BYO-dumb} — and because
//! the seam is the weakest-common-denominator (per-object CAS + list), every capability below behaves
//! IDENTICALLY on both backend classes for a given keyring; a managed backend only *prevents* below the
//! seam what a BYO backend can merely *detect* (the anti-rollback row). So the matrix's live axis is the
//! keyring, and the backend axis collapses to one behavioural note (rollback: prevent vs detect).
//!
//! This file adds the concurrency axis — the DAG's signature capability the linear chain structurally
//! cannot offer — as executable assertions. (OPE-543: member ids are the self-certifying `uuid8` of their
//! author key, so fixtures derive each id from its seed via [`mid`].)

use edsign::SigningKey;
use keyeo_dag::{Keyeo, MemberInit, MembershipAction, StrongRemove};
use openom_keyring_dag::{
    sign_op, KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringRole, KeyringState,
};

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}
fn pk32(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn mid(seed: u8) -> String {
    openom_keyring_dag::derive_member_id(&pk32(&sk(seed)))
}
fn minit(role: KeyringRole, seed: u8) -> KeyringMemberInit {
    MemberInit {
        id: mid(seed),
        role,
        author_public_key: pk32(&sk(seed)),
        hpke_public_key: [seed; 32],
    }
}
fn engine(members: &[KeyringMemberInit]) -> KeyringEngine {
    Keyeo::new(
        KeyringState::create(keyeo_dag::GroupId::unscoped(), members),
        KeyringAccess,
        StrongRemove,
    )
}
fn add(
    role: KeyringRole,
    seed: u8,
) -> MembershipAction<String, KeyringRole, openom_keyring_dag::Ed25519> {
    MembershipAction::Add {
        member: mid(seed),
        role,
        author_public_key: pk32(&sk(seed)),
        hpke_public_key: [seed; 32],
        member_proof: None,
    }
}
fn has(k: &KeyringEngine, seed: u8) -> bool {
    let id = mid(seed);
    k.state().active_members().iter().any(|(m, _)| m == &id)
}

/// Concurrency row (non-conflicting): two co-owners, offline on different branches, each add a DIFFERENT
/// ordinary member — a genuine fork. The DAG merges both branches deterministically and keeps both adds.
/// This is the row the linear chain cannot match: its single-head CAS serializes the two writes, so the
/// second writer's revision is stale and must be rebuilt + re-proposed (safe, but not a merge).
#[test]
fn dag_merges_non_conflicting_concurrent_edits_where_the_chain_would_serialize() {
    let cast = [
        minit(KeyringRole::OWNER, 1),
        minit(KeyringRole::CO_OWNER, 2),
        minit(KeyringRole::CO_OWNER, 3),
    ];
    // Two engines diverge from the same genesis, each learning one side of the fork, then exchange.
    let mut ea = engine(&cast);
    let mut eb = engine(&cast);
    let g = sign_op(
        [1; 32],
        vec![],
        mid(1),
        MembershipAction::Create {
            initial_members: cast.to_vec(),
        },
        &sk(1),
    );
    ea.apply(g.clone()).unwrap();
    eb.apply(g.clone()).unwrap();

    // bob adds dave on A; carol adds erin on B — concurrent children of genesis, different authors.
    let dave = sign_op(
        [2; 32],
        vec![[1; 32]],
        mid(2),
        add(KeyringRole::EDITOR, 4),
        &sk(2),
    );
    let erin = sign_op(
        [3; 32],
        vec![[1; 32]],
        mid(3),
        add(KeyringRole::EDITOR, 5),
        &sk(3),
    );
    ea.apply(dave.clone()).unwrap();
    eb.apply(erin.clone()).unwrap();
    // exchange the other side of the fork
    ea.apply(erin).unwrap();
    eb.apply(dave).unwrap();

    for e in [&ea, &eb] {
        assert!(
            has(e, 4) && has(e, 5),
            "the DAG merges both concurrent adds — neither is lost"
        );
    }
    assert_eq!(
        ea.state().active_members(),
        eb.state().active_members(),
        "and both replicas converge"
    );
}

/// Concurrency row (multi-signer under a fork): a quorum threshold is met by approvals that arrive on a
/// FORK — the proposer proposes on one branch, an approver approves on a concurrent branch, and the DAG
/// still tallies them once merged. The chain's draft-exchange can collect the same signatures but a
/// competing head revision forces a re-propose; the DAG merges the approvals across the fork.
#[test]
fn dag_tallies_quorum_approvals_that_arrive_on_a_fork() {
    use openom_keyring_dag::{KeyringQuorum, KeyringQuorumEngine};
    let cast = [
        minit(KeyringRole::OWNER, 1),
        minit(KeyringRole::CO_OWNER, 2),
        minit(KeyringRole::CO_OWNER, 3),
        minit(KeyringRole::EDITOR, 6),
    ];
    let mut k: KeyringQuorumEngine = Keyeo::with_quorum(
        KeyringState::create(keyeo_dag::GroupId::unscoped(), &cast),
        KeyringAccess,
        StrongRemove,
        KeyringQuorum::threshold(3),
    );
    let sign = |id: u8, parents: Vec<[u8; 32]>, author: String, seed: u8, act| {
        sign_op([id; 32], parents, author, act, &sk(seed))
    };
    k.apply(sign(
        1,
        vec![],
        mid(1),
        1,
        MembershipAction::Create {
            initial_members: cast.to_vec(),
        },
    ))
    .unwrap();
    let promote = MembershipAction::ChangeRole {
        member: mid(6),
        new_role: KeyringRole::CO_OWNER,
    };
    // propose on the main line, then TWO approvals on concurrent branches off the proposal.
    k.apply(sign(
        2,
        vec![[1; 32]],
        mid(2),
        2,
        MembershipAction::Propose {
            proposal_id: [7; 32],
            target: Box::new(promote),
        },
    ))
    .unwrap();
    k.apply(sign(
        3,
        vec![[2; 32]],
        mid(3),
        3,
        MembershipAction::Approve {
            proposal_id: [7; 32],
        },
    ))
    .unwrap();
    k.apply(sign(
        4,
        vec![[2; 32]],
        mid(1),
        1,
        MembershipAction::Approve {
            proposal_id: [7; 32],
        },
    ))
    .unwrap();
    // commit references both concurrent approvals in its causal past.
    k.apply(sign(
        5,
        vec![[3; 32], [4; 32]],
        mid(2),
        2,
        MembershipAction::Commit {
            proposal_id: [7; 32],
        },
    ))
    .unwrap();

    assert_eq!(
        k.state()
            .members
            .get(&mid(6))
            .filter(|m| m.is_active())
            .map(|m| m.role),
        Some(KeyringRole::CO_OWNER),
        "3-of-4 approvals arriving across a fork are tallied and the promotion takes effect"
    );
}
