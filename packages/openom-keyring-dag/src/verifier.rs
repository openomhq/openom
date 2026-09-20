//! The DAG keyring's [`KeyringVerifier`] adapter (OPE-277) — the keyless server-side seam.
//!
//! `admit(prior_state, update)` reconstructs the resolver from the opaque trust state (pinned genesis +
//! the op closure), applies the new op, and reports the resolved [`MembershipView`] + whether membership
//! changed. This is where the DAG's admit-then-resolve model meets the seam's anchor/view vocabulary:
//! - a validly-signed op the resolver gives no effect resolves to `changed = false` — the seam's honest
//!   no-op case, which chain never has;
//! - the anti-rollback state lives INSIDE the opaque `state` bytes (the op closure), never a shared field;
//! - a `ReFound` / `RotateRecoveryAuthority` admission sets `reset_boundary` (the server's cooldown gate).
//!
//! State + update are the engine's own opaque encoding (the seam never inspects them). The op bytes are
//! the SAME `blob_sync` codec the transport publishes, so an op verifies identically however it arrived.

use keyeo_dag::{ApplyOutcome, Error as KeyeoError, Keyeo, MembershipAction, SignedOp, StrongRemove};
use openom_keyring_api::{Admitted, KeyringVerifier, MemberView, MembershipView, VerifyError};
use serde::{Deserialize, Serialize};

use crate::blob_sync::{decode_op, dto_to_minit, minit_to_dto, MemberInitDto};
use crate::{KeyringAccess, KeyringEngine, KeyringMemberInit, KeyringState};

/// The genesis facts a replica trusts out-of-band (first-sight pin): the founding membership + the
/// recovery authority. Both engines pin these; here they seed the resolver's construction base.
#[derive(Serialize, Deserialize)]
struct PinnedConfig {
    /// The group (tree) id the engine's genesis is scoped to. Taken from the signed genesis op at
    /// bootstrap, so every replayed op — whose signed `group_id` must match — is gated to this tree; a
    /// tampered value fails closed (the signed ops won't match).
    #[serde(default)]
    group_id: Vec<u8>,
    genesis: Vec<MemberInitDto>,
    reset_authority: Option<[u8; 32]>,
}

/// The DAG's opaque trust state: the pinned config + the admitted op closure (each entry the `blob_sync`
/// op encoding). The keyring channel uses `Retention::Never`, so at family scale this stays small.
#[derive(Serialize, Deserialize)]
struct DagTrustState {
    pinned: PinnedConfig,
    ops: Vec<Vec<u8>>,
}

/// One admitted update. `Bootstrap` seeds first sight (pinned config + the genesis op); `Op` is every
/// subsequent op. The variant must match the presence of prior state.
#[derive(Serialize, Deserialize)]
enum UpdateDto {
    Bootstrap { pinned: PinnedConfig, genesis_op: Vec<u8> },
    Op { op: Vec<u8> },
}

/// The DAG keyring's keyless verifier. Holds no secrets and no state — everything comes in via
/// `prior_state`/`update` and goes out via the returned opaque state, exactly as the seam requires.
#[derive(Clone, Copy, Debug, Default)]
pub struct DagVerifier;

impl DagVerifier {
    fn build(pinned: &PinnedConfig) -> KeyringEngine {
        let genesis: Vec<KeyringMemberInit> = pinned.genesis.iter().map(dto_to_minit).collect();
        let base = KeyringState::create(keyeo_dag::GroupId::new(pinned.group_id.clone()), &genesis)
            .with_reset_authority(pinned.reset_authority);
        Keyeo::new(base, KeyringAccess, StrongRemove)
    }

    /// Replay the stored (already-admitted) op closure onto a fresh engine. These were valid when first
    /// admitted, so a failure here is a corrupt/tampered state blob, not a new refusal.
    fn replay(engine: &mut KeyringEngine, ops: &[Vec<u8>]) -> Result<(), VerifyError> {
        for bytes in ops {
            let op = decode_op(bytes).map_err(|_| VerifyError::Malformed)?;
            engine.apply(op).map_err(|_| VerifyError::Malformed)?;
        }
        engine.flush().map_err(|_| VerifyError::Malformed)?;
        Ok(())
    }
}

pub(crate) fn view_of(state: &KeyringState, reset_boundary: bool) -> MembershipView {
    let members = state
        .members
        .iter()
        .filter(|(_, m)| m.is_active())
        .map(|(id, m)| MemberView {
            member_id: id.clone(),
            role: m.role.0,
            author_public_key: m.author_public_key.to_vec(),
            hpke_public_key: m.hpke_public_key.to_vec(),
        })
        .collect();
    MembershipView::new(members, reset_boundary)
}

/// Map a keyeo apply error/outcome to a neutral [`VerifyError`] for the NEW op (stored ops use `replay`).
// A value->value conversion of the owned apply result; taking `&` would force a borrow dance for no gain.
#[allow(clippy::needless_pass_by_value)]
fn classify(outcome: Result<ApplyOutcome<String, [u8; 32]>, KeyeoError<String>>) -> Result<(), VerifyError> {
    match outcome {
        Ok(ApplyOutcome::Applied { .. }) => Ok(()),
        // Missing a parent op — the update references history the verifier hasn't been given (re-fetch).
        Ok(ApplyOutcome::Buffered { .. }) => Err(VerifyError::Stale),
        Err(KeyeoError::BadSignature | KeyeoError::UnknownAuthor { .. }) => {
            Err(VerifyError::Unauthenticated)
        }
        Err(KeyeoError::StaleFork) => Err(VerifyError::Rollback),
        Err(_) => Err(VerifyError::Malformed),
    }
}

fn encode_state(state: &DagTrustState) -> Vec<u8> {
    postcard::to_allocvec(state).expect("DagTrustState serialization is infallible")
}

impl KeyringVerifier for DagVerifier {
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError> {
        let upd: UpdateDto = postcard::from_bytes(update).map_err(|_| VerifyError::Malformed)?;
        match (prior_state, upd) {
            // First sight: seed the pinned config + the (inert, per OPE-271) genesis op as the root.
            (None, UpdateDto::Bootstrap { pinned, genesis_op }) => {
                // OPE-543 (A2): the server trusts `PinnedConfig.genesis` to seed the base — an admission path
                // the resolver's Add/Create gate never runs against. Re-enforce the self-cert binding here:
                // a pinned genesis member whose id does not derive from its carried author key is refused.
                for m in pinned.genesis.iter().map(dto_to_minit) {
                    if !crate::member_id_binds_key(&m.id, m.author_public_key.as_ref()) {
                        return Err(VerifyError::Malformed);
                    }
                }
                let mut engine = Self::build(&pinned);
                let op = decode_op(&genesis_op).map_err(|_| VerifyError::Malformed)?;
                let update_ref = op.id().to_vec();
                classify(engine.apply(op))?;
                engine.flush().map_err(|_| VerifyError::Malformed)?;
                let view = view_of(engine.state(), false);
                // The tree id from the VERIFIED resolved state (bound into every op's signature; survives the
                // genesis Create fold), never from an unsigned side channel.
                let tree_id = engine.state().group_id.0.clone();
                let state = encode_state(&DagTrustState { pinned, ops: vec![genesis_op] });
                Ok(Admitted { state, view, changed: true, tree_id, update_ref })
            }
            // Every subsequent op: replay the closure, resolve before + after, diff the membership.
            (Some(prior), UpdateDto::Op { op: op_bytes }) => {
                let st: DagTrustState =
                    postcard::from_bytes(prior).map_err(|_| VerifyError::Malformed)?;
                let mut engine = Self::build(&st.pinned);
                Self::replay(&mut engine, &st.ops)?;
                let before = view_of(engine.state(), false).members;

                let op = decode_op(&op_bytes).map_err(|_| VerifyError::Malformed)?;
                let op_id = op.id();
                let is_reset = matches!(
                    op.action(),
                    MembershipAction::ReFound { .. } | MembershipAction::RotateRecoveryAuthority { .. }
                );
                classify(engine.apply(op))?;
                // (a) vs (b): an op unauthorized AT ITS CAUSAL POSITION is permanently ineffective on
                // every branch — refuse it (anti-spam), which is convergence-safe because no honest client
                // ever gives it effect. An op that merely lost a concurrent race is authorized-at-position
                // and MUST be kept (it may stand on a branch that hasn't seen the invalidator) — that is
                // the genuine admit-then-resolve no-op (changed=false), the case the chain can't represent.
                if engine.authorized_at_position(&op_id) == Some(false) {
                    return Err(VerifyError::Unauthorized);
                }
                engine.flush().map_err(|_| VerifyError::Malformed)?;

                let view = view_of(engine.state(), is_reset);
                let changed = view.members != before;
                let tree_id = engine.state().group_id.0.clone();
                let update_ref = op_id.to_vec();
                let mut ops = st.ops;
                ops.push(op_bytes);
                let state = encode_state(&DagTrustState { pinned: st.pinned, ops });
                Ok(Admitted { state, view, changed, tree_id, update_ref })
            }
            // A bootstrap against existing state, or an op with no prior state — malformed sequencing.
            _ => Err(VerifyError::Malformed),
        }
    }
}

/// Build a `Bootstrap` update from the pinned genesis + the signed genesis op — the first-sight input a
/// server (or client adoption path) admits.
///
/// (Helper for callers/tests; the seam itself never constructs
/// updates.)
///
/// # Panics
/// Never in practice: the built `UpdateDto` always serializes.
pub fn bootstrap_update(
    genesis: &[KeyringMemberInit],
    reset_authority: Option<[u8; 32]>,
    genesis_op: &crate::KeyringOp,
) -> Vec<u8> {
    let dto = UpdateDto::Bootstrap {
        pinned: PinnedConfig {
            // The group id comes from the signed genesis op — the authentic value every replayed op is
            // gated against (never trusted from an unsigned side channel).
            group_id: genesis_op.group_id.0.clone(),
            genesis: genesis.iter().map(minit_to_dto).collect(),
            reset_authority,
        },
        genesis_op: crate::blob_sync::encode_op(genesis_op),
    };
    postcard::to_allocvec(&dto).expect("UpdateDto serialization is infallible")
}

/// Build an `Op` update from a signed op — every non-genesis admission.
///
/// # Panics
/// Never in practice: the built `UpdateDto` always serializes.
#[must_use]
pub fn op_update(op: &crate::KeyringOp) -> Vec<u8> {
    let dto = UpdateDto::Op {
        op: crate::blob_sync::encode_op(op),
    };
    postcard::to_allocvec(&dto).expect("UpdateDto serialization is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_op, KeyringMemberInit, KeyringRole};
    use keyeo_dag::MemberInit;

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    /// OPE-543: fixture member ids are the self-certifying `uuid8` of their own author key.
    fn mid(seed: u8) -> String {
        openom_keyring_api::derive_member_id(&vk(seed))
    }
    fn minit(role: KeyringRole, seed: u8) -> KeyringMemberInit {
        MemberInit {
            id: mid(seed),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }
    fn add(role: KeyringRole, seed: u8) -> crate::KeyringAction {
        MembershipAction::Add {
            member: mid(seed),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
            member_proof: None,
        }
    }
    fn create(members: &[KeyringMemberInit]) -> crate::KeyringAction {
        MembershipAction::Create { initial_members: members.to_vec() }
    }

    #[test]
    fn dag_verifier_folds_admitted_ops_into_a_membership_view() {
        let v = DagVerifier;
        let gm = vec![minit(KeyringRole::OWNER, 1)];
        let genesis_op = sign_op([1; 32], vec![], mid(1), create(&gm), &sk(1));
        // bootstrap
        let boot = v
            .admit(None, &bootstrap_update(&gm, None, &genesis_op))
            .unwrap();
        assert!(boot.changed);
        assert_eq!(boot.view.members.len(), 1);
        assert_eq!(boot.view.owner().unwrap().member_id, mid(1));

        // founder adds bob as a co-owner
        let add_bob = sign_op([2; 32], vec![[1; 32]], mid(1), add(KeyringRole::CO_OWNER, 2), &sk(1));
        let step = v.admit(Some(&boot.state), &op_update(&add_bob)).unwrap();
        assert!(step.changed, "adding a member changes the view");
        let mut ids: Vec<String> = step.view.members.iter().map(|m| m.member_id.clone()).collect();
        ids.sort();
        let mut expected = vec![mid(1), mid(2)];
        expected.sort();
        assert_eq!(ids, expected);
        assert_eq!(step.view.signers().count(), 2, "both are signers");
    }

    #[test]
    fn a_permanently_unauthorized_op_is_refused_not_admitted() {
        // dave is a Maintainer (never a signer), so his add is unauthorized AT ITS CAUSAL POSITION —
        // permanently ineffective on every branch. The verifier REFUSES it (anti-spam), where a naive
        // admit-then-resolve would keep it as a no-op that just wastes space.
        let v = DagVerifier;
        let gm = vec![
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::MAINTAINER, 4),
        ];
        let genesis_op = sign_op([1; 32], vec![], mid(1), create(&gm), &sk(1));
        let boot = v.admit(None, &bootstrap_update(&gm, None, &genesis_op)).unwrap();
        let daves_add = sign_op([2; 32], vec![[1; 32]], mid(4), add(KeyringRole::EDITOR, 9), &sk(4));
        assert_eq!(
            v.admit(Some(&boot.state), &op_update(&daves_add)).unwrap_err(),
            VerifyError::Unauthorized,
            "an op unauthorized at its causal position is refused, not kept as a no-op"
        );
    }

    #[test]
    fn an_op_that_lost_a_concurrent_race_is_admitted_as_a_no_op() {
        // The genuine admit-then-resolve no-op the chain can't represent. bob (a co-owner) adds carol on
        // one branch while the founder CONCURRENTLY removes bob on another. bob's add WAS authorized at
        // its position, so it is kept (changed=false), NOT refused — a replica on the branch that hasn't
        // seen the removal needs it to converge.
        let v = DagVerifier;
        let gm = vec![
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
        ];
        let genesis_op = sign_op([1; 32], vec![], mid(1), create(&gm), &sk(1));
        let boot = v.admit(None, &bootstrap_update(&gm, None, &genesis_op)).unwrap();

        let remove_bob = sign_op([2; 32], vec![[1; 32]], mid(1), MembershipAction::Remove { member: mid(2) }, &sk(1));
        let s1 = v.admit(Some(&boot.state), &op_update(&remove_bob)).unwrap();

        // bob's add is a child of genesis — concurrent with his own removal.
        let bob_adds_carol = sign_op([3; 32], vec![[1; 32]], mid(2), add(KeyringRole::EDITOR, 3), &sk(2));
        let out = v.admit(Some(&s1.state), &op_update(&bob_adds_carol)).unwrap();
        assert!(!out.changed, "bob's concurrently-invalidated add is admitted as a no-op, not refused");
        assert!(!out.view.members.iter().any(|m| m.member_id == mid(3)), "and carol is not added");
    }

    #[test]
    fn a_genesis_with_a_bad_signature_is_refused() {
        // The genesis Create authenticates against its own initial_members' key (founder = vk(1)), but this
        // op is signed by an unrelated key — the engine must reject it, and `classify` must map that to an
        // error rather than admitting it. (A classify that always returned Ok would admit a forged genesis.)
        let v = DagVerifier;
        let gm = vec![minit(KeyringRole::OWNER, 1)];
        let bad = sign_op([1; 32], vec![], mid(1), create(&gm), &sk(9));
        assert!(
            v.admit(None, &bootstrap_update(&gm, None, &bad)).is_err(),
            "a bad-signature genesis must not be admitted"
        );
    }

    #[test]
    fn a_bootstrap_with_a_non_self_certifying_pinned_member_is_refused() {
        // OPE-543 (A2): the server seeds its base from `PinnedConfig.genesis`, an admission path the resolver
        // never gates. A pinned genesis member whose id is not the uuid8 of its carried author key must be
        // refused at bootstrap, else a forged binding would enter the trusted base.
        let v = DagVerifier;
        // A well-signed genesis, but the pinned member id does not derive from its key.
        let forged = KeyringMemberInit {
            id: "aaaaaaaa-aaaa-8aaa-8aaa-aaaaaaaaaaaa".to_string(),
            role: KeyringRole::OWNER,
            author_public_key: vk(1),
            hpke_public_key: [1; 32],
        };
        let gm = vec![forged.clone()];
        let genesis_op = sign_op([1; 32], vec![], forged.id.clone(), create(&gm), &sk(1));
        assert_eq!(
            v.admit(None, &bootstrap_update(&gm, None, &genesis_op)).unwrap_err(),
            VerifyError::Malformed,
            "a pinned genesis member whose id does not bind its key is refused"
        );
    }
}
