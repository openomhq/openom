//! Keyless admission for the self-contained DAG anchor transported by the managed `/keyring` channel.
//!
//! The op-at-a-time [`crate::verifier::DagVerifier`] remains the primitive verifier. This adapter serves
//! the distribution contract used by clients: each server revision contains a complete anchor, allowing a
//! fresh device to restore from the latest revision without reconstructing a separate op journal.

use openom_keyring_api::{
    Admitted, EngineKind, KeyringVerifier, MembershipEnvelope, MembershipView, VerifyError,
};

use crate::client::{
    accept_remote_anchor, anchor_pin, crosses_reset_boundary, group_id, resolve, verify_anchor,
    watermark, ClientError,
};

/// Verifies and merges a self-contained DAG anchor without holding any secret key material.
#[derive(Clone, Copy, Debug, Default)]
pub struct DagAnchorVerifier;

// Owned error adapter for direct use with `Result::map_err` at every client-facade call site.
#[allow(clippy::needless_pass_by_value)]
fn classify(error: ClientError) -> VerifyError {
    match error {
        ClientError::RolledBack(_) => VerifyError::Rollback,
        ClientError::Engine(_) => VerifyError::Unauthenticated,
        ClientError::Malformed(_) | ClientError::BadWatermark(_) => VerifyError::Malformed,
    }
}

fn unwrap(bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let envelope = MembershipEnvelope::decode(bytes).map_err(|_| VerifyError::Malformed)?;
    if envelope.engine_kind() != Ok(EngineKind::Dag) {
        return Err(VerifyError::Malformed);
    }
    Ok(envelope.body)
}

fn wrap(anchor: Vec<u8>) -> Vec<u8> {
    MembershipEnvelope::wrap(EngineKind::Dag, anchor).encode()
}

impl KeyringVerifier for DagAnchorVerifier {
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError> {
        let candidate = unwrap(update)?;
        let candidate_group = group_id(&candidate).map_err(classify)?;

        let (state, previous_view, reset_boundary) = if let Some(prior_state) = prior_state {
            let prior = unwrap(prior_state)?;
            let prior_group = group_id(&prior).map_err(classify)?;
            if prior_group != candidate_group {
                return Err(VerifyError::Malformed);
            }
            let previous = resolve(&prior).map_err(classify)?.members;
            let pin = anchor_pin(&prior).map_err(classify)?;
            let floor = watermark(&prior).map_err(classify)?;
            let reset = crosses_reset_boundary(&prior, &candidate).map_err(classify)?;
            let merged = accept_remote_anchor(&prior, &candidate, &prior_group, &pin, &floor)
                .map_err(classify)?;
            (merged, Some(previous), reset)
        } else {
            // First sight is intentionally self-signed, like chain genesis. Deriving the pin from the
            // candidate does not add outside trust; verify_anchor still checks signatures, content ids,
            // self-certifying member ids, and that the pinned genesis DTO matches the signed Create op.
            let pin = anchor_pin(&candidate).map_err(classify)?;
            verify_anchor(&candidate, &candidate_group, &pin).map_err(classify)?;
            (candidate, None, false)
        };

        let resolved = resolve(&state).map_err(classify)?;
        let changed = previous_view
            .as_ref()
            .is_none_or(|previous| previous != &resolved.members);
        let update_ref = watermark(&state).map_err(classify)?;
        let view = MembershipView::new(resolved.members.members, reset_boundary);

        Ok(Admitted {
            state: wrap(state),
            view,
            changed,
            tree_id: candidate_group,
            update_ref,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{append_add, provision_anchor};
    use crate::{KeyringMemberInit, KeyringRole};

    fn signing_key(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
    }

    fn member_id(seed: u8) -> String {
        openom_keyring_api::derive_member_id(&signing_key(seed).verifying_key().to_bytes())
    }

    fn envelope(anchor: Vec<u8>) -> Vec<u8> {
        MembershipEnvelope::wrap(EngineKind::Dag, anchor).encode()
    }

    fn member(seed: u8) -> KeyringMemberInit {
        KeyringMemberInit {
            id: member_id(seed),
            role: KeyringRole::VIEWER,
            author_public_key: signing_key(seed).verifying_key().to_bytes(),
            hpke_public_key: [seed; 32],
        }
    }

    #[test]
    fn full_anchor_admission_bootstraps_and_advances_verified_state() {
        let owner_key = signing_key(1);
        let genesis = provision_anchor(
            b"0123456789abcdef",
            &member_id(1),
            owner_key.verifying_key(),
            keyeo_wrap::X25519PublicKey::from_bytes([1; 32]),
            None,
            b"genesis seal".to_vec(),
            &owner_key,
        );
        let verifier = DagAnchorVerifier;
        let first = verifier.admit(None, &envelope(genesis.clone())).unwrap();
        assert_eq!(first.view.members.len(), 1);

        let advanced =
            append_add(&genesis, &member_id(1), &member(2), Vec::new(), &owner_key).unwrap();
        let second = verifier
            .admit(Some(&first.state), &envelope(advanced))
            .unwrap();
        assert!(second.changed);
        assert_eq!(second.view.members.len(), 2);
        assert!(!second.view.reset_boundary);
    }

    #[test]
    fn full_anchor_admission_refuses_a_rollback() {
        let owner_key = signing_key(3);
        let genesis = provision_anchor(
            b"fedcba9876543210",
            &member_id(3),
            owner_key.verifying_key(),
            keyeo_wrap::X25519PublicKey::from_bytes([3; 32]),
            None,
            Vec::new(),
            &owner_key,
        );
        let advanced =
            append_add(&genesis, &member_id(3), &member(4), Vec::new(), &owner_key).unwrap();
        let verifier = DagAnchorVerifier;
        let first = verifier.admit(None, &envelope(advanced)).unwrap();
        assert_eq!(
            verifier.admit(Some(&first.state), &envelope(genesis)),
            Err(VerifyError::Rollback)
        );
    }
}
