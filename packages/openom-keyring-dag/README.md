# openom-keyring-dag

> openom's DAG keyring binding — the openom role model, Ed25519 seam, authority policy, and recovery key
> wired onto the generic `keyeo-dag` group-membership DAG (the sequencer-free keyring).

**Status:** built · keyring engine (one of two) · dependency-light / openom-domain-specific · design keyring-dag (OPE-137/269)
**Last updated:** 2026-09-23

## What it is — and is not

`keyeo-dag` is domain-free; this crate is its openom binding. It fixes the four generic type parameters —
op ids are 32-byte content hashes, member ids are openom member strings, roles are [`KeyringRole`]
(`Owner=1 … Viewer=5`, bound to `openom_keyring_api::ROLE_*`), signatures are keyeo-dag's unified [`Ed25519`] (strict
Ed25519 via `edsign`) — and supplies the authority policy: [`KeyringAccess`] gates keyring writes to signers
(CoOwner-or-stronger), with founder-signed governance and, in v2, per-family [`KeyringQuorum`] rules.
It adds **recovery** (the RVK derived from the escrowed RRK secret, pinned in genesis, authorizing a
`ReFound`) and implements the keyless [`openom_keyring_api::KeyringVerifier`] seam in two forms: op-at-a-time
admission for the engine primitive, and self-contained full-anchor admission for the managed server channel.
The latter verifies and merges an anchor while retaining a latest-revision restore artifact, without holding a
key. Concurrency, merge, and strong-remove come from `keyeo-dag` underneath.

It is **not** the passphrase lifecycle: provision / unlock / recover / author (which touch the DEK and the
sealer) live in `openom-vault`, above this. It is **not** the linear chain engine — that is the separate
`openom-keyring-chain`, and the two are interchangeable behind `openom-keyring-api`. Despite wiring openom's model, its
non-dev dependency tree is **dependency-light** (it binds roles to `openom-keyring-api`'s convention and derives its RVK
through `edsign`, not `openom-crypto`); only its test harnesses pull the
openom crates to cross-check against the chain.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **KDAG-1** | Only a signer (CoOwner-or-stronger) can write the keyring; a Maintainer's keyring op is refused. | Keyring administrative authority is strictly the signer set — a lower role cannot alter membership. | `tests::a_maintainer_cannot_write_the_keyring` |
| **KDAG-2** | A `ReFound` retargets the owner only when signed by the pinned recovery authority; without it (or against a non-owner) it is rejected. | Recovery is gated on the RRK-derived key pinned in genesis — strictly stronger than the chain's self-signed reset. | `tests::a_refound_signed_by_the_recovery_authority_retargets_the_owner`, `tests::a_refound_is_rejected_without_the_recovery_authority_or_against_a_non_owner` |
| **KDAG-3** | A concurrent fork converges with both branches surviving; a fork branching from before the merge horizon is rejected. | Sequencer-free merge must not lose ops, but also can't accept an op reaching behind the GC'd horizon. | `tests::a_fork_converges_and_both_survive`, `tests::a_fork_branching_from_before_the_merge_horizon_is_rejected` |
| **KDAG-4** | A second `Create` cannot re-found the group and wipe the roster; an op carrying a key that isn't the author's registered key is ignored. | Genesis and author-key binding close two roster-hijack vectors. | `tests::a_second_create_cannot_re_found_and_wipe_the_roster`, `tests::an_op_carrying_a_key_that_is_not_the_authors_registered_key_is_ignored` |
| **KDAG-5** | A privileged op concurrent with a recovery is voided, but a later owner op stands. | Recovery takes precedence over concurrent privileged writes without permanently freezing post-recovery governance. | `tests::a_privileged_op_concurrent_with_recovery_is_voided_but_a_later_owner_op_stands` |
| **KDAG-6** | The op verifier and full-anchor verifier fold authenticated DAG state into a `openom_keyring_api::MembershipView`; full-anchor admission refuses rollback. The RVK is deterministic + secret-dependent. | The keyless server seam, fresh-device restore artifact, and recovery-key derivation remain one verified contract. | `verifier::tests::dag_verifier_folds_admitted_ops_into_a_membership_view`, `anchor_verifier::tests::full_anchor_admission_bootstraps_and_advances_verified_state`, `anchor_verifier::tests::full_anchor_admission_refuses_a_rollback`, `recovery::tests::different_secrets_yield_different_rvks` |

The RVK derivation is byte-identical to the chain vault's (`openom_crypto::derive_rvk`), guarded by a
cross-check test in `openom-vault`. Run: `node scripts/cargo.mjs test -p openom-keyring-dag` (from the repo root).

## Usage

```rust,ignore
use openom_keyring_dag::{anchor_verifier::DagAnchorVerifier, recovery};
use openom_keyring_api::KeyringVerifier;

// Keyless managed-server admission: verify/merge a full anchor against prior opaque trust state.
let admitted = DagAnchorVerifier.admit(prior_state, &anchor_envelope)?;
let members = admitted.view.members;

// Recovery: the RVK pinned in genesis, derived from the escrowed RRK secret.
let rvk_public = recovery::rvk_public(&rrk_secret);
```

Entry points: the type aliases (`KeyringAction` / `KeyringOp` / `KeyringState` / `KeyringEngine`),
`KeyringRole`, `sign_op`, `KeyringAccess` + `KeyringQuorum` / `QuorumRule` (authority), `recovery`
(`derive_rvk` / `rvk_public`), `verifier` and `anchor_verifier` (the two `KeyringVerifier` adapters),
and `client` / `blob_sync`.

## Position

Layer 2 — one of the two keyring engines, over `keyeo-dag` (Layer 0) and behind `openom-keyring-api` (Layer 1). Above
it sits `openom-vault` (the lifecycle). Non-dev deps: `keyeo-dag`, `openom-keyring-api`, `edsign`, `store-blob`, serde.
Full dependency graph: see `packages/README.md`.
