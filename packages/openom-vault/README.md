# openom-vault

> The keyring **vault** layer — the durable-account-backed lifecycle (provision / unlock / recover /
> change-passphrase / author membership) over a keyring, for both engines.

**Status:** built · key-custody lifecycle · openom-coupled by design · design keyring-dag/design.dag-vault.md (OPE-273/279)
**Last updated:** 2026-09-21

## What it is — and is not

The stateful, secret-holding top of the keyring stack. Behind the [`KeyringLifecycle`] trait it borrows one
profile-level [`UnlockedAccount`] to provision and unlock any number of independent tree sessions. Each
session receives fresh owned keys derived from the account's stored-random identity master, so the account
remains resident and reusable while session secrets remain independently owned. Recovery and credential
changes remain explicit lifecycle operations. The vault also drives membership operations: add/remove a
member and promote/demote a co-owner. Joined-member unlock can borrow that same durable account while keeping
the chain's signer pins as separate non-secret trust metadata. [`AppVault`] dispatches each call to the right engine — [`ChainVault`] over
`openom-keyring-chain` or [`DagVault`] over `openom-keyring-dag` — on the tree's bound [`openom_keyring_api::EngineKind`], so one binary
serves both. Underneath sits the engine-neutral **sealing core** (`vault_core`: DEK / epoch / RRK / KDF /
recovery-code / `SealerSet` machinery), extracted so both engines share one implementation of the
security-critical crypto path. This crate is an **rlib only** — the single browser wasm surface is
`openom-app-core` (which consumes this vault as a plain dependency); the legacy `wasm` veneer that once
lived here was retired (OPE-389). Two engine-neutral
membership helpers also live here, both typed against `openom-keyring-api`'s `MembershipView` (so they
read the folded view, never an engine's raw wire): `attribution::verify_entry` (authorize a landed entry
by its kind + author against the governing view — moved off the chain crate in OPE-333) and
`membership::moderators` (the Owner/Co-owner set).

It is **not** `openom-sealer`: that is now the lean, engine-free DEK *session* (`Sealer` / `SealerSet` /
`seal` / `open`) this crate builds on. It is **not** the keyless server seam (`openom-keyring-api`) — the lifecycle
results carry `SealerSet` + `Passphrase` / `RecoveryCode` / `DidKey`, so they must stay off the server's
key-free binding surface. Unlike the engines below it, this crate is **openom-coupled by design** (it uses
`openom-crypto`'s AEAD/KDF and `openom-protocol`'s envelope/id types) and keeps the `openom-` prefix; that
coupling is load-bearing, not incidental (see `packages/openom-crypto` and OPE-283).

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **VAULT-1** | One unlocked durable account can provision and unlock multiple independent trees under the same stable identity; a second replica reaches each tree's identical DEK. | Account authentication happens once per profile session, rather than consuming or re-deriving identity for every tree operation. | `lifecycle::tests::one_unlocked_account_is_reusable_across_trees`, `vault::tests::provision_then_unlock_on_another_device_opens_the_same_data`, `dag_vault::tests::dag_provision_then_unlock_opens_the_same_data` |
| **VAULT-2** | Account unlock / credential change / recovery reject the wrong credential, and tree unlock rejects a foreign account. | Public keystore and keyring blobs reveal no usable account or tree secret without the corresponding credential and identity. | `account_keystore::tests::wrong_passphrase_fails`, `vault::tests::unlock_with_the_wrong_account_is_rejected`, `vault::tests::change_passphrase_with_the_wrong_old_passphrase_fails`, `vault::tests::recover_with_the_wrong_code_fails` |
| **VAULT-3** | Both engines satisfy one lifecycle contract, and a keyring for another `tree_id` is refused (the caller's expected id is trusted, never the document's). | `AppVault` can dispatch either engine identically, and the tree-binding AAD stays non-circular. | `lifecycle::tests::chain_and_dag_satisfy_the_same_lifecycle_contract`, `vault::tests::a_keyring_for_another_tree_is_refused` |
| **VAULT-4** | Removing a member re-keys to a fresh epoch that locks them out of new content. | Forward secrecy: a removed member keeps only what they could already read. | `vault::tests::removing_a_member_re_keys_and_denies_them_new_content`, `dag_vault::tests::dag_remove_member_forward_secret_epoch_locks_them_out` |
| **VAULT-5** | `recover` pins the write epoch to DEK *material* (`revision‖key_id‖H(DEK)`), and a stale anchor / rolled-back watermark is refused. | Anti-rollback binds recovery to real key material, not a public label an attacker can mint (OPE-286). | `vault::tests::recover_pins_the_write_epoch_to_dek_material`, `dag_vault::tests::dag_watermark_advances_and_a_stale_anchor_is_refused` |
| **VAULT-6** | Absurd KDF params are rejected before Argon2id runs; the member's `did:key` is the founder key and stable across unlock. | A malicious keyring can't `DoS` via KDF cost, and the claim-author id is deterministic. | `vault::tests::absurd_kdf_params_are_rejected_before_running_argon2id`, `dag_vault::tests::did_key_is_the_founder_key_and_stable_across_unlock` |
| **VAULT-7** | The vault's provisioning RVK (`openom_crypto::derive_rvk`) and the dag engine's verifying RVK (`openom_keyring_dag::recovery`) are byte-identical. | A tree recovered by one is verifiable by the other — the two derivations live in different crates and must not drift. | `dag_vault::tests::vault_and_engine_derive_the_same_recovery_key` |

Run: `node scripts/cargo.mjs test -p openom-vault` (from the repo root).

## Usage

```rust,ignore
use openom_vault::{AppVault, lifecycle::{KeyringLifecycle, VaultContext}};

// Dispatches to the chain or dag engine on the tree's bound EngineKind.
let vault = AppVault::from_kind(engine_kind);
let account = keystore.unlock(passphrase.expose())?;
let ctx = VaultContext { tree_id, member_id, replica_id };

let provisioned = vault.provision(&ctx, &account)?; // new tree → keyring bytes + a DEK session
let session = vault.unlock(&ctx, &keyring_bytes, &account)?; // same account remains usable for other trees
```

Entry points: `AppVault` (engine dispatch), the `KeyringLifecycle` trait, `ChainVault` / `DagVault`,
`VaultContext`, `VaultError`, the `sharing` module (the engine-neutral distribution + member epoch-adopt
marshalling `openom-app-core`'s worker calls), and the `attribution` / `membership` modules (landed-entry
authorization + the moderator set over a `MembershipView`).

## Position

The top of the keyring stack: above the two engines (`openom-keyring-chain`, `openom-keyring-dag`) and above
`openom-sealer` (the DEK session it uses). Its native counterpart is `openom-vault-host` (Tauri custody).
Full dependency graph: see `packages/README.md`.
