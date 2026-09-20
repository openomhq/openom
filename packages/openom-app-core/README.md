# openom-app-core

> The application-facing Rust core shared by the browser worker and native host: durable account custody,
> encrypted tree sessions, the claim engine, and local-first synchronization.

**Status:** built · account/tree custody cutover in progress · wasm + native rlib
**Last updated:** 2026-09-21

## What it is — and is not

`openom-app-core` is the application boundary over `openom-vault`, `openom-data-tree`, and
`openom-docsync`. One profile-level [`AccountHandle`] keeps an [`openom_vault::UnlockedAccount`] resident
inside the Rust host. Account operations create, unlock, recover, rotate, or re-wrap that identity without
touching any tree. Tree operations borrow the handle to provision or unlock independent encrypted trees, so
the same self-certifying `member_id` spans every tree while each tree keeps its own DEK session and keyring.

The same store-generic functions run over the browser worker's `MemoryBlob` and the native host's durable
store. [`AppCore`] owns the live tree, sealer session, local log, membership verifier, and sync planning. The
JavaScript worker or native host performs asynchronous storage/network I/O around these synchronous calls.

It is not an authentication session, network client, or persistence policy. Supabase JWT custody and the
profile-level location of the wrapped keystore belong to the shell/session layers. Secret account material
never leaves [`AccountHandle`]; the shell receives only the wrapped keystore, public identity fields,
registration signature, generation, and one-time recovery code.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **APP-CORE-1** | One unlocked account provisions and reopens multiple trees under both keyring engines with one stable identity; changing its passphrase once leaves every tree openable. | Account identity and credentials are profile-level, never copied into each tree. | `lifecycle_tests::one_account_handle_owns_and_reopens_multiple_trees_on_both_engines` |
| **APP-CORE-2** | Recovery and explicit root rotation preserve `member_id`, advance the generation, refresh the live handle, and revoke the prior recovery material. | A stale handle or old recovery code must not silently restore revoked account custody. | `lifecycle_tests::recovery_and_root_rotation_refresh_the_handle_and_revoke_old_material` |
| **APP-CORE-3** | Registration proof signs the shared, domain-separated issuer/subject/member/timestamp encoding and fails verification when a bound claim changes. | The auth subject can only bind itself to an account whose signing key the client controls. | `lifecycle_tests::registration_proof_matches_the_server_verification_bytes` |

Run: `node scripts/cargo.mjs test -p openom-app-core --all-features` (from the repo root).

## Usage

```rust,ignore
let created = account_create(&passphrase)?;
let first = provision_tree(store_a, engine, &created.handle, &tree_a, &replica, "tree-a")?;
let second = provision_tree(store_b, engine, &created.handle, &tree_b, &replica, "tree-b")?;
assert_eq!(first.did_key, second.did_key);
```

Entry points: account custody (`AccountHandle`, `account_create`, `account_unlock`,
`account_change_passphrase`, `account_recover`, `account_rotate_root`, `account_register_proof`), tree custody
(`provision_tree`, `unlock_tree`), and the live local-first engine (`AppCore`).

## Position

The app-facing orchestration layer above `openom-vault`, `openom-data-tree`, `openom-docsync`, and
`store-blob`; below `openom-app-core-host`, the wasm worker veneer, and the Tauri shell. Full dependency
graph: see `packages/README.md`.
