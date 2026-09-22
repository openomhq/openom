# openom-vault-host

The native **account/keyring custody persistence seam** for the openom Tauri host: the [`VaultStore`] trait and
its durable `SQLite` backing ([`sqlite::SqliteVaultStore`]).

A tree's keyring is a *wrapped* DEK — not secret, but it must survive a relaunch — and its watermark is the
engine-opaque anti-rollback cursor. The store also holds one profile-level account record; account custody is
never duplicated per tree. `VaultStore` persists these records, and
`commit_keyring` writes each tree's keyring and watermark in **one transaction** so a crash can never leave the
stored anchor disagreeing with its cursor. It's kept in its own
file (`vault.sqlite`), separate from the doc/blob store, so copying or restoring the tree database can't drag
the anti-rollback watermark backward with it.

The profile account is one portable, explicitly revisioned record. It scopes the wrapped blob and effective
generation floor to a stable `member_id`, and atomically carries the confirmed auth binding, acknowledged
remote ETag/version, and pending backup intent. `SQLite` stores the complete record as one value and commits only
the next expected record revision; that local revision is independent of the credential generation and every
tree watermark. The trait is injected, so the native host is testable with an in-memory fake and, on Tauri,
backs onto `SqliteVaultStore` (behind the `sqlite` feature).

## Invariants

| ID | Invariant | Why | Verified by |
|---|---|---|---|
| **VAULT-HOST-1** | A profile-account commit advances exactly one portable record revision and cannot lower the effective generation floor for the same identity. | Local CAS ordering must never become a credential rollback path. | `sqlite::tests::account_record_cas_rejects_conflicts_and_identity_scoped_floor_rollback` |
| **VAULT-HOST-2** | `effective_floor` is at least the authenticated local blob generation, even when a persisted floor is lower. | Losing only the explicit floor must not make a surviving newer blob unusable or teach a lower floor. | `account_record_tests::effective_floor_self_heals_a_lower_persisted_value` |
| **VAULT-HOST-3** | Replacing the stable identity replaces its floor and clears binding, acknowledgement, and pending state. | Sync metadata from one identity must never authorize or acknowledge another identity's backup. | `account_record_tests::a_different_identity_gets_its_own_floor_and_drops_remote_state` |
| **VAULT-HOST-4** | The stored blob hash must equal SHA-256 of the exact wrapped account bytes. | A corrupted record must not associate backup acknowledgements with different ciphertext. | `account_record_tests::validation_rejects_a_blob_hash_for_different_wrapped_bytes` |
| **VAULT-HOST-5** | A backup/revoke intent is pinned to the exact local version and confirmed binding; acknowledgement compare-clears only that intent, and a pending revoke cannot be downgraded to backup. | A stale response must never acknowledge newer custody, and revocation must win over an upload retry. | `account_record_tests::pending_backup_compare_and_clear_is_exact_and_revoke_wins` |

## Scope

This crate is *only* the persistence seam. The DEK, the keyring engine (chain/dag), the claim engine, the local
device store, and the whole passphrase + sharing lifecycle now run natively in
[`openom-app-core-host`](../openom-app-core-host), which is parameterized over a `VaultStore`. The older
thin-custody `VaultHost` that once lived here (holding live sealer sessions + the full lifecycle in this crate)
was superseded by that full-native-core host and has been removed.
