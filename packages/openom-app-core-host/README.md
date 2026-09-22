# openom-app-core-host

The native Rust host for the application core. It owns one unlocked profile account, all live tree cores, and
the filesystem-backed local stores used by the Tauri shell; account and tree secrets never enter the webview.
It reports explicit `none` / `locked` / `unlocked` account custody and locks by dropping every live tree core
plus the resident account while retaining encrypted persistence.
Fetched account backups are first opened in temporary Rust custody. Only the resulting authenticated snapshot
is committed to the injected store; the resident account and live trees are replaced after that commit lands.
All native account mutations hold one profile operation mutex across read, credential verification, record-CAS
commit, read-back verification, and resident-handle installation.

## What it is — and is not

This crate coordinates synchronous account, tree, sharing, and local-data operations. `openom-vault-host`
provides the injected persistence seam for the singleton wrapped account plus per-tree keyrings/watermarks;
Tauri commands are a thin asynchronous veneer in `apps/src-tauri`. It is not an auth provider or network
client, and it does not persist invite-handshake resume state.

## Invariants

| ID | Invariant | Why | Verified by |
|---|---|---|---|
| **APP-HOST-1** | One resident account identity can own multiple trees; changing its passphrase once preserves every tree identity on both engines. | Account credentials wrap the profile root, not individual tree DEKs. | `tests::one_native_account_owns_multiple_trees_and_changes_its_passphrase_once` |
| **APP-HOST-2** | Joined-tree reopen derives founder/member dispatch from verified keyring membership and uses the same profile account on chain and DAG. | A stored per-tree credential must not choose or authorize the reopen path. | `tests::a_member_joins_on_a_second_host_writes_and_converges_with_the_owner`, `tests::a_member_joins_a_dag_tree_by_anchor_and_converges_with_the_owner` |
| **APP-HOST-3** | Account lock drops all resident account and tree secrets without deleting their encrypted persistence. | A locked session must not retain usable keys or destroy the data needed to unlock again. | `tests::account_status_and_lock_follow_native_custody` |
| **APP-HOST-4** | Candidate adoption verifies credentials and the generation floor, commits the authenticated snapshot, and only then replaces resident account/tree custody; recovery adoption rotates its credential first. | A bad credential or failed local write must leave the previously usable identity and trees intact, and a used recovery code must not remain valid. | `tests::candidate_adoption_commits_before_replacing_native_custody`, `tests::recovery_candidate_rotates_before_native_adoption` |
| **APP-HOST-5** | Native profile mutations serialize the complete record protocol, account-dependent tree lifecycle uses the same gate, and record revision advances independently of account generation. | A same-generation passphrase re-wrap is still a new local record; neither concurrent credential calls nor account-backed tree opens may cross an identity replacement. | `tests::profile_gate_blocks_account_dependent_tree_lifecycle`, `tests::one_native_account_owns_multiple_trees_and_changes_its_passphrase_once` |

## Position

Above `openom-app-core`, `openom-vault`, `openom-vault-host`, and the local stores; below the Tauri command
layer. The browser counterpart is the worker in `apps/app/src/core/appCore.worker.js`.
