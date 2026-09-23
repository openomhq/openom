#![doc = include_str!("../README.md")]

use std::sync::Arc;

use openom_app_core_host::{
    AccountAdopted, AccountBackupAcknowledged, AccountChanged, AccountIdentity, AccountOpened,
    AccountSnapshot, AccountStatus, AccountSyncState, AddedMember, AppCoreHost, BlobData, BlobMeta,
    DagKeyringSyncOutcome, InviteMaterial, KeyringRevisionPayload, MemberToAdd, MemberUnlocked,
    Provisioned, RemovedMember, RoleChanged, SyncOut, Unlocked,
};
use openom_crypto::{Passphrase, RecoveryCode};
use openom_keyring_api::EngineKind;
use openom_protocol::ids::{MemberId, TreeId};
use openom_vault_host::sqlite::SqliteVaultStore;
use openom_vault_host::{
    AccountBinding, AccountRemoteCheckpoint, PendingAccountBackup, PendingBackupKind, VaultStore,
};
use tauri::{Manager, State};

/// The one native session host (OPE-427 Full-A): it runs `openom-app-core` natively — the DEK, the claim
/// engine, and each doc's local device store all live in this process — with the keyring anchor + anti-rollback
/// watermark held in a durable `SQLite` `VaultStore`. Every `#[command]` below is a thin wrapper over it.
type Host = Arc<AppCoreHost<SqliteVaultStore>>;

/// A stored object — `(key, ciphertext bytes)` — the webview↔host sync ferry unit (the host's `StoredObject`).
type StoredObject = (String, Vec<u8>);

/// Map a host error to the structured `{code, message}` JSON the webview adapter normalizes into an `AppError`
/// (matching the wasm veneer's error channel — so the gate's tamper / rollback / wrong-passphrase distinctions,
/// and the sync driver's retriable/auth classification, survive on the native host).
fn e(err: openom_app_core_host::HostError) -> String {
    serde_json::json!({ "code": openom_app_core_host::error_code(&err), "message": err.to_string() }).to_string()
}

/// A `spawn_blocking` join failure (a panic/cancel in the worker) in the same structured shape.
fn join_err(err: impl std::fmt::Display) -> String {
    serde_json::json!({ "code": "internal", "message": err.to_string() }).to_string()
}

/// The keyring engine for newly provisioned trees (OPE-278), resolved at RUNTIME and owned by the custody host
/// in Rust — never taken from the (less-trusted) webview. Runtime, not `cfg`, on purpose: one binary can reach
/// more than one backend (managed Lambda, BYO Google Drive), so a future dual-engine world maps each backend to
/// its engine here without a rebuild. Existing trees already carry their own engine in the keyring, so this only
/// picks what to stamp on a NEW tree. Today every backend uses the chain engine; the hidden
/// `OPENOM_KEYRING_ENGINE=dag` override selects the dag keyring for bring-up. Same tag mapping (`EngineKind`'s
/// `FromStr`) as the web/wasm host, so the two can't drift.
fn keyring_engine() -> EngineKind {
    std::env::var("OPENOM_KEYRING_ENGINE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EngineKind::Chain)
}

// --------------------------------------------------------------- lifecycle (Argon2id: async spawn_blocking)

/// Provision a fresh tree: the host opens a core over the native store, PERSISTS the keyring + watermark
/// natively, and registers the core. Returns the recovery code + author `did:key`.
#[tauri::command]
async fn core_provision(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
) -> Result<Provisioned, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.provision_tree(&doc, &TreeId::new(tree_id)).map_err(e)
    })
    .await
    .map_err(join_err)?
}

/// Unlock an existing tree: the host loads the keyring FROM THE NATIVE STORE (never a webview argument — the
/// boundary that stops an XSS feeding a stale/forged keyring), opens the core, and registers it. The webview
/// then [`core_bootstrap`]s to fold back any mint committed offline in a previous session.
#[tauri::command]
async fn core_unlock(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
) -> Result<Unlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.open_tree(&doc, &TreeId::new(tree_id)).map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn account_create(
    state: State<'_, Host>,
    passphrase: String,
) -> Result<AccountOpened, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_create(&Passphrase::new(passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn account_unlock(
    state: State<'_, Host>,
    passphrase: String,
) -> Result<AccountIdentity, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_unlock(&Passphrase::new(passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
fn account_status(state: State<'_, Host>) -> Result<AccountStatus, String> {
    state.account_status().map_err(e)
}

#[tauri::command]
fn account_lock(state: State<'_, Host>) {
    state.account_lock();
}

#[tauri::command]
async fn account_recover(
    state: State<'_, Host>,
    recovery_code: String,
    new_passphrase: String,
) -> Result<AccountOpened, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_recover(
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
fn account_public_identity(state: State<'_, Host>) -> Result<AccountIdentity, String> {
    state.account_public_identity().map_err(e)
}

#[tauri::command]
fn account_snapshot(state: State<'_, Host>) -> Result<AccountSnapshot, String> {
    state.account_snapshot().map_err(e)
}

#[tauri::command]
fn account_sync_state(state: State<'_, Host>) -> Result<AccountSyncState, String> {
    state.account_sync_state().map_err(e)
}

#[tauri::command]
fn account_confirm_binding(
    state: State<'_, Host>,
    binding: AccountBinding,
) -> Result<AccountSyncState, String> {
    state.account_confirm_binding(binding).map_err(e)
}

#[tauri::command]
fn account_stage_backup(
    state: State<'_, Host>,
    kind: PendingBackupKind,
    binding: AccountBinding,
) -> Result<AccountSyncState, String> {
    state.account_stage_backup(kind, binding).map_err(e)
}

#[tauri::command]
fn account_acknowledge_backup(
    state: State<'_, Host>,
    expected: PendingAccountBackup,
    checkpoint: AccountRemoteCheckpoint,
) -> Result<AccountBackupAcknowledged, String> {
    state
        .account_acknowledge_backup(&expected, checkpoint)
        .map_err(e)
}

#[tauri::command]
async fn account_adopt_candidate(
    state: State<'_, Host>,
    expected_member_id: String,
    candidate: Vec<u8>,
    passphrase: String,
    binding: AccountBinding,
    checkpoint: AccountRemoteCheckpoint,
) -> Result<AccountAdopted, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_adopt_candidate(
            &openom_vault_host::AccountMemberId::new(expected_member_id),
            &candidate,
            &Passphrase::new(passphrase.into_bytes()),
            binding,
            checkpoint,
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn account_adopt_recovery_candidate(
    state: State<'_, Host>,
    expected_member_id: String,
    candidate: Vec<u8>,
    recovery_code: String,
    new_passphrase: String,
    binding: AccountBinding,
    checkpoint: AccountRemoteCheckpoint,
) -> Result<AccountAdopted, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_adopt_recovery_candidate(
            &openom_vault_host::AccountMemberId::new(expected_member_id),
            &candidate,
            &RecoveryCode::new(recovery_code),
            &Passphrase::new(new_passphrase.into_bytes()),
            binding,
            checkpoint,
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn account_change_passphrase(
    state: State<'_, Host>,
    new_passphrase: String,
) -> Result<AccountChanged, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_change_passphrase(&Passphrase::new(new_passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
async fn account_rotate_root(
    state: State<'_, Host>,
    passphrase: String,
) -> Result<AccountOpened, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.account_rotate_root(&Passphrase::new(passphrase.into_bytes()))
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

#[tauri::command]
fn account_register_proof(
    state: State<'_, Host>,
    issuer: String,
    subject: String,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    state
        .account_register_proof(&issuer, &subject, timestamp)
        .map_err(e)
}

/// The SELF-CERTIFYING member id (OPE-543): `derive_member_id(author_public_key)` — the native mirror of the
/// wasm `deriveMemberId`, over the SAME crate fn, so the JS seam never re-implements the derivation (max-Rust).
/// Pure + stateless (SHA-256 → UUIDv8), so no host state and no `spawn_blocking`.
#[tauri::command]
fn core_derive_member_id(author_public_key: Vec<u8>) -> String {
    openom_keyring_api::derive_member_id(&author_public_key)
}

/// Admit an OOB-verified member to a shared tree (owner action): the host produces the new keyring revision,
/// re-opens the owner core in place on the shared keyring, and persists it natively. Returns the opaque keyring
/// revision the webview PUBLISHES (keyring first, then the advisory summary). Argon2id (re-open), so
/// `spawn_blocking`.
#[tauri::command]
async fn core_add_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    member: MemberToAdd,
) -> Result<AddedMember, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.add_tree_member(&doc, &TreeId::new(tree_id), &member)
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

/// Remove a member (owner action) with forward-secure revocation: the host pins the departing member's history,
/// rotates the epoch, re-opens the owner core under it in place, and persists it natively. Returns the opaque
/// rotated keyring for the webview to publish (advisory summary FIRST, then keyring, then a data sync to push
/// the cover) + whether the history was pinned. Argon2id (re-open), so `spawn_blocking`.
#[tauri::command]
async fn core_remove_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    remove_member_id: String,
) -> Result<RemovedMember, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.remove_tree_member(
            &doc,
            &TreeId::new(tree_id),
            &MemberId::new(remove_member_id),
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

/// Change a member's role (owner action): promote to co-owner or demote. No epoch rotation — the host refreshes
/// the owner core's §B3 resolver in place and persists the new keyring. Returns the opaque keyring for the
/// webview to publish (promote keyring-first, demote advisory-first) + whether it was a demote. Argon2id, so
/// `spawn_blocking`.
#[tauri::command]
async fn core_change_role(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    target_member_id: String,
    new_role: String,
) -> Result<RoleChanged, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.change_tree_member_role(
            &doc,
            &TreeId::new(tree_id),
            &MemberId::new(target_member_id),
            &new_role,
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

/// A joining member's first open: the host verifies the fetched keyring history against the OOB pin, unlocks at
/// the verified head, and establishes native custody (member context + keyring + retention). `hops` is the
/// framed keyring history the webview fetched; trusted signers are derived from the verified walk, never passed.
/// Argon2id, so `spawn_blocking`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri invoke convention: the flat argument list IS the JS calling shape
async fn core_join_as_member(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    hops: Vec<u8>,
    pinned_revision: u32,
    pinned_hash: Vec<u8>,
) -> Result<MemberUnlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.join_chain_tree(
            &doc,
            &TreeId::new(tree_id),
            &hops,
            pinned_revision,
            &pinned_hash,
        )
        .map_err(e)
    })
    .await
    .map_err(join_err)?
}

/// A joining member's FIRST open on the DAG engine — verify the served self-contained anchor against the OOB pin,
/// then unlock as the member. Argon2id, so `spawn_blocking`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri invoke convention: the flat argument list IS the JS calling shape
async fn core_join_dag_anchor(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    anchor: Vec<u8>,
    pin: Vec<u8>,
) -> Result<MemberUnlocked, String> {
    let host = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.join_dag_tree(&doc, &TreeId::new(tree_id), &anchor, &pin)
            .map_err(e)
    })
    .await
    .map_err(join_err)?
}

// --------------------------------------------------------------- session ops (cheap: sync is fine)

/// Whether a keyring is already stored natively for `doc` (the shell's "provision vs unlock" fork).
#[tauri::command]
fn core_has_keyring(state: State<'_, Host>, doc: String) -> Result<bool, String> {
    state
        .store()
        .load_keyring(&doc)
        .map(|k| k.is_some())
        .map_err(join_err)
}

/// Rebuild `doc`'s engine from its durable local log — call once after [`core_unlock`] on open.
#[tauri::command]
fn core_bootstrap(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.bootstrap(&doc).map_err(e)
}

/// Buffer an identity-anchor mint into `doc`'s intention; [`core_commit`] seals + persists it.
#[tauri::command]
fn core_assert_anchor(
    state: State<'_, Host>,
    doc: String,
    id: String,
    type_uri: String,
) -> Result<(), String> {
    state.assert_anchor(&doc, &id, &type_uri).map_err(e)
}

/// Seal + persist `doc`'s buffered mint batch to its local store.
#[tauri::command]
fn core_commit(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.commit(&doc).map_err(e)
}

/// The write-side role pre-check: whether `doc` may commit directly, or must route its edit to a proposal.
#[tauri::command]
fn core_can_commit_directly(state: State<'_, Host>, doc: String) -> Result<bool, String> {
    state.can_commit_directly(&doc).map_err(e)
}

/// Open a historical delta envelope to its op-batch JSON (the decrypted change) for the change-history feed.
#[tauri::command]
fn core_open_history_delta(
    state: State<'_, Host>,
    doc: String,
    envelope: Vec<u8>,
) -> Result<String, String> {
    state.open_history_delta(&doc, &envelope).map_err(e)
}

/// Editor: seal `doc`'s buffered intention as a proposal for a maintainer to review (empty if nothing minted).
#[tauri::command]
fn core_propose(state: State<'_, Host>, doc: String) -> Result<Vec<u8>, String> {
    state.propose(&doc).map_err(e)
}

/// Maintainer: verify + commit an editor `proposal` as an attributed delta; returns the number of ops committed.
#[tauri::command]
fn core_approve_proposal(
    state: State<'_, Host>,
    doc: String,
    proposal: Vec<u8>,
) -> Result<usize, String> {
    state.approve_proposal(&doc, &proposal).map_err(e)
}

/// Fold `doc`'s local store through the §B3 gate; returns how many entries folded.
#[tauri::command]
fn core_fold(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.fold(&doc).map_err(e)
}

/// `doc`'s materialized read model as a JSON string (the webview renders it).
#[tauri::command]
fn core_project(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.project(&doc).map_err(e)
}

// ---- keyring publish + advisory + invite (all read the NATIVE stored keyring) ----

/// The opaque payload to PUT to the server's keyring channel (the wrapped current keyring / dag anchor).
#[tauri::command]
fn core_keyring_publish_payload(state: State<'_, Host>, doc: String) -> Result<Vec<u8>, String> {
    state.keyring_publish_payload(&doc).map_err(e)
}

/// The advisory membership summary JSON (OPE-293) to PUT to the server's /access channel.
#[tauri::command]
fn core_membership_summary(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.membership_summary(&doc).map_err(e)
}

/// The OOB invite pin for the current keyring (the joiner verifies the walk against it).
#[tauri::command]
fn core_invite_pin(state: State<'_, Host>, doc: String) -> Result<Vec<u8>, String> {
    state.invite_pin(&doc).map_err(e)
}

/// The invite MINT material (v3): `{ engine, pin(full), signers }` — the webview drives `invite.mint`
/// engine-agnostically and records the signer set for the admit gate.
#[tauri::command]
fn core_invite_material(state: State<'_, Host>, doc: String) -> Result<InviteMaterial, String> {
    state.invite_material(&doc).map_err(e)
}

// ---- claim edits (buffered into the intention; core_commit seals them) ----

#[tauri::command]
fn core_assert_claim(
    state: State<'_, Host>,
    doc: String,
    target: String,
    predicate: String,
    value_json: String,
) -> Result<(), String> {
    state
        .assert_claim(&doc, &target, &predicate, &value_json)
        .map_err(e)
}

#[tauri::command]
fn core_supersede_claim(
    state: State<'_, Host>,
    doc: String,
    prior: String,
    target: String,
    predicate: String,
    value_json: String,
) -> Result<(), String> {
    state
        .supersede_claim(&doc, &prior, &target, &predicate, &value_json)
        .map_err(e)
}

#[tauri::command]
fn core_remove_record(
    state: State<'_, Host>,
    doc: String,
    target: String,
) -> Result<String, String> {
    state.remove_record(&doc, &target).map_err(e)
}

#[tauri::command]
fn core_revoke(state: State<'_, Host>, doc: String, removal_op_id: String) -> Result<(), String> {
    state.revoke(&doc, &removal_op_id).map_err(e)
}

#[tauri::command]
fn core_reset(state: State<'_, Host>, doc: String) -> Result<(), String> {
    state.reset(&doc).map_err(e)
}

#[tauri::command]
fn core_set_moderators(
    state: State<'_, Host>,
    doc: String,
    moderators: Vec<String>,
) -> Result<(), String> {
    state.set_moderators(&doc, moderators).map_err(e)
}

#[tauri::command]
fn core_close(state: State<'_, Host>, doc: String) {
    state.close(&doc);
}

// ---- reads (JSON strings the webview parses, as the wasm veneer returns) ----

#[tauri::command]
fn core_oplog(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.oplog(&doc).map_err(e)
}

#[tauri::command]
fn core_live_records(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.live_records(&doc).map_err(e)
}

#[tauri::command]
fn core_live_claims_of(
    state: State<'_, Host>,
    doc: String,
    target: String,
    predicate: String,
) -> Result<String, String> {
    state.live_claims_of(&doc, &target, &predicate).map_err(e)
}

#[tauri::command]
fn core_live_claims_of_any(
    state: State<'_, Host>,
    doc: String,
    target: String,
) -> Result<String, String> {
    state.live_claims_of_any(&doc, &target).map_err(e)
}

#[tauri::command]
fn core_resolve_id(
    state: State<'_, Host>,
    doc: String,
    anchor: String,
) -> Result<Option<String>, String> {
    state.resolve_id(&doc, &anchor).map_err(e)
}

#[tauri::command]
fn core_pending_count(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.pending_count(&doc).map_err(e)
}

#[tauri::command]
fn core_anomalies(state: State<'_, Host>, doc: String) -> Result<usize, String> {
    state.anomalies(&doc).map_err(e)
}

/// This device's pull frontier (`{replica_hex: counter}`) for the server's GC gate-2 liveness report.
#[tauri::command]
fn core_pull_frontier(
    state: State<'_, Host>,
    doc: String,
) -> Result<std::collections::BTreeMap<String, u64>, String> {
    state.pull_frontier(&doc).map_err(e)
}

// ---- soft-removal review queue (OPE-426) ----

#[tauri::command]
fn core_pending_reviews(state: State<'_, Host>, doc: String) -> Result<String, String> {
    state.pending_reviews(&doc).map_err(e)
}

#[tauri::command]
fn core_approve_pending(
    state: State<'_, Host>,
    doc: String,
    replica: String,
    counter: u64,
) -> Result<bool, String> {
    state.approve_pending(&doc, &replica, counter).map_err(e)
}

#[tauri::command]
fn core_discard_pending(
    state: State<'_, Host>,
    doc: String,
    replica: String,
    counter: u64,
) -> Result<bool, String> {
    state.discard_pending(&doc, &replica, counter).map_err(e)
}

/// Adopt newer keyring revisions the webview fetched (a member/device keyring sync): the host validates the
/// successor `hops` against the stored anchor, persists + retains them, adopts any rotated epoch on the running
/// core (via the retained member secret), and refreshes its §B3 resolver. No Argon2 (pure verification), so a
/// sync command.
#[tauri::command]
fn core_sync_keyring(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    hops: Vec<u8>,
) -> Result<(), String> {
    state
        .sync_keyring(&doc, &TreeId::new(tree_id), &hops)
        .map_err(e)
}

/// Reconcile the latest served DAG anchor against native custody. The host alone classifies stale-local,
/// unchanged, and verified-adopted states; the webview cannot supply or overwrite the local trust anchor.
#[tauri::command]
fn core_sync_dag_anchor(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    anchor: Vec<u8>,
) -> Result<DagKeyringSyncOutcome, String> {
    state
        .sync_dag_anchor(&doc, &TreeId::new(tree_id), &anchor)
        .map_err(e)
}

/// The current stored chain keyring revision (0 if none) — the webview fetches successors from `head + 1` to
/// adopt on a sync tick.
#[tauri::command]
fn core_keyring_head(state: State<'_, Host>, doc: String) -> Result<u32, String> {
    state.keyring_head(&doc).map_err(e)
}

/// The wrapped `KeyringUpdate` (+ raw body for benign-409 comparison) for one retained chain keyring revision —
/// the webview walks `server_head + 1 ..= local_head` and PUTs each to republish its produced tail.
#[tauri::command]
fn core_keyring_publish_payload_at(
    state: State<'_, Host>,
    doc: String,
    revision: u32,
) -> Result<KeyringRevisionPayload, String> {
    state.keyring_publish_payload_at(&doc, revision).map_err(e)
}

/// The wrapped DAG `KeyringUpdate` (+ raw anchor for benign-409 comparison) for the next server revision.
#[tauri::command]
fn core_dag_keyring_publish_payload(
    state: State<'_, Host>,
    doc: String,
    tree_id: Vec<u8>,
    revision: u32,
) -> Result<KeyringRevisionPayload, String> {
    state
        .dag_keyring_publish_payload(&doc, &TreeId::new(tree_id), revision)
        .map_err(e)
}

/// One sync tick against a remote snapshot the webview fetched: the host mirrors it into `doc`'s local store,
/// folds/adopts through the §B3 gate, maybe compacts (when `compact_k > 0`), and returns the objects the remote
/// is missing (for the webview to PUT) plus how many folded. The webview ferries ciphertext + drives the fetch;
/// the DEK, the fold, and the plaintext store stay native.
#[tauri::command]
fn core_sync(
    state: State<'_, Host>,
    doc: String,
    remote: Vec<StoredObject>,
    present: Vec<String>,
    compact_k: u32,
) -> Result<SyncOut, String> {
    state.sync(&doc, &remote, &present, compact_k).map_err(e)
}

/// From a LIST of the remote's keys, the subset the webview must still FETCH — the host drops immutable log
/// objects `doc` already pulled (OPE-464) so the webview doesn't re-download the whole retained log each tick.
#[tauri::command]
fn core_plan_fetch(
    state: State<'_, Host>,
    doc: String,
    keys: Vec<String>,
) -> Result<Vec<String>, String> {
    state.plan_fetch(&doc, &keys).map_err(e)
}

// ---- media blob store (OPE-435/436): durable content-addressed photos/attachments (apps/…/blobs.js) ----
// Each blob is SEALED under its doc's DEK by the host, so a put/get needs the doc UNLOCKED; the content
// address is the SHA-256 of the plaintext. The webview binds the active doc (TauriBlobStore.bindDoc), so
// every call carries `doc`.

/// `blob_put`'s payload — the webview sends `{ args: { bytes, mime, w, h } }`; the host hashes + seals.
#[derive(serde::Deserialize)]
struct BlobPutArgs {
    bytes: Vec<u8>,
    mime: Option<String>,
    w: Option<u32>,
    h: Option<u32>,
}

#[tauri::command]
fn blob_put(state: State<'_, Host>, doc: String, args: BlobPutArgs) -> Result<String, String> {
    state
        .blob_put(&doc, &args.bytes, args.mime, args.w, args.h)
        .map_err(e)
}

#[tauri::command]
fn blob_has(state: State<'_, Host>, doc: String, hash: String) -> Result<bool, String> {
    state.blob_has(&doc, &hash).map_err(e)
}

#[tauri::command]
fn blob_meta(
    state: State<'_, Host>,
    doc: String,
    hash: String,
) -> Result<Option<BlobMeta>, String> {
    state.blob_meta(&doc, &hash).map_err(e)
}

#[tauri::command]
fn blob_get(state: State<'_, Host>, doc: String, hash: String) -> Result<Option<BlobData>, String> {
    state.blob_get(&doc, &hash).map_err(e)
}

#[tauri::command]
fn blob_delete(state: State<'_, Host>, doc: String, hash: String) -> Result<(), String> {
    state.blob_delete(&doc, &hash).map_err(e)
}

/// Seal arbitrary client-owned secret bytes under `doc`'s tree DEK (OPE-453) — the durable invite mint record.
/// Returns the wire envelope the webview stores in place of the plaintext; the DEK stays native.
#[tauri::command]
fn core_seal_app_secret(
    state: State<'_, Host>,
    doc: String,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    state.seal_app_secret(&doc, &bytes).map_err(e)
}

/// Open an app-secret envelope sealed by `core_seal_app_secret` under `doc`'s DEK.
#[tauri::command]
fn core_open_app_secret(
    state: State<'_, Host>,
    doc: String,
    sealed: Vec<u8>,
) -> Result<Vec<u8>, String> {
    state.open_app_secret(&doc, &sealed).map_err(e)
}

#[tauri::command]
fn blob_list(state: State<'_, Host>, doc: String) -> Result<Vec<String>, String> {
    state.blob_list(&doc).map_err(e)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // The app data dir holds the durable keyring/watermark store (vault.sqlite); each doc's local
            // device store is a FsBlob rooted under docs/{doc}. Kept separate so a copied/restored tree can't
            // drag the anti-rollback watermark with it.
            let dir = app.path().app_data_dir().expect("app data dir");
            std::fs::create_dir_all(&dir).ok();
            // Fail-closed surfacing (NOT `.expect`): in a release build SqliteVaultStore::open errors on a schema
            // mismatch instead of destroying data (store-schema). Turning that into a `.expect` panic would be a
            // silent crash at boot (release hides the console) — so log an actionable message to stderr/logcat and
            // abort startup cleanly. A native dialog (tauri-plugin-dialog) is a follow-up.
            let vault = match SqliteVaultStore::open(dir.join("vault.sqlite")) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[openom] cannot open the vault store: {e}\n\
                         This tree's local data may have been written by a newer version of the app — please \
                         update the app. (Dev: remove the app data dir to start fresh.)"
                    );
                    return Err(format!("vault store: {e}").into());
                }
            };
            let host = AppCoreHost::new(vault, dir.join("docs"), keyring_engine());
            app.manage(Arc::new(host));
            // Media (photos/attachments) lives in per-doc {doc}.media.sqlite files the host opens on demand,
            // each blob SEALED under its doc's DEK (OPE-435/436) — no separate managed store.
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            core_has_keyring,
            account_create,
            account_unlock,
            account_status,
            account_lock,
            account_recover,
            account_change_passphrase,
            account_rotate_root,
            account_register_proof,
            account_public_identity,
            account_snapshot,
            account_sync_state,
            account_confirm_binding,
            account_stage_backup,
            account_acknowledge_backup,
            account_adopt_candidate,
            account_adopt_recovery_candidate,
            core_provision,
            core_unlock,
            core_derive_member_id,
            core_add_member,
            core_remove_member,
            core_change_role,
            core_join_as_member,
            core_join_dag_anchor,
            core_bootstrap,
            core_assert_anchor,
            core_commit,
            core_can_commit_directly,
            core_open_history_delta,
            core_propose,
            core_approve_proposal,
            core_fold,
            core_project,
            core_keyring_publish_payload,
            core_membership_summary,
            core_invite_pin,
            core_invite_material,
            core_assert_claim,
            core_supersede_claim,
            core_remove_record,
            core_revoke,
            core_reset,
            core_set_moderators,
            core_close,
            core_oplog,
            core_live_records,
            core_live_claims_of,
            core_live_claims_of_any,
            core_resolve_id,
            core_pending_count,
            core_anomalies,
            core_pull_frontier,
            core_pending_reviews,
            core_approve_pending,
            core_discard_pending,
            core_sync_keyring,
            core_sync_dag_anchor,
            core_keyring_head,
            core_keyring_publish_payload_at,
            core_dag_keyring_publish_payload,
            core_sync,
            core_plan_fetch,
            blob_put,
            blob_has,
            blob_meta,
            blob_get,
            blob_delete,
            blob_list,
            core_seal_app_secret,
            core_open_app_secret
        ])
        .run(tauri::generate_context!())
        .expect("error while running openom");
}
