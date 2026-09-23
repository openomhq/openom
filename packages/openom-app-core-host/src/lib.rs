#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use openom_app_core::{AccountHandle, AppCore, StoredObject};
use openom_crypto::{Passphrase, RecoveryCode};
use openom_keyring_api::EngineKind;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_vault_host::{
    AccountBackupVersion as StoredAccountBackupVersion, AccountBinding,
    AccountBlobHash as StoredAccountBlobHash, AccountGeneration, AccountGenerationFloor,
    AccountIdentityRecord, AccountKeystore, AccountMemberId, AccountRecord,
    AccountRemoteCheckpoint, PendingAccountBackup, PendingBackupKind, VaultStore,
};
use store_blob::{BlobStore, FsBlob, Precondition};
use store_media::MediaStore;
pub use store_media::{BlobData, BlobMeta};

/// A live core: an `AppCore` behind its own `Mutex` (Tauri invokes race on a thread pool).
pub type CoreHandle = Arc<Mutex<AppCore<FsBlob>>>;
/// The per-doc registry, keyed by doc id.
type CoreMap = HashMap<String, CoreHandle>;

/// A fresh, ephemeral replica id (16 bytes from the OS CSPRNG) minted per open. NEVER a caller argument: a
/// repeated replica id forks the per-replica counter chain (an anti-fork security property), and a fresh id per
/// open is also what lets a re-opened core pull its own previously-persisted entries as a peer (OPE-431).
fn fresh_replica() -> Result<[u8; 16], HostError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| HostError::Store(format!("csprng: {e}")))?;
    Ok(id)
}

/// Reject a `doc` id that could escape `data_dir` (the webview supplies it, so `../..` etc. must never reach a
/// filesystem join). A doc id is a tree key: non-empty and made only of url-safe id characters.
fn checked_doc(doc: &str) -> Result<&str, HostError> {
    let ok = !doc.is_empty()
        && doc.len() <= 128
        && doc
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(doc)
    } else {
        Err(HostError::Store(format!("invalid doc id: {doc:?}")))
    }
}

/// Wall-clock milliseconds for mint timestamps (the native analog of the wasm veneer's `now_millis`).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// A host failure: a keyring-engine error, a keyring-store I/O error, or an operation on a tree the host has no
/// keyring for.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The keyring engine rejected the lifecycle op (wrong passphrase, stale keyring, malformed anchor).
    #[error(transparent)]
    Vault(#[from] openom_app_core::VaultError),
    /// The core (fold / commit / bootstrap / sync) failed — a local store I/O or engine fault.
    #[error(transparent)]
    Core(#[from] openom_app_core::CoreError),
    /// The claim engine rejected a mint (un-canonicalizable value, malformed op).
    #[error(transparent)]
    Tree(#[from] openom_data_tree::TreeError),
    /// The native keyring/watermark store failed (I/O, CAS).
    #[error("keyring store: {0}")]
    Store(String),
    /// Durable account-candidate persistence failed after credential verification.
    #[error("account storage unavailable: {0}")]
    AccountStorage(String),
    /// A credential-authenticated candidate did not match the member id bound to the authenticated subject.
    #[error("account identity conflict: {0}")]
    IdentityConflict(String),
    /// No keyring is stored for this tree — the host can't unlock a tree it never provisioned/joined.
    #[error("no keyring stored for {0}")]
    NoKeyring(String),
    /// No live core for this tree — provision or unlock it first.
    #[error("no live core for {0}")]
    NoCore(String),
    /// No profile account is currently unlocked in the native process.
    #[error("no unlocked profile account")]
    NoAccount,
}

/// The stable UI error-code for a [`HostError`] (the app's error registry). The Tauri command layer returns
/// `{code, message}` so the webview renders the same tamper / rollback / wrong-passphrase distinctions on the
/// native host as the wasm veneer does — the `AppError` contract, alive on both runtimes.
#[must_use]
pub fn error_code(err: &HostError) -> &'static str {
    match err {
        HostError::Vault(v) => openom_app_core::vault_error_code(v),
        HostError::IdentityConflict(_) => openom_app_core::error_codes::IDENTITY_CONFLICT,
        HostError::Store(message) if message.contains("account record conflict") => {
            openom_app_core::error_codes::VERSION_CONFLICT
        }
        HostError::AccountStorage(_) => openom_app_core::error_codes::STORAGE_BLOCKED,
        HostError::Core(_)
        | HostError::Tree(_)
        | HostError::Store(_)
        | HostError::NoKeyring(_)
        | HostError::NoCore(_)
        | HostError::NoAccount => openom_app_core::error_codes::INTERNAL,
    }
}

/// The result of [`AppCoreHost::provision`] — the durable core is registered in the host; the caller gets only
/// what it shows the user (the recovery code) + the author identity.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provisioned {
    pub did_key: String,
}

/// Account creation/recovery output. The wrapped keystore remains in native `SQLite`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountOpened {
    pub recovery_code: String,
    pub generation: u64,
}

/// Observable custody state for the profile account. Public identity is available only while unlocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    None,
    Locked,
    Unlocked,
}

/// Public admission identity for the resident profile account.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountIdentity {
    pub member_id: String,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// Account credential-change output.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountChanged {
    pub generation: u64,
}

/// Exact wrapped account bytes and the backup version authenticated by the resident Rust handle.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSnapshot {
    pub keystore: Vec<u8>,
    pub generation: u64,
    pub blob_hash: Vec<u8>,
}

/// A fetched candidate that was credential-verified, durably committed, and installed as resident custody.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAdopted {
    pub member_id: String,
    pub recovery_code: String,
    pub generation: u64,
    pub blob_hash: Vec<u8>,
}

/// Non-secret account-record version exposed to the sync coordinator.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncVersion {
    pub generation: u64,
    pub blob_hash: Vec<u8>,
}

/// Server-confirmed provider binding exposed to the sync coordinator.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncBinding {
    pub issuer: String,
    pub subject: String,
    pub member_id: String,
}

/// Last remote ETag/version acknowledged for this binding.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncCheckpoint {
    pub etag: String,
    pub version: Option<AccountSyncVersion>,
}

/// Durable operation intent, pinned to an exact local version and auth binding.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncPending {
    pub kind: PendingBackupKind,
    pub version: AccountSyncVersion,
    pub binding: AccountSyncBinding,
}

/// Identity-scoped custody metadata without the wrapped keystore bytes.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncIdentity {
    pub member_id: String,
    pub version: AccountSyncVersion,
    pub floor: u64,
    pub effective_floor: u64,
}

/// Non-secret projection of the native local account record.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncRecord {
    pub revision: u64,
    pub identity: AccountSyncIdentity,
    pub retained_identities: Vec<AccountSyncIdentity>,
    pub binding: Option<AccountSyncBinding>,
    pub acknowledged_backup: Option<AccountSyncCheckpoint>,
    pub pending_backup: Option<AccountSyncPending>,
}

/// Native account-sync state. Native `SQLite` is durable without browser persistence grants.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSyncState {
    pub record: Option<AccountSyncRecord>,
    pub storage_persistence: &'static str,
}

/// Result of exact pending-operation compare-and-clear.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBackupAcknowledged {
    pub cleared: bool,
    pub record: Option<AccountSyncRecord>,
    pub storage_persistence: &'static str,
}

/// Compatibility shape for callers transitioning to [`AppCoreHost::account_public_identity`]. `kdf_params`
/// is always empty because member credentials are no longer provisioned per tree.
#[cfg(test)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberAccount {
    pub kdf_params: Vec<u8>,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// One chain keyring revision's publish payload (see [`AppCoreHost::keyring_publish_payload_at`]): the wrapped
/// `KeyringUpdate` the webview PUTs, plus the raw keyring state it compares against the server's served bytes to
/// distinguish a benign already-admitted revision from a fork.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyringRevisionPayload {
    pub update: Vec<u8>,
    pub body: Vec<u8>,
}

/// What the native invite MINT needs from the keyring so the webview's `invite.mint` (pure JS) stays
/// engine-agnostic: the FULL v3 pin (chain: `rev(u32 BE)‖kh(32)` = 36 bytes; dag: the opaque `dagAnchorPin`) and
/// the `engine` tag. (The admit-gate signer fingerprint is derived separately from the engine-agnostic keyring
/// summary, so it isn't needed here.)
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMaterial {
    pub engine: String,
    pub pin: Vec<u8>,
}

/// The result of [`AppCoreHost::open_tree`] — the core is registered in the host; the caller gets the author
/// identity + the four advisory repair flags.
// Four INDEPENDENT repair signals, mirroring the core's `Unlocked` — not a state enum.
#[derive(serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    pub did_key: String,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
    pub needs_rrk_backfill: bool,
    pub write_epoch_unreachable: bool,
}

/// The OOB-verified joiner an owner admits via [`AppCoreHost::add_tree_member`] — the id + role + the two public
/// keys the joiner shared out of band (from their profile account). NOT trust-bearing custody: these are the
/// owner's own OOB-verified inputs, distinct from the keyring/floor the host sources natively.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberToAdd {
    pub member_id: String,
    pub role: String,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

/// The result of [`AppCoreHost::add_tree_member`] — the opaque new keyring revision for the webview to PUBLISH (so
/// peers + the joiner can pull it). The owner's running core has already been re-opened in place on the shared
/// keyring (so its sealer now signs). Publish keyring FIRST, then the advisory summary (OPE-293 add ordering).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedMember {
    pub keyring: Vec<u8>,
    /// Whether this add flipped solo→shared — the caller seals + pushes a signed base of the owner's pre-share
    /// history on the first share so a joiner can bootstrap the whole tree (OPE-360 §5).
    pub first_share: bool,
}

/// The result of [`AppCoreHost::remove_tree_member`] — the opaque ROTATED keyring revision for the webview to
/// PUBLISH, and whether the departing member's landed history was pinned by a snapshot before the rotation.
/// `history_preserved == false` means the removal ran before the departing member's writes were pulled/covered
/// (offline or a very-last-second edit), so in-transit preservation was reduced — the client look-behind still
/// rejects forgeries, so this is an availability/audit signal, not a security one (design-review Q2). On a
/// removal the webview publishes the ADVISORY summary FIRST, then the keyring (OPE-293 remove ordering), then a
/// data sync to push the self-heal cover.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedMember {
    pub keyring: Vec<u8>,
    pub history_preserved: bool,
}

/// The result of [`AppCoreHost::change_tree_member_role`] — the opaque new keyring revision to publish, and
/// whether it was a DEMOTE. No epoch rotation (a role change touches signing authority, not keys), so the
/// owner's running core keeps its sealer; only its §B3 resolver refreshes. The webview publishes a PROMOTE
/// keyring-first, but a DEMOTE advisory-FIRST — the restrictive change must land before the crypto that
/// authorizes it (design-review F8 / OPE-293).
#[derive(serde::Serialize)]
pub struct RoleChanged {
    pub keyring: Vec<u8>,
    pub demote: bool,
}

/// The result of [`AppCoreHost::join_chain_tree`] / [`AppCoreHost::join_dag_tree`] — the member's author
/// identity; the ready member core is registered in the host.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberUnlocked {
    pub did_key: String,
}

/// One object the webview must PUT after a sync tick: its key + bytes + whether it's a POINTER (heads/snapshot —
/// overwrite) vs an immutable log object (If-None-Match). The core decides `pointer` (from the key); the webview
/// ferries it without inspecting the key.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadObject {
    pub key: String,
    pub bytes: Vec<u8>,
    pub pointer: bool,
}

/// The result of [`AppCoreHost::sync`] — the objects to upload (each with its `pointer` flag), how many entries
/// folded, and the `covered` frontier (`{replica: counter}`) the webview sends as the snapshot's
/// `x-openom-covered` GC header.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOut {
    pub uploads: Vec<UploadObject>,
    pub folded: usize,
    pub covered: std::collections::BTreeMap<String, u64>,
}

/// The result of [`AppCoreHost::recover`] — the new recovery code to show once + the author identity + the two
/// advisory repair flags; the fresh keyring/watermark are persisted natively and the core registered.
#[cfg(test)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // four INDEPENDENT repair signals, mirroring the veneer's OpenResult
pub struct Recovered {
    pub recovery_code: String,
    pub did_key: String,
    pub needs_reseal: bool,
    pub needs_backfill: bool,
    /// Recovery mints a fresh escrow reaching every epoch, so these are always `false` — present only so the
    /// native recovery result matches the account-plus-tree composition used by the veneer (M2).
    pub needs_rrk_backfill: bool,
    pub write_epoch_unreachable: bool,
}

/// The result of [`AppCoreHost::change_passphrase`] — the rotated recovery code; the re-wrapped keyring +
/// watermark are persisted natively. The DEK is unchanged, so the running core keeps working (no re-open).
#[cfg(test)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseChanged {
    pub recovery_code: String,
}

/// The native app-core host. `store` holds the keyring anchor + anti-rollback watermark per tree; `data_dir`
/// roots each doc's local device `FsBlob`; `engine` is the keyring engine for NEW trees (existing trees carry
/// their own in the keyring). Live cores are held per-doc behind a `Mutex`.
pub struct AppCoreHost<St: VaultStore> {
    store: St,
    data_dir: PathBuf,
    engine: EngineKind,
    cores: Mutex<CoreMap>,
    /// The one unlocked profile account shared by every owned and joined tree session.
    account: Mutex<Option<AccountHandle>>,
    /// Serializes the complete profile-account read/verify/mutate/commit/install protocol.
    account_ops: Mutex<()>,
    /// Per-doc EXCLUSIVE operation lock. Every op that opens a core or writes the keyring (the provision /
    /// unlock / recover / change-passphrase / join / member-unlock / membership / keyring-sync paths) holds it
    /// across its whole body, so a re-open's check-then-commit can't be raced by another open of the same doc
    /// (the join re-join-guard TOCTOU) and store writes never interleave. This coarser lock closes the
    /// no-core-yet window the core `Arc`'s own `Mutex` can't cover.
    op_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Per-doc media stores (photos/attachments), opened lazily and cached. Each is a `{doc}.media.sqlite`
    /// under `data_dir` holding blobs SEALED under that doc's DEK (OPE-435/436) — see [`media_store`](Self::media_store).
    media_stores: Mutex<HashMap<String, Arc<MediaStore>>>,
}

impl<St: VaultStore> AppCoreHost<St> {
    /// A host over `store` (keyring/watermark custody), rooting each doc's local device store under `data_dir`.
    pub fn new(store: St, data_dir: impl Into<PathBuf>, engine: EngineKind) -> Self {
        Self {
            store,
            data_dir: data_dir.into(),
            engine,
            cores: Mutex::new(HashMap::new()),
            account: Mutex::new(None),
            account_ops: Mutex::new(()),
            op_locks: Mutex::new(HashMap::new()),
            media_stores: Mutex::new(HashMap::new()),
        }
    }

    /// This doc's exclusive op-lock (created on first use). Callers hold the returned guard for the whole op.
    fn op_lock(&self, doc: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.op_locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(doc.to_string())
                .or_default(),
        )
    }

    fn account_op(&self) -> std::sync::MutexGuard<'_, ()> {
        self.account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The keyring/watermark store (for the Tauri command layer to reach the native custody).
    pub const fn store(&self) -> &St {
        &self.store
    }

    fn with_account<T>(
        &self,
        f: impl FnOnce(&AccountHandle) -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        let account = self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(account.as_ref().ok_or(HostError::NoAccount)?)
    }

    fn snapshot_wire(snapshot: openom_app_core::AccountSnapshot) -> AccountSnapshot {
        let version = snapshot.version();
        AccountSnapshot {
            keystore: snapshot.into_keystore(),
            generation: version.generation().get(),
            blob_hash: version.blob_hash().as_bytes().to_vec(),
        }
    }

    fn sync_version(version: StoredAccountBackupVersion) -> AccountSyncVersion {
        AccountSyncVersion {
            generation: version.generation().get(),
            blob_hash: version.blob_hash().as_bytes().to_vec(),
        }
    }

    fn sync_binding(binding: &AccountBinding) -> AccountSyncBinding {
        AccountSyncBinding {
            issuer: binding.issuer().to_string(),
            subject: binding.subject().to_string(),
            member_id: binding.member_id().as_str().to_string(),
        }
    }

    fn sync_record(record: &AccountRecord) -> AccountSyncRecord {
        let sync_identity = |identity: &AccountIdentityRecord| AccountSyncIdentity {
            member_id: identity.member_id().as_str().to_string(),
            version: Self::sync_version(identity.version()),
            floor: identity.persisted_floor().get(),
            effective_floor: identity.effective_floor().get(),
        };
        AccountSyncRecord {
            revision: record.revision().get(),
            identity: sync_identity(record.identity()),
            retained_identities: record
                .retained_identities()
                .iter()
                .map(sync_identity)
                .collect(),
            binding: record.binding().map(Self::sync_binding),
            acknowledged_backup: record.acknowledged_backup().map(|checkpoint| {
                AccountSyncCheckpoint {
                    etag: checkpoint.etag().to_string(),
                    version: checkpoint.version().map(Self::sync_version),
                }
            }),
            pending_backup: record.pending_backup().map(|pending| AccountSyncPending {
                kind: pending.kind(),
                version: Self::sync_version(pending.version()),
                binding: Self::sync_binding(pending.binding()),
            }),
        }
    }

    fn sync_state(record: Option<&AccountRecord>) -> AccountSyncState {
        AccountSyncState {
            record: record.map(Self::sync_record),
            storage_persistence: "native",
        }
    }

    fn stored_identity(handle: &AccountHandle) -> AccountIdentityRecord {
        let snapshot = openom_app_core::account_snapshot(handle);
        let version = snapshot.version();
        let generation = AccountGeneration::new(version.generation().get());
        AccountIdentityRecord::new(
            AccountMemberId::new(handle.member_id().as_str()),
            AccountKeystore::new(snapshot.into_keystore()),
            StoredAccountBackupVersion::new(
                generation,
                StoredAccountBlobHash::new(*version.blob_hash().as_bytes()),
            ),
            AccountGenerationFloor::new(generation.get()),
        )
    }

    fn next_account_record(
        current: Option<&AccountRecord>,
        handle: &AccountHandle,
        pending_kind: Option<PendingBackupKind>,
    ) -> Result<AccountRecord, HostError> {
        let identity = Self::stored_identity(handle);
        match current {
            Some(record) => record
                .next_identity(identity, pending_kind)
                .map_err(HostError::Store),
            None => Ok(AccountRecord::new(identity)),
        }
    }

    fn persist_account_handle(
        &self,
        current: Option<&AccountRecord>,
        handle: &AccountHandle,
        pending_kind: Option<PendingBackupKind>,
    ) -> Result<AccountRecord, HostError> {
        let next = Self::next_account_record(current, handle, pending_kind)?;
        self.persist_account_record(current, &next)
    }

    fn persist_account_record(
        &self,
        current: Option<&AccountRecord>,
        next: &AccountRecord,
    ) -> Result<AccountRecord, HostError> {
        self.store
            .commit_account(next, current.map(AccountRecord::revision))
            .map_err(HostError::Store)?;
        if self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .as_ref()
            != Some(next)
        {
            return Err(HostError::Store(
                "account persistence verification failed".into(),
            ));
        }
        Ok(next.clone())
    }

    fn commit_candidate(
        &self,
        current: Option<&AccountRecord>,
        handle: AccountHandle,
        recovery_code: String,
        binding: AccountBinding,
        checkpoint: AccountRemoteCheckpoint,
        pending_kind: Option<PendingBackupKind>,
    ) -> Result<AccountAdopted, HostError> {
        let member_id = handle.member_id().as_str().to_string();
        let snapshot = Self::snapshot_wire(openom_app_core::account_snapshot(&handle));
        let next = Self::next_account_record(current, &handle, None)?
            .finish_remote_adoption(binding, checkpoint, pending_kind)
            .map_err(HostError::Store)?;
        self.persist_account_record(current, &next)
            .map_err(|error| match error {
                HostError::Store(message) if !message.contains("account record conflict") => {
                    HostError::AccountStorage(message)
                }
                other => other,
            })?;
        self.lock_cores().clear();
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
        Ok(AccountAdopted {
            member_id,
            recovery_code,
            generation: snapshot.generation,
            blob_hash: snapshot.blob_hash,
        })
    }

    /// Report whether this profile has no account, a persisted locked account, or a resident unlocked account.
    ///
    /// # Errors
    /// Returns [`HostError::Store`] when persisted account custody cannot be read.
    pub fn account_status(&self) -> Result<AccountStatus, HostError> {
        let _operation = self.account_op();
        if self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            return Ok(AccountStatus::Unlocked);
        }
        Ok(
            if self
                .store
                .load_account()
                .map_err(HostError::Store)?
                .is_some()
            {
                AccountStatus::Locked
            } else {
                AccountStatus::None
            },
        )
    }

    /// Drop every live tree core and the resident profile account. Persisted ciphertext remains untouched.
    pub fn account_lock(&self) {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.lock_cores().clear();
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Create and persist the profile account, leaving its secrets resident for tree operations.
    ///
    /// # Errors
    /// Returns [`HostError`] if an account already exists, account creation fails, or persistence fails.
    pub fn account_create(&self, passphrase: &Passphrase) -> Result<AccountOpened, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.store.load_account().map_err(HostError::Store)?;
        if current.is_some() {
            return Err(HostError::Store("profile account already exists".into()));
        }
        let created = openom_app_core::account_create(passphrase)?;
        self.persist_account_handle(None, &created.handle, None)?;
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(created.handle);
        Ok(AccountOpened {
            recovery_code: created.recovery_code,
            generation: created.generation.get(),
        })
    }

    /// Unlock the persisted profile account and retain its live handle in native memory.
    ///
    /// # Errors
    /// Returns [`HostError`] if no account exists, the passphrase is wrong, or persistence cannot be read.
    pub fn account_unlock(&self, passphrase: &Passphrase) -> Result<AccountIdentity, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let handle = openom_app_core::account_unlock(
            passphrase,
            record.identity().keystore().as_bytes(),
            openom_app_core::AccountGeneration::new(record.identity().effective_floor().get()),
        )?;
        if handle.member_id().as_str() != record.identity().member_id().as_str() {
            return Err(HostError::Store(
                "stored account member id does not match authenticated keystore".into(),
            ));
        }
        let identity = openom_app_core::account_public_identity(&handle);
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
        Ok(AccountIdentity {
            member_id: identity.member_id,
            author_public_key: identity.author_public_key,
            hpke_public_key: identity.hpke_public_key,
        })
    }

    /// Return the resident account's public admission identity.
    ///
    /// # Errors
    /// Returns [`HostError::NoAccount`] when the profile account is locked.
    pub fn account_public_identity(&self) -> Result<AccountIdentity, HostError> {
        let _operation = self.account_op();
        self.with_account(|account| {
            let identity = openom_app_core::account_public_identity(account);
            Ok(AccountIdentity {
                member_id: identity.member_id,
                author_public_key: identity.author_public_key,
                hpke_public_key: identity.hpke_public_key,
            })
        })
    }

    /// Return the exact wrapped bytes and authenticated backup version for the resident account.
    ///
    /// # Errors
    /// Returns [`HostError::NoAccount`] when the profile account is locked.
    pub fn account_snapshot(&self) -> Result<AccountSnapshot, HostError> {
        let _operation = self.account_op();
        self.with_account(|account| {
            Ok(Self::snapshot_wire(openom_app_core::account_snapshot(
                account,
            )))
        })
    }

    /// Return the non-secret local account journal used by the network sync coordinator.
    ///
    /// # Errors
    /// Returns [`HostError::Store`] when persisted account custody cannot be read.
    pub fn account_sync_state(&self) -> Result<AccountSyncState, HostError> {
        let _operation = self.account_op();
        let record = self.store.load_account().map_err(HostError::Store)?;
        Ok(Self::sync_state(record.as_ref()))
    }

    /// Persist the exact provider subject the server confirmed for this durable identity.
    ///
    /// # Errors
    /// Returns [`HostError`] when no local account exists, the binding mismatches, or persistence fails.
    pub fn account_confirm_binding(
        &self,
        binding: AccountBinding,
    ) -> Result<AccountSyncState, HostError> {
        let _operation = self.account_op();
        let current = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let next = current.confirm_binding(binding).map_err(HostError::Store)?;
        let committed = if next.revision() == current.revision() {
            current
        } else {
            self.persist_account_record(Some(&current), &next)?
        };
        Ok(Self::sync_state(Some(&committed)))
    }

    /// Journal an account backup/revocation before the network request begins.
    ///
    /// # Errors
    /// Returns [`HostError`] when the binding is not confirmed or persistence fails.
    pub fn account_stage_backup(
        &self,
        kind: PendingBackupKind,
        binding: AccountBinding,
    ) -> Result<AccountSyncState, HostError> {
        let _operation = self.account_op();
        let current = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let next = current
            .stage_backup(kind, binding)
            .map_err(HostError::Store)?;
        let committed = if next.revision() == current.revision() {
            current
        } else {
            self.persist_account_record(Some(&current), &next)?
        };
        Ok(Self::sync_state(Some(&committed)))
    }

    /// Compare-and-clear exactly the pending operation acknowledged by the server.
    ///
    /// # Errors
    /// Returns [`HostError`] when the checkpoint is invalid or persistence fails.
    pub fn account_acknowledge_backup(
        &self,
        expected: &PendingAccountBackup,
        checkpoint: AccountRemoteCheckpoint,
    ) -> Result<AccountBackupAcknowledged, HostError> {
        let _operation = self.account_op();
        let current = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let Some(next) = current
            .acknowledge_backup(expected, checkpoint)
            .map_err(HostError::Store)?
        else {
            return Ok(AccountBackupAcknowledged {
                cleared: false,
                record: Some(Self::sync_record(&current)),
                storage_persistence: "native",
            });
        };
        let committed = self.persist_account_record(Some(&current), &next)?;
        Ok(AccountBackupAcknowledged {
            cleared: true,
            record: Some(Self::sync_record(&committed)),
            storage_persistence: "native",
        })
    }

    /// Verify and durably adopt a fetched account blob with a passphrase.
    ///
    /// # Errors
    /// Returns [`HostError`] without changing resident custody when verification or persistence fails.
    pub fn account_adopt_candidate(
        &self,
        expected_member_id: &AccountMemberId,
        candidate: &[u8],
        passphrase: &Passphrase,
        binding: AccountBinding,
        checkpoint: AccountRemoteCheckpoint,
    ) -> Result<AccountAdopted, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.store.load_account().map_err(HostError::Store)?;
        let floor = current.as_ref().map_or(0, |record| {
            record.floor_for_member(expected_member_id).get()
        });
        let handle = openom_app_core::account_open_candidate(
            passphrase,
            candidate,
            openom_app_core::AccountGeneration::new(floor),
        )?;
        if handle.member_id().as_str() != expected_member_id.as_str() {
            return Err(HostError::IdentityConflict(
                "account candidate member id does not match the bound remote identity".into(),
            ));
        }
        self.commit_candidate(
            current.as_ref(),
            handle,
            String::new(),
            binding,
            checkpoint,
            None,
        )
    }

    /// Verify, rotate, and durably adopt a fetched account blob with a recovery credential.
    ///
    /// # Errors
    /// Returns [`HostError`] without changing resident custody when verification, rotation, or persistence
    /// fails.
    pub fn account_adopt_recovery_candidate(
        &self,
        expected_member_id: &AccountMemberId,
        candidate: &[u8],
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
        binding: AccountBinding,
        checkpoint: AccountRemoteCheckpoint,
    ) -> Result<AccountAdopted, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.store.load_account().map_err(HostError::Store)?;
        let floor = current.as_ref().map_or(0, |record| {
            record.floor_for_member(expected_member_id).get()
        });
        let recovered = openom_app_core::account_recover_candidate(
            recovery_code,
            new_passphrase,
            candidate,
            openom_app_core::AccountGeneration::new(floor),
        )?;
        if recovered.handle.member_id().as_str() != expected_member_id.as_str() {
            return Err(HostError::IdentityConflict(
                "account candidate member id does not match the bound remote identity".into(),
            ));
        }
        self.commit_candidate(
            current.as_ref(),
            recovered.handle,
            recovered.recovery_code,
            binding,
            checkpoint,
            Some(PendingBackupKind::Revoke),
        )
    }

    /// Recover and rotate the singleton account, atomically persisting its new generation.
    ///
    /// # Errors
    /// Returns [`HostError`] if the recovery code is invalid, the account is stale, or persistence fails.
    pub fn account_recover(
        &self,
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
    ) -> Result<AccountOpened, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let recovered = openom_app_core::account_recover(
            recovery_code,
            new_passphrase,
            record.identity().keystore().as_bytes(),
            openom_app_core::AccountGeneration::new(record.identity().effective_floor().get()),
        )?;
        self.persist_account_handle(
            Some(&record),
            &recovered.handle,
            Some(PendingBackupKind::Revoke),
        )?;
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(recovered.handle);
        Ok(AccountOpened {
            recovery_code: recovered.recovery_code,
            generation: recovered.generation.get(),
        })
    }

    /// Re-wrap the singleton account without touching any tree keyring.
    ///
    /// # Errors
    /// Returns [`HostError`] if the account is locked, wrapping fails, or persistence fails.
    pub fn account_change_passphrase(
        &self,
        new_passphrase: &Passphrase,
    ) -> Result<AccountChanged, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let mut resident = self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = openom_app_core::account_change_passphrase(
            resident.as_mut().ok_or(HostError::NoAccount)?,
            new_passphrase,
        )?;
        let handle = resident.as_ref().ok_or(HostError::NoAccount)?;
        if let Err(error) =
            self.persist_account_handle(Some(&record), handle, Some(PendingBackupKind::Backup))
        {
            *resident = None;
            return Err(error);
        }
        Ok(AccountChanged {
            generation: changed.generation.get(),
        })
    }

    /// Rotate the account wrapping root, recovery code, and authenticated generation.
    ///
    /// # Errors
    /// Returns [`HostError`] if the account is locked, the passphrase is wrong, rotation fails, or persistence
    /// fails. A persistence failure locks the resident account rather than retaining uncommitted root material.
    pub fn account_rotate_root(&self, passphrase: &Passphrase) -> Result<AccountOpened, HostError> {
        let _operation = self
            .account_ops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .ok_or(HostError::NoAccount)?;
        let mut resident = self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rotated = openom_app_core::account_rotate_root(
            resident.as_mut().ok_or(HostError::NoAccount)?,
            passphrase,
        )?;
        let handle = resident.as_ref().ok_or(HostError::NoAccount)?;
        if let Err(error) =
            self.persist_account_handle(Some(&record), handle, Some(PendingBackupKind::Revoke))
        {
            *resident = None;
            return Err(error);
        }
        Ok(AccountOpened {
            recovery_code: rotated.recovery_code,
            generation: rotated.generation.get(),
        })
    }

    /// Sign the server's frozen account-registration proof bytes inside native custody.
    ///
    /// # Errors
    /// Returns [`HostError::NoAccount`] when the profile account is locked.
    pub fn account_register_proof(
        &self,
        issuer: &str,
        subject: &str,
        timestamp: i64,
    ) -> Result<Vec<u8>, HostError> {
        let _operation = self.account_op();
        self.with_account(|account| {
            Ok(openom_app_core::account_register_proof(
                account, issuer, subject, timestamp,
            ))
        })
    }

    /// This doc's local device store: a `FsBlob` under `data_dir/{doc}`. The `doc` id is validated first so a
    /// webview-supplied value can never traverse out of `data_dir`.
    fn doc_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(checked_doc(doc)?);
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
    }

    /// This doc's chain keyring-revision RETENTION store — a native `FsBlob` at `data_dir/{doc}.kr`, holding one
    /// object per accepted keyring revision keyed by its zero-padded revision number. The §B3 look-behind needs
    /// these prior revisions to judge a write against the membership that governed it at creation (design-review
    /// F5): after a rotation the head alone can't say whether a pre-rotation author was authorized THEN. Kept in
    /// native custody, alongside the head — never fed from the webview. Sibling dir (`.kr` can't collide with
    /// another doc: `checked_doc` forbids `.`). The dag resolver ignores retention (it resolves from the anchor).
    fn retention_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(format!("{}.kr", checked_doc(doc)?));
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
    }

    /// Retain an accepted keyring `revision`'s bytes natively (idempotent).
    fn retain_revision(&self, doc: &str, revision: u32, keyring: &[u8]) -> Result<(), HostError> {
        self.retention_store(doc)?
            .put(&format!("{revision:010}"), keyring, Precondition::Any)
            .map_err(|e| HostError::Store(e.to_string()))?;
        Ok(())
    }

    /// The `(revision, keyring)` pairs retained so far — the prior-revision set the §B3 resolver looks behind to.
    fn retained_revisions(&self, doc: &str) -> Result<Vec<(u32, Vec<u8>)>, HostError> {
        let store = self.retention_store(doc)?;
        let mut out = Vec::new();
        for (key, _etag) in store
            .list("")
            .map_err(|e| HostError::Store(e.to_string()))?
        {
            if let Ok(rev) = key.parse::<u32>() {
                if let Some((bytes, _etag)) = store
                    .get(&key)
                    .map_err(|e| HostError::Store(e.to_string()))?
                {
                    out.push((rev, bytes));
                }
            }
        }
        Ok(out)
    }

    /// Native custody for the chain join's non-secret trusted signer pin set.
    fn trust_context_store(&self, doc: &str) -> Result<FsBlob, HostError> {
        let dir = self.data_dir.join(format!("{}.trust", checked_doc(doc)?));
        std::fs::create_dir_all(&dir).map_err(|e| HostError::Store(e.to_string()))?;
        Ok(FsBlob::new(dir))
    }

    fn save_trusted_signers(&self, doc: &str, trusted_signers: &[u8]) -> Result<(), HostError> {
        let store = self.trust_context_store(doc)?;
        store
            .put("signers", trusted_signers, Precondition::Any)
            .map_err(|e| HostError::Store(e.to_string()))?;
        Ok(())
    }

    fn load_trusted_signers(&self, doc: &str) -> Result<Vec<u8>, HostError> {
        Ok(self
            .trust_context_store(doc)?
            .get("signers")
            .map_err(|e| HostError::Store(e.to_string()))?
            .map(|(b, _etag)| b)
            .unwrap_or_default())
    }

    /// This doc's MEDIA store — a `{doc}.media.sqlite` under `data_dir`, holding photos/attachments SEALED
    /// under the doc's DEK (OPE-435/436). Opened lazily and cached (a `SQLite` connection per doc), so repeat
    /// `blob_*` calls reuse one handle. Sibling file (`.media.sqlite` can't collide with a `{doc}` dir or the
    /// `.kr`/`.mc` custody dirs: `checked_doc` forbids `.`).
    fn media_store(&self, doc: &str) -> Result<Arc<MediaStore>, HostError> {
        let doc = checked_doc(doc)?;
        let mut map = self
            .media_stores
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(store) = map.get(doc) {
            return Ok(Arc::clone(store));
        }
        std::fs::create_dir_all(&self.data_dir).map_err(|e| HostError::Store(e.to_string()))?;
        let path = self.data_dir.join(format!("{doc}.media.sqlite"));
        let store = Arc::new(MediaStore::open(path).map_err(HostError::Store)?);
        map.insert(doc.to_string(), Arc::clone(&store));
        Ok(store)
    }

    /// Unframe a `[u32-be len][body]…` run (the walk's `bodies_framed`, ascending from genesis) into
    /// `(revision, body)` pairs — revision `r` is the `r-1`-th body.
    fn unframe_revisions(framed: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, HostError> {
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut revision = 1u32;
        while i < framed.len() {
            let end = i
                .checked_add(4)
                .filter(|&e| e <= framed.len())
                .ok_or_else(|| HostError::Store("truncated framed revision length".into()))?;
            let len = u32::from_be_bytes(framed[i..end].try_into().expect("4 bytes")) as usize;
            let body_end = end
                .checked_add(len)
                .filter(|&e| e <= framed.len())
                .ok_or_else(|| HostError::Store("truncated framed revision body".into()))?;
            out.push((revision, framed[end..body_end].to_vec()));
            revision += 1;
            i = body_end;
        }
        Ok(out)
    }

    /// Provision a fresh tree: open a core over the native store, PERSIST the keyring + watermark natively (one
    /// atomic `commit_keyring`), and register the core. Returns the recovery code + author `did:key`.
    ///
    /// # Errors
    /// [`HostError::Vault`] if provisioning fails; [`HostError::Store`] if the keyring can't be persisted.
    pub fn provision_tree(&self, doc: &str, tree_id: &TreeId) -> Result<Provisioned, HostError> {
        let _account_operation = self.account_op();
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let replica = ReplicaId::new(fresh_replica()?);
        let p = self.with_account(|account| {
            openom_app_core::provision_tree(
                self.doc_store(doc)?,
                self.engine,
                account,
                tree_id,
                &replica,
                doc.to_string(),
            )
            .map_err(HostError::from)
        })?;
        self.store
            .commit_keyring(doc, &p.keyring, &p.watermark)
            .map_err(HostError::Store)?;
        // Retain the genesis revision for the §B3 look-behind (a later rotation must still judge writes made
        // under this revision). Chain-meaningful; a harmless unused blob for the dag.
        self.retain_revision(
            doc,
            openom_vault::sharing::chain_watermark_floor(&p.watermark),
            &p.keyring,
        )?;
        self.register(doc, p.core);
        Ok(Provisioned { did_key: p.did_key })
    }

    /// Unlock an existing tree: load the keyring anchor FROM THE NATIVE STORE (never a webview argument — this
    /// is the boundary that stops an XSS feeding a stale/forged keyring), open the core, and register it.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree was never provisioned/joined; [`HostError::Vault`] on a wrong
    /// passphrase / stale keyring; [`HostError::Store`] on a store read failure.
    pub fn open_tree(&self, doc: &str, tree_id: &TreeId) -> Result<Unlocked, HostError> {
        let _account_operation = self.account_op();
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let anchor = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let replica = ReplicaId::new(fresh_replica()?);
        let retained = self.retained_revisions(doc)?;
        let signers = self.load_trusted_signers(doc)?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );
        let (core, result) =
            self.with_account(|account| {
                match openom_app_core::account_tree_role(self.engine, &anchor, account)? {
                    Some(openom_vault::sharing::AccountTreeRole::Founder) => {
                        let opened = openom_app_core::unlock_tree(
                            self.doc_store(doc)?,
                            self.engine,
                            account,
                            tree_id,
                            &replica,
                            &anchor,
                            doc.to_string(),
                        )?;
                        let result = Unlocked {
                            did_key: opened.did_key,
                            needs_reseal: opened.needs_reseal,
                            needs_backfill: opened.needs_backfill,
                            needs_rrk_backfill: opened.needs_rrk_backfill,
                            write_epoch_unreachable: opened.write_epoch_unreachable,
                        };
                        Ok((opened.core, result))
                    }
                    Some(openom_vault::sharing::AccountTreeRole::Member) => {
                        let opened = openom_app_core::unlock_tree_as_member(
                            self.doc_store(doc)?,
                            self.engine,
                            account,
                            &anchor,
                            tree_id,
                            &signers,
                            &replica,
                            floor,
                            &retained,
                            doc.to_string(),
                        )?;
                        let result = Unlocked {
                            did_key: opened.did_key,
                            needs_reseal: false,
                            needs_backfill: false,
                            needs_rrk_backfill: false,
                            write_epoch_unreachable: false,
                        };
                        Ok((opened.core, result))
                    }
                    None => Err(HostError::Vault(openom_app_core::VaultError::NotAuthorized)),
                }
            })?;
        self.register(doc, core);
        self.with_core(doc, |opened| {
            opened.author_cover()?;
            Ok(())
        })?;
        Ok(result)
    }

    /// Recover owner access on a device that already has the tree provisioned/joined: load the stored keyring +
    /// watermark FROM THE NATIVE STORE (never a webview argument), recover under a new passphrase, PERSIST the
    /// fresh keyring + watermark natively, and register the new core. Returns the new recovery code + identity.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree isn't stored; [`HostError::Vault`] on a wrong recovery code / stale
    /// keyring; [`HostError::Store`] on a store read/write failure.
    #[cfg(test)]
    pub fn recover(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        recovery_code: &RecoveryCode,
        new_passphrase: &Passphrase,
    ) -> Result<Recovered, HostError> {
        let _ = member_id;
        let account = self.account_recover(recovery_code, new_passphrase)?;
        let r = self.open_tree(doc, &TreeId::new(tree_id))?;
        Ok(Recovered {
            recovery_code: account.recovery_code,
            did_key: r.did_key,
            needs_reseal: r.needs_reseal,
            needs_backfill: r.needs_backfill,
            needs_rrk_backfill: false,
            write_epoch_unreachable: false,
        })
    }

    /// Change the passphrase on a tree in native custody: load the stored keyring + watermark, re-wrap under
    /// the new passphrase, and PERSIST the fresh keyring natively. The DEK is unchanged — the running core
    /// keeps working (no re-open). Returns the rotated recovery code to show once.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree isn't stored; [`HostError::Vault`] on a wrong current passphrase;
    /// [`HostError::Store`] on a store read/write failure.
    #[cfg(test)]
    pub fn change_passphrase(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> Result<PassphraseChanged, HostError> {
        let _ = (doc, tree_id, member_id);
        self.account_unlock(old_passphrase)?;
        self.account_change_passphrase(new_passphrase)?;
        Ok(PassphraseChanged {
            recovery_code: String::new(),
        })
    }

    /// Mint a joining member's account from their passphrase (stateless — no tree, no store, no core): the first
    /// step of the member flow, before an owner admits them. Returns the codec-encoded KDF params + the two
    /// OOB-shareable public keys. (Account-level NATIVE custody of the KDF params — so they never round-trip
    /// through the webview — is the F6 follow-up; for now the caller persists them as the wasm worker does.)
    ///
    /// # Errors
    /// [`HostError::Vault`] if the member secret derivation fails.
    #[allow(clippy::unused_self)] // account-level today; becomes stateful when it persists native account custody (F6)
    #[cfg(test)]
    pub fn provision_member(&self, passphrase: &Passphrase) -> Result<MemberAccount, HostError> {
        if self
            .store
            .load_account()
            .map_err(HostError::Store)?
            .is_some()
        {
            let member = openom_vault::sharing::provision_member(passphrase)?;
            return Ok(MemberAccount {
                kdf_params: member.kdf_params,
                author_public_key: member.author_public_key,
                hpke_public_key: member.hpke_public_key,
            });
        } else {
            self.account_create(passphrase)?;
        }
        let m = self.account_public_identity()?;
        Ok(MemberAccount {
            kdf_params: Vec::new(),
            author_public_key: m.author_public_key,
            hpke_public_key: m.hpke_public_key,
        })
    }

    /// Admit an OOB-verified `member` to a shared tree (owner action): produce a new keyring revision that
    /// HPKE-wraps the tree DEK to the joiner + records them (the shared `sharing::add_member` math), RE-OPEN the
    /// owner's running core on that shared keyring (a solo→shared transition — the solo sealer doesn't sign, so
    /// a signing sealer + a §B3 resolver are installed), and swap it IN PLACE under the per-doc lock held for
    /// the whole op (so no concurrent sync folds/seals against a mid-change core — design-review F1/F3). The
    /// keyring + watermark are committed natively only AFTER the re-open succeeds (candidate-core-before-commit,
    /// F9). Returns the opaque keyring revision the webview PUBLISHES (keyring FIRST, then the advisory summary,
    /// OPE-293 add ordering). Publish-pending durability is the follow-up shared with `remove_member` (F1/Q3).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the owner tree isn't open; [`HostError::NoKeyring`] if none is stored;
    /// [`HostError::Vault`] on a wrong owner passphrase / bad joiner key / unauthorized add; [`HostError::Core`]
    /// on the re-open / resolver / hydrate; [`HostError::Store`] on a store fault.
    pub fn add_tree_member(
        &self,
        doc: &str,
        tree_id: &TreeId,
        member: &MemberToAdd,
    ) -> Result<AddedMember, HostError> {
        let _account_operation = self.account_op();
        // Hold the owner core's per-doc lock across the WHOLE op — a concurrent sync/session op that grabbed the
        // same Arc must not interleave with the keyring change + in-place re-open (design-review F1/F3). The
        // op-lock also serializes the store writes below against a concurrent open of the same doc.
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = self
            .core(doc)
            .ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        // Whether THIS add flips solo→shared (read from the OLD keyring, before the rotation) — so the owner's
        // own pre-share history is folded as trusted BEFORE the §B3 gate goes live (OPE-360 §5).
        let first_share = !openom_vault::sharing::keyring_has_been_shared(self.engine, &keyring)?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );
        let replica = ReplicaId::new(fresh_replica()?);
        let member_id = MemberId::new(&member.member_id);
        let added = self.with_account(|account| {
            openom_app_core::add_tree_member(
                &openom_app_core::TreeMutationContext {
                    engine: self.engine,
                    keyring: &keyring,
                    account,
                    tree_id,
                    replica_id: &replica,
                    min_revision: floor,
                },
                &openom_app_core::MemberAdmission {
                    member_id: &member_id,
                    role: &member.role,
                    author_public_key: &member.author_public_key,
                    hpke_public_key: &member.hpke_public_key,
                },
            )
            .map_err(HostError::from)
        })?;
        // The §B3 look-behind needs the new revision retained; but persist it only AFTER the fallible candidate
        // build succeeds (F9) — feed it to the resolver IN MEMORY here rather than requiring a prior disk write.
        let new_rev = openom_vault::sharing::chain_watermark_floor(&added.watermark);
        let mut retained = self.retained_revisions(doc)?;
        retained.push((new_rev, added.keyring.clone()));
        // Candidate-core-before-commit (F9): re-open the owner on the shared keyring (fallible), install §B3
        // (over the retained revisions incl. the new one), and hydrate BEFORE persisting anything.
        let reopen_replica = ReplicaId::new(fresh_replica()?);
        let re = self.with_account(|account| {
            openom_app_core::unlock_tree(
                self.doc_store(doc)?,
                self.engine,
                account,
                tree_id,
                &reopen_replica,
                &added.keyring,
                doc.to_string(),
            )
            .map_err(HostError::from)
        })?;
        let mut new_core = re.core;
        let resolver = openom_vault::resolver_from(self.engine, &added.keyring, &retained)?;
        if first_share {
            // Fold the owner's OWN pre-share history (trusted; solo-era, their own device log) BEFORE the §B3
            // gate goes live — else the re-fold rejects the owner's own unsigned solo entries and loses their
            // tree (and the first-share base seal would snapshot nothing). Subsequent re-shares stay gated.
            new_core.bootstrap()?;
            new_core.set_membership(resolver)?;
        } else {
            new_core.set_membership(resolver)?;
            new_core.bootstrap()?;
        }
        // Candidate good → NOW persist retention + the keyring (the sole commit point).
        self.retain_revision(doc, new_rev, &added.keyring)?;
        self.store
            .commit_keyring(doc, &added.keyring, &added.watermark)
            .map_err(HostError::Store)?;
        *guard = new_core; // in-place swap under the held lock
        Ok(AddedMember {
            keyring: added.keyring,
            first_share,
        })
    }

    /// Remove a member (owner action) with FORWARD-SECURE revocation: pin the departing member's landed history
    /// under the PRE-removal epoch (compact-before-remove — else a cold re-judging replica Drops it as a
    /// backdated forge, OPE-421 / F2), mint a fresh epoch the removed member can't reach via the shared
    /// `sharing::remove_member` math, re-open the owner's core under the NEW epoch (the old sealer seals under a
    /// dead epoch), author the self-heal cover over the removed member's stored history (dag; a no-op on a
    /// chain-retained tree), and swap it IN PLACE under the per-doc lock held for the WHOLE op (F1/F3 — no
    /// concurrent sync seals under the dead epoch). Keyring committed only AFTER the re-open succeeds (F9).
    ///
    /// The caller (webview) is responsible for pulling the departing member's writes first (a data sync with a
    /// compaction that UPLOADS the pinning snapshot BEFORE this rotation publishes) and, after this returns,
    /// publishing the ADVISORY summary FIRST, then the keyring, then a data sync to push the cover. Durable
    /// re-publish (a removed member keeps server access until the rotated keyring lands) is derived by the sync
    /// tick from local-head > server-head (F1/Q3), so it needs no marker here.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the tree isn't open; [`HostError::NoKeyring`] if none is stored;
    /// [`HostError::Vault`] on a wrong owner passphrase / removing the owner / unknown member / unauthorized;
    /// [`HostError::Core`] on the compact / re-open / cover; [`HostError::Store`] on a store fault.
    pub fn remove_tree_member(
        &self,
        doc: &str,
        tree_id: &TreeId,
        remove_member_id: &MemberId,
    ) -> Result<RemovedMember, HostError> {
        let _account_operation = self.account_op();
        // Hold the owner core's per-doc lock across the WHOLE op (F1/F3) + the op-lock to serialize store writes.
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = self
            .core(doc)
            .ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );

        // compact-before-remove (F2/OPE-421): fold any already-pulled departing writes + pin them into a
        // snapshot under the PRE-removal epoch, so the covered frontier vouches for their landed history. The
        // webview's prior sync pulls + uploads the snapshot; this keeps the local covered frontier current.
        // history_preserved is best-effort: false ⇒ nothing covered yet (removed before pulling).
        guard.fold()?;
        guard.compact()?;
        let history_preserved = !guard.subsumed_frontier().is_empty();

        let replica = ReplicaId::new(fresh_replica()?);
        let removed = self.with_account(|account| {
            openom_app_core::remove_tree_member(
                &openom_app_core::TreeMutationContext {
                    engine: self.engine,
                    keyring: &keyring,
                    account,
                    tree_id,
                    replica_id: &replica,
                    min_revision: floor,
                },
                remove_member_id,
            )
            .map_err(HostError::from)
        })?;
        // The §B3 look-behind must judge the departing member's PRE-rotation writes against the revision that
        // governed them (F5). Feed the rotated revision to the resolver in memory; persist retention only after
        // the candidate build succeeds (F9).
        let new_rev = openom_vault::sharing::chain_watermark_floor(&removed.watermark);
        let mut retained = self.retained_revisions(doc)?;
        retained.push((new_rev, removed.keyring.clone()));
        // Candidate-core-before-commit (F9): re-open the owner under the NEW epoch (the old sealer is now stale),
        // install §B3 (over the retained revisions), hydrate, then author the self-heal cover.
        let reopen_replica = ReplicaId::new(fresh_replica()?);
        let re = self.with_account(|account| {
            openom_app_core::unlock_tree(
                self.doc_store(doc)?,
                self.engine,
                account,
                tree_id,
                &reopen_replica,
                &removed.keyring,
                doc.to_string(),
            )
            .map_err(HostError::from)
        })?;
        let mut new_core = re.core;
        let resolver = openom_vault::resolver_from(self.engine, &removed.keyring, &retained)?;
        new_core.set_membership(resolver)?;
        new_core.bootstrap()?;
        new_core.author_cover()?; // dag self-heal over the removed member's stored history (no-op on chain)
        self.retain_revision(doc, new_rev, &removed.keyring)?;
        self.store
            .commit_keyring(doc, &removed.keyring, &removed.watermark)
            .map_err(HostError::Store)?;
        *guard = new_core; // in-place swap under the held lock
        Ok(RemovedMember {
            keyring: removed.keyring,
            history_preserved,
        })
    }

    /// Change an existing member's role (owner action, OPE-364): `new_role == "co-owner"` PROMOTES to the signer
    /// set, any other role DEMOTES. A role change touches signing authority, NOT keys — no epoch rotation — so
    /// the owner's running core keeps its sealer and is NOT re-opened; only its §B3 resolver refreshes (over the
    /// retained revisions, so a demoted member's pre-demote history is judged against the revision that governed
    /// it). A DEMOTE first pins the member's already-folded pre-demote history (compact-before-demote — a cold
    /// replica would otherwise Drop it as un-vouched, same as removal; chain demote is forward-secure for the
    /// commit capability via the OPE-421 look-behind, dag via the resolver's `StrongDemote` rule). The whole op
    /// holds the per-doc lock (F1/F3). Returns the new keyring + whether it was a demote (the webview publishes a
    /// promote keyring-first, a demote advisory-first — F8).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the tree isn't open; [`HostError::NoKeyring`] if none is stored;
    /// [`HostError::Vault`] on a wrong owner passphrase / unknown-or-owner target / unauthorized change;
    /// [`HostError::Core`] on the compact / resolver refresh; [`HostError::Store`] on a store fault.
    pub fn change_tree_member_role(
        &self,
        doc: &str,
        tree_id: &TreeId,
        target_member_id: &MemberId,
        new_role: &str,
    ) -> Result<RoleChanged, HostError> {
        let _account_operation = self.account_op();
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = self
            .core(doc)
            .ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let floor = openom_vault::sharing::chain_watermark_floor(
            &self.store.watermark(doc).map_err(HostError::Store)?,
        );
        let demote = new_role != "co-owner";
        if demote {
            // compact-before-demote: pin the member's already-folded pre-demote history (same look-behind
            // requirement as removal — a cold replica would else Drop it as un-vouched).
            guard.fold()?;
            guard.compact()?;
        }
        let replica = ReplicaId::new(fresh_replica()?);
        let changed = self.with_account(|account| {
            openom_app_core::change_tree_member_role(
                &openom_app_core::TreeMutationContext {
                    engine: self.engine,
                    keyring: &keyring,
                    account,
                    tree_id,
                    replica_id: &replica,
                    min_revision: floor,
                },
                target_member_id,
                new_role,
            )
            .map_err(HostError::from)
        })?;
        // Refresh the §B3 resolver on the RUNNING core (no re-open — no epoch rotation, the sealer is unchanged);
        // this re-judges existing writes under the new membership (a demote drops the member's over-authority
        // commits, keeps their authorized-then history via the retained revisions). Build + install it BEFORE
        // persisting (F9): feed the new revision to the resolver in memory, and only retain/commit on success.
        let new_rev = openom_vault::sharing::chain_watermark_floor(&changed.watermark);
        let mut retained = self.retained_revisions(doc)?;
        retained.push((new_rev, changed.keyring.clone()));
        let resolver = openom_vault::resolver_from(self.engine, &changed.keyring, &retained)?;
        guard.set_membership(resolver)?;
        self.retain_revision(doc, new_rev, &changed.keyring)?;
        self.store
            .commit_keyring(doc, &changed.keyring, &changed.watermark)
            .map_err(HostError::Store)?;
        Ok(RoleChanged {
            keyring: changed.keyring,
            demote,
        })
    }

    /// A joining member's FIRST open: verify the fetched keyring history from genesis against the OOB invite pin
    /// (`verify_keyring_walk` — fails closed, persists NOTHING on any bad walk / pin mismatch), unlock at the
    /// verified head BEFORE persisting (F3 — a wrong passphrase leaves no partial state), then persist the
    /// trusted signer pins first, retain every revision, and commit the head keyring as the sole commit point.
    /// `trusted_signers` are derived from the verified walk, never a webview argument. Refuses to re-join a tree
    /// already in native custody; the resident profile account supplies all member secrets.
    ///
    /// # Errors
    /// [`HostError::Store`] if already joined or on a store fault; [`HostError::Vault`] on a failed walk / pin
    /// mismatch; [`HostError::Core`] on a wrong passphrase / member-unlock failure.
    #[allow(clippy::too_many_arguments)]
    pub fn join_chain_tree(
        &self,
        doc: &str,
        tree_id: &TreeId,
        hops: &[u8],
        pinned_revision: u32,
        pinned_hash: &[u8],
    ) -> Result<MemberUnlocked, HostError> {
        let _account_operation = self.account_op();
        // Hold the doc's op-lock across the WHOLE join (check-then-commit): two concurrent joins (a double
        // invoke, or a compromised webview racing two invite payloads) must not both pass the re-join guard and
        // both write, the later silently winning — the exact attacker-redirect the guard exists to prevent.
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-join guard: never overwrite an already-established trust relationship (native custody is the trust
        // root, so an overwrite would let a compromised webview redirect the member to an attacker tree).
        if self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .is_some()
        {
            return Err(HostError::Store(format!(
                "already joined {doc:?}; unlock, don't re-join"
            )));
        }
        let walk = openom_vault::sharing::verify_keyring_walk(
            tree_id,
            hops,
            pinned_revision,
            pinned_hash,
        )?;
        let retained = Self::unframe_revisions(&walk.bodies_framed)?;
        // Unlock at the verified head BEFORE persisting anything (F3).
        let replica = ReplicaId::new(fresh_replica()?);
        let m = self.with_account(|account| {
            openom_app_core::unlock_tree_as_member(
                self.doc_store(doc)?,
                self.engine,
                account,
                &walk.head_keyring,
                tree_id,
                &walk.trusted_signers_flat,
                &replica,
                walk.revision,
                &retained,
                doc.to_string(),
            )
            .map_err(HostError::from)
        })?;
        // Persist context FIRST, then retention, then the keyring head as the sole commit point (F6/F7).
        self.save_trusted_signers(doc, &walk.trusted_signers_flat)?;
        for (rev, body) in &retained {
            self.retain_revision(doc, *rev, body)?;
        }
        self.store
            .commit_keyring(doc, &walk.head_keyring, &m.watermark)
            .map_err(HostError::Store)?;
        let did_key = m.did_key.clone();
        self.register(doc, m.core);
        // Self-heal cover over any since-removed member's history already in the local store (design-review #6):
        // a no-op on a fresh join, real work on a re-open that carries removed-member deltas.
        self.with_core(doc, |c| {
            c.author_cover()?;
            Ok(())
        })?;
        Ok(MemberUnlocked { did_key })
    }

    /// A joining member's FIRST open on the DAG engine: the dag analog of [`join_chain_tree`](Self::join_chain_tree). Instead of a
    /// genesis-walk, verify the served self-contained anchor against the OOB pin (`verify_dag_anchor` — fails
    /// closed on founder substitution / rollback / checkpoint), unlock as the member at the verified anchor
    /// (empty trusted-signers + revision 0, no per-revision retention — the anchor IS the whole history), then
    /// persist context + commit the anchor as the sole commit point. Same op-lock + re-join guard as the chain
    /// path. `anchor_wrapped` is the highest served (MembershipEnvelope-wrapped) revision; `pin` is the v3 dag pin.
    ///
    /// # Errors
    /// [`HostError::Store`] if already joined / on a store fault; [`HostError::Vault`] on a failed anchor verify;
    /// [`HostError::Core`] on a wrong passphrase / member-unlock failure.
    #[allow(clippy::too_many_arguments)]
    pub fn join_dag_tree(
        &self,
        doc: &str,
        tree_id: &TreeId,
        anchor_wrapped: &[u8],
        pin: &[u8],
    ) -> Result<MemberUnlocked, HostError> {
        let _account_operation = self.account_op();
        if self.engine != EngineKind::Dag {
            return Err(HostError::Store("join_dag_anchor is dag-only".into()));
        }
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .is_some()
        {
            return Err(HostError::Store(format!(
                "already joined {doc:?}; unlock, don't re-join"
            )));
        }
        let anchor = openom_vault::sharing::unwrap_dag_keyring(anchor_wrapped)?;
        let verified = openom_vault::sharing::verify_dag_anchor(&anchor, tree_id, pin)?;
        let no_retained: Vec<(u32, Vec<u8>)> = Vec::new();
        // Unlock at the verified anchor BEFORE persisting (F3). Dag carries no signer walk / retention, so the
        // trusted-signers are empty and the revision is 0 (mirrors the web joinDagAnchor).
        let replica = ReplicaId::new(fresh_replica()?);
        let m = self.with_account(|account| {
            openom_app_core::unlock_tree_as_member(
                self.doc_store(doc)?,
                self.engine,
                account,
                &verified.keyring,
                tree_id,
                &[],
                &replica,
                0,
                &no_retained,
                doc.to_string(),
            )
            .map_err(HostError::from)
        })?;
        self.save_trusted_signers(doc, &[])?;
        self.store
            .commit_keyring(doc, &verified.keyring, &m.watermark)
            .map_err(HostError::Store)?;
        let did_key = m.did_key.clone();
        self.register(doc, m.core);
        self.with_core(doc, |c| {
            c.author_cover()?;
            Ok(())
        })?;
        Ok(MemberUnlocked { did_key })
    }

    #[cfg(test)]
    fn provision(
        &self,
        doc: &str,
        tree_id: &[u8],
        _member_id: &str,
        passphrase: &Passphrase,
    ) -> Result<Provisioned, HostError> {
        self.account_create(passphrase)?;
        self.provision_tree(doc, &TreeId::new(tree_id))
    }

    #[cfg(test)]
    fn unlock(
        &self,
        doc: &str,
        tree_id: &[u8],
        _member_id: &str,
        passphrase: &Passphrase,
    ) -> Result<Unlocked, HostError> {
        self.account_unlock(passphrase)?;
        self.open_tree(doc, &TreeId::new(tree_id))
    }

    #[cfg(test)]
    fn add_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        _owner_member_id: &str,
        owner_passphrase: &Passphrase,
        member: &MemberToAdd,
    ) -> Result<AddedMember, HostError> {
        self.account_unlock(owner_passphrase)?;
        self.add_tree_member(doc, &TreeId::new(tree_id), member)
    }

    #[cfg(test)]
    fn remove_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        _owner_member_id: &str,
        owner_passphrase: &Passphrase,
        member_id: &str,
    ) -> Result<RemovedMember, HostError> {
        self.account_unlock(owner_passphrase)?;
        self.remove_tree_member(doc, &TreeId::new(tree_id), &MemberId::new(member_id))
    }

    #[cfg(test)]
    fn change_role(
        &self,
        doc: &str,
        tree_id: &[u8],
        _owner_member_id: &str,
        owner_passphrase: &Passphrase,
        member_id: &str,
        role: &str,
    ) -> Result<RoleChanged, HostError> {
        self.account_unlock(owner_passphrase)?;
        self.change_tree_member_role(doc, &TreeId::new(tree_id), &MemberId::new(member_id), role)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn join_as_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        _member_id: &str,
        passphrase: &Passphrase,
        _member_kdf_params: &[u8],
        hops: &[u8],
        pinned_revision: u32,
        pinned_hash: &[u8],
    ) -> Result<MemberUnlocked, HostError> {
        self.account_unlock(passphrase)?;
        self.join_chain_tree(
            doc,
            &TreeId::new(tree_id),
            hops,
            pinned_revision,
            pinned_hash,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn join_dag_anchor(
        &self,
        doc: &str,
        tree_id: &[u8],
        _member_id: &str,
        passphrase: &Passphrase,
        _member_kdf_params: &[u8],
        anchor: &[u8],
        pin: &[u8],
    ) -> Result<MemberUnlocked, HostError> {
        self.account_unlock(passphrase)?;
        self.join_dag_tree(doc, &TreeId::new(tree_id), anchor, pin)
    }

    /// Unlock a SHARED tree as a non-owner member on a device that has already JOINED: load the trusted keyring,
    /// the member context (kdf + trusted signers), and the anti-rollback floor FROM NATIVE CUSTODY (never a
    /// webview argument — C2), HPKE-unwrap the member DEKs, and register a ready core carrying its epoch-adopt
    /// secret + a §B3 resolver over the retained revisions.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if the tree was never joined (no keyring / no member context);
    /// [`HostError::Core`] on a wrong passphrase / unpinned signer / removed member; [`HostError::Store`] on a
    /// store fault.
    #[cfg(test)]
    pub fn unlock_as_member(
        &self,
        doc: &str,
        tree_id: &[u8],
        member_id: &str,
        passphrase: &Passphrase,
    ) -> Result<MemberUnlocked, HostError> {
        let _ = member_id;
        self.account_unlock(passphrase)?;
        let opened = self.open_tree(doc, &TreeId::new(tree_id))?;
        Ok(MemberUnlocked {
            did_key: opened.did_key,
        })
    }

    /// The current stored CHAIN keyring revision (the anti-rollback floor); `0` when none is stored yet. Lets the
    /// webview fetch only the SUCCESSORS to adopt on a sync tick (`readKeyring(head + 1)`) — the native
    /// counterpart to the web worker's `keyringStore.head`. Chain-only: a dag head is an anchor, not a scalar
    /// revision (its adoption is the separate anchor-merge path).
    ///
    /// # Errors
    /// [`HostError::Store`] if the watermark read fails.
    pub fn keyring_head(&self, doc: &str) -> Result<u32, HostError> {
        if self.engine != EngineKind::Chain {
            // A dag watermark is a concatenated op-id frontier, not a scalar revision — reading its first bytes
            // as a "head" is meaningless. Refuse (the caller skips the chain keyring-before-data step), matching
            // sync_keyring's own engine guard.
            return Err(HostError::Store(
                "keyring_head is chain-only; a dag head is an anchor".into(),
            ));
        }
        let watermark = self.store.watermark(doc).map_err(HostError::Store)?;
        if watermark.is_empty() {
            return Ok(0);
        }
        Ok(openom_vault::sharing::chain_watermark_floor(&watermark))
    }

    /// Whether native custody holds a MEMBER context for `doc` (the kdf params + trusted signers written at JOIN).
    /// A reopen dispatches on this: `true` → a joined device reopens via [`unlock_as_member`](Self::unlock_as_member);
    /// `false` → an owner via [`unlock`](Self::unlock). It's custody metadata (no DEK), so it's probeable BEFORE
    /// unlock — which lets the client-facing open-tree path cover both roles without the webview choosing.
    ///
    /// # Errors
    /// [`HostError::Store`] if the member-context store read fails.
    #[cfg(test)]
    pub fn has_member_context(&self, doc: &str) -> Result<bool, HostError> {
        let _account_operation = self.account_op();
        let keyring = self.store.load_keyring(doc).map_err(HostError::Store)?;
        let Some(keyring) = keyring else {
            return Ok(false);
        };
        self.with_account(|account| {
            Ok(matches!(
                openom_app_core::account_tree_role(self.engine, &keyring, account)?,
                Some(openom_vault::sharing::AccountTreeRole::Member)
            ))
        })
    }

    /// Adopt newer keyring revisions pulled from the network (a member/device keyring sync — CHAIN). Validates
    /// the successor `hops` against the locally-stored anchor (`accept_remote_keyring` — a fork / rollback /
    /// withheld-hop / rogue-signer run is refused and NOTHING persisted), persists the new head + retains each
    /// new revision, then on the running core adopts any ROTATED write epoch via the retained epoch-adopt secret
    /// (OPE-393 — a no-op for an owner/solo core; a soft no-op for a member that discovers it was removed) and
    /// refreshes the §B3 resolver over the newly-retained revisions. Holds the per-doc lock across the op
    /// (F1/F3). (Dag keyring adoption is the anchor merge — a separate path, not yet on the host.)
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::NoKeyring`] if the tree isn't open / stored; [`HostError::Vault`] on
    /// a rejected keyring run; [`HostError::Core`] on adoption / resolver; [`HostError::Store`] on a store fault
    /// (or a dag deployment, where this path doesn't apply).
    pub fn sync_keyring(&self, doc: &str, tree_id: &TreeId, hops: &[u8]) -> Result<(), HostError> {
        if self.engine != EngineKind::Chain {
            return Err(HostError::Store(
                "dag keyring adoption is the anchor merge, not this chain-walk path".into(),
            ));
        }
        let op = self.op_lock(doc);
        let _op = op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = self
            .core(doc)
            .ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let anchor = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        let old_watermark = self.store.watermark(doc).map_err(HostError::Store)?;
        let anchor_rev = openom_vault::sharing::chain_watermark_floor(&old_watermark);
        let accepted = openom_vault::sharing::accept_remote_keyring(&anchor, tree_id, hops)?;
        // CARRY the OPE-286 write-epoch pin forward (accept returns a bare revision, which would erase it and
        // weaken a later recover's write-epoch authentication — design-review #2).
        let watermark = openom_vault::sharing::chain_watermark_carry(
            openom_vault::sharing::chain_watermark_floor(&accepted.watermark),
            &old_watermark,
        );
        self.store
            .commit_keyring(doc, &accepted.keyring, &watermark)
            .map_err(HostError::Store)?;
        // Retain each newly-accepted revision (unwrap the wrapped hop to its raw body; hop i is anchor_rev+1+i).
        for (idx, (_i, wrapped)) in Self::unframe_revisions(hops)?.into_iter().enumerate() {
            let raw = openom_vault::sharing::unwrap_chain_keyring(&wrapped)?;
            let revision = anchor_rev
                .checked_add(1)
                .and_then(|r| r.checked_add(u32::try_from(idx).ok()?))
                .ok_or_else(|| HostError::Store("keyring revision overflow".into()))?;
            self.retain_revision(doc, revision, &raw)?;
        }
        // Refresh the non-secret signer pins from the newly accepted head so a legitimate signer-set rotation
        // cannot leave a joined account locked to its join-time set.
        let signers = openom_vault::sharing::chain_head_signers_flat(&accepted.keyring)?;
        self.save_trusted_signers(doc, &signers)?;
        // Adopt any rotated epoch + refresh the §B3 resolver on the running core, then re-author the self-heal
        // cover so a removed member's history that arrived on this tick is covered (design-review #6), not only
        // when THIS device did the removal.
        guard.adopt_epochs(&accepted.keyring)?;
        let resolver = openom_vault::resolver_from(
            self.engine,
            &accepted.keyring,
            &self.retained_revisions(doc)?,
        )?;
        guard.set_membership(resolver)?;
        guard.author_cover()?;
        Ok(())
    }

    /// The opaque payload to PUT to the server's keyring channel for `doc` — the CURRENT stored keyring, wrapped
    /// as the wire `KeyringUpdate` on the chain, or the raw anchor on the dag. Read from native custody (never a
    /// webview-supplied keyring), so a compromised webview can only publish the head the host actually holds.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if none is stored; [`HostError::Vault`] if the keyring can't be wrapped.
    pub fn keyring_publish_payload(&self, doc: &str) -> Result<Vec<u8>, HostError> {
        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        Ok(match self.engine {
            EngineKind::Chain => openom_vault::sharing::wrap_chain_keyring_update(&keyring)?,
            EngineKind::Dag => keyring, // the dag PUTs the full self-contained anchor
        })
    }

    /// The publish payload for a specific RETAINED chain keyring `revision`: the wrapped `KeyringUpdate` to PUT,
    /// plus the raw keyring state the server stores/serves. The owner-side tick republish walks
    /// `server_head + 1 ..= local_head` and PUTs each `update` (the server admits only revision == head + 1); on a
    /// 409 it compares the server's served bytes to `body` to tell a benign already-admitted revision from a fork.
    /// Chain-only (a dag PUTs the whole anchor, no per-revision walk).
    ///
    /// # Errors
    /// [`HostError::Store`] on a dag engine or a missing retained revision; [`HostError::Vault`] if the body can't
    /// be wrapped.
    pub fn keyring_publish_payload_at(
        &self,
        doc: &str,
        revision: u32,
    ) -> Result<KeyringRevisionPayload, HostError> {
        if self.engine != EngineKind::Chain {
            return Err(HostError::Store(
                "keyring_publish_payload_at is chain-only".into(),
            ));
        }
        let body = self
            .retained_revisions(doc)?
            .into_iter()
            .find(|(r, _)| *r == revision)
            .map(|(_, b)| b)
            .ok_or_else(|| HostError::Store(format!("no retained keyring revision {revision}")))?;
        let update = openom_vault::sharing::wrap_chain_keyring_update(&body)?;
        Ok(KeyringRevisionPayload { update, body })
    }

    /// The advisory membership summary (OPE-293) for `doc` as a JSON string — the coarse `{members, basis}` view
    /// the webview PUTs to the server's `/access` channel. Computed from the NATIVE stored keyring.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if none is stored; [`HostError::Vault`] on a malformed keyring.
    pub fn membership_summary(&self, doc: &str) -> Result<String, HostError> {
        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        Ok(openom_vault::sharing::keyring_summary(
            self.engine,
            &keyring,
        )?)
    }

    /// The OOB invite pin for `doc`'s current keyring — the `(revision, hash)`-binding hash a joining member
    /// verifies the walk against (chain), or the opaque anchor pin (dag). From native custody.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if none is stored; [`HostError::Vault`] on a malformed keyring.
    pub fn invite_pin(&self, doc: &str) -> Result<Vec<u8>, HostError> {
        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        Ok(match self.engine {
            EngineKind::Chain => openom_vault::sharing::chain_keyring_pin(&keyring)?,
            EngineKind::Dag => openom_vault::sharing::dag_anchor_pin(&keyring)?,
        })
    }

    /// The invite MINT material (v3): the full engine pin, so the webview drives `invite.mint` engine-agnostically.
    /// Chain packs `rev‖kh` here (the joiner's `verify_keyring_walk` checks exactly those 36 bytes); dag returns
    /// the opaque anchor pin.
    ///
    /// # Errors
    /// [`HostError::NoKeyring`] if none is stored; [`HostError::Vault`]/[`HostError::Store`] on a malformed keyring.
    pub fn invite_material(&self, doc: &str) -> Result<InviteMaterial, HostError> {
        let keyring = self
            .store
            .load_keyring(doc)
            .map_err(HostError::Store)?
            .ok_or_else(|| HostError::NoKeyring(doc.to_string()))?;
        match self.engine {
            EngineKind::Chain => {
                let revision = self.keyring_head(doc)?;
                let kh = openom_vault::sharing::chain_keyring_pin(&keyring)?; // the 32-byte keyring-body hash
                let mut pin = revision.to_be_bytes().to_vec();
                pin.extend_from_slice(&kh);
                Ok(InviteMaterial {
                    engine: EngineKind::Chain.as_tag().to_string(),
                    pin,
                })
            }
            EngineKind::Dag => {
                let pin = openom_vault::sharing::dag_anchor_pin(&keyring)?;
                Ok(InviteMaterial {
                    engine: EngineKind::Dag.as_tag().to_string(),
                    pin,
                })
            }
        }
    }

    /// Assert a claim about `target` (`value_json` = the claim value as a JSON string, as the wasm veneer takes
    /// it). Buffered into the intention; [`commit`](Self::commit) seals it.
    ///
    /// # Errors
    /// [`HostError::NoCore`]; [`HostError::Store`] if `value_json` is invalid; [`HostError::Tree`] if the claim
    /// can't be canonicalized.
    pub fn assert_claim(
        &self,
        doc: &str,
        target: &str,
        predicate: &str,
        value_json: &str,
    ) -> Result<(), HostError> {
        let value = serde_json::from_str(value_json)
            .map_err(|e| HostError::Store(format!("bad claim value json: {e}")))?;
        self.with_core(doc, |c| {
            c.tree_mut()
                .assert_claim(target, predicate, value, now_millis())?;
            Ok(())
        })
    }

    /// Supersede `prior` with a fresh claim value (an atomic edit).
    ///
    /// # Errors
    /// As [`assert_claim`](Self::assert_claim).
    pub fn supersede_claim(
        &self,
        doc: &str,
        prior: &str,
        target: &str,
        predicate: &str,
        value_json: &str,
    ) -> Result<(), HostError> {
        let value = serde_json::from_str(value_json)
            .map_err(|e| HostError::Store(format!("bad claim value json: {e}")))?;
        self.with_core(doc, |c| {
            c.tree_mut()
                .supersede_claim(prior, target, predicate, value, now_millis())?;
            Ok(())
        })
    }

    /// Remove one of this author's records by id — returns the Remove op's own id (for a later [`revoke`]).
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Tree`].
    pub fn remove_record(&self, doc: &str, target: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.tree_mut().remove(target, now_millis())?))
    }

    /// Undo a same-author Remove by its op id.
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Tree`].
    pub fn revoke(&self, doc: &str, removal_op_id: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| {
            c.tree_mut().revoke(removal_op_id, now_millis())?;
            Ok(())
        })
    }

    /// Clear the tree + local durable store (demo reseed / hard local reset). Keeps the DEK.
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Core`].
    pub fn reset(&self, doc: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.reset()?))
    }

    /// Set the §B3 moderator `did:key`s (Maintainer+).
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn set_moderators(&self, doc: &str, moderators: Vec<String>) -> Result<(), HostError> {
        self.with_core(doc, |c| {
            c.set_moderators(moderators.into_iter().collect());
            Ok(())
        })
    }

    /// The operations log as a JSON string.
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Core`].
    pub fn oplog(&self, doc: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.oplog_json()?))
    }

    /// Every live record as a JSON-array string.
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Core`]; [`HostError::Store`] if it can't serialize.
    pub fn live_records(&self, doc: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| {
            serde_json::to_string(&c.live_records()?).map_err(|e| HostError::Store(e.to_string()))
        })
    }

    /// The live claims about `target` under `predicate`, as a JSON-array string.
    ///
    /// # Errors
    /// [`HostError::NoCore`]; [`HostError::Store`] if it can't serialize.
    pub fn live_claims_of(
        &self,
        doc: &str,
        target: &str,
        predicate: &str,
    ) -> Result<String, HostError> {
        self.with_core(doc, |c| {
            serde_json::to_string(&c.live_claims_of(target, predicate))
                .map_err(|e| HostError::Store(e.to_string()))
        })
    }

    /// Every live claim about `target`, whatever the predicate, as a JSON-array string.
    ///
    /// # Errors
    /// [`HostError::NoCore`]; [`HostError::Store`] if it can't serialize.
    pub fn live_claims_of_any(&self, doc: &str, target: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| {
            serde_json::to_string(&c.live_claims_of_any(target))
                .map_err(|e| HostError::Store(e.to_string()))
        })
    }

    /// The canonical person id an anchor resolves to, or `None`.
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn resolve_id(&self, doc: &str, anchor: &str) -> Result<Option<String>, HostError> {
        self.with_core(doc, |c| Ok(c.resolve_id(anchor)))
    }

    /// How many mints are buffered, uncommitted.
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn pending_count(&self, doc: &str) -> Result<usize, HostError> {
        self.with_core(doc, |c| Ok(c.pending_count()))
    }

    /// Data-integrity anomalies observed (undecodable / quarantined / §B3-rejected).
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn anomalies(&self, doc: &str) -> Result<usize, HostError> {
        self.with_core(doc, |c| Ok(c.anomalies()))
    }

    /// This device's PULL frontier (`{replica_hex: counter}`) — reported to the server's GC gate 2 so a slow
    /// member's un-pulled log tail isn't reaped before it can pull it (OPE-409).
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn pull_frontier(
        &self,
        doc: &str,
    ) -> Result<std::collections::BTreeMap<String, u64>, HostError> {
        self.with_core(doc, |c| Ok(c.pull_frontier()))
    }

    /// The soft-removal review queue as a JSON string (OPE-426).
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn pending_reviews(&self, doc: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.pending_reviews()))
    }

    /// Approve a pending trailing edit (OPE-426); returns whether it was approved.
    ///
    /// # Errors
    /// [`HostError::NoCore`] / [`HostError::Core`].
    pub fn approve_pending(
        &self,
        doc: &str,
        replica: &str,
        counter: u64,
    ) -> Result<bool, HostError> {
        self.with_core(doc, |c| Ok(c.approve_pending(replica, counter)?))
    }

    /// Discard a pending trailing edit (OPE-426); returns whether it was present.
    ///
    /// # Errors
    /// [`HostError::NoCore`].
    pub fn discard_pending(
        &self,
        doc: &str,
        replica: &str,
        counter: u64,
    ) -> Result<bool, HostError> {
        self.with_core(doc, |c| Ok(c.discard_pending(replica, counter)))
    }

    /// Close a doc: drop its live core (and DEK) from the registry — the identity-change / lock hook. Idempotent.
    pub fn close(&self, doc: &str) {
        let empty = {
            let mut cores = self.lock_cores();
            cores.remove(doc);
            cores.is_empty()
        };
        if empty {
            *self
                .account
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    // ── Media blob store (OPE-435/436): photos/attachments, SEALED under the doc's DEK ────────────────────
    // The webview's TauriBlobStore (apps/app/src/core/blobs.js) drives these. A put/get needs the doc's LIVE
    // core (it holds the DEK) — so media can only be attached to / read from an UNLOCKED tree; has/meta/delete/
    // list are plain store reads over the opaque bytes. The content address is the SHA-256 of the plaintext.

    /// Seal `bytes` under `doc`'s DEK and store them content-addressed; returns the hex SHA-256 address. The
    /// plaintext is hashed + sealed by the live core, then only the opaque envelope is persisted — nothing
    /// plaintext reaches disk. Idempotent: identical bytes map to one entry.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if `doc` is locked/closed; [`HostError::Core`] on a seal failure; [`HostError::Store`]
    /// on a persist failure.
    pub fn blob_put(
        &self,
        doc: &str,
        bytes: &[u8],
        mime: Option<String>,
        w: Option<u32>,
        h: Option<u32>,
    ) -> Result<String, HostError> {
        let size = bytes.len() as u64;
        let (hash, sealed) = self.with_core(doc, |c| Ok(c.seal_media(bytes)?))?;
        let meta = store_media::PutMeta {
            mime,
            w,
            h,
            size,
            created: now_millis(),
        };
        self.media_store(doc)?
            .put(&hash, &sealed, meta)
            .map_err(HostError::Store)?;
        Ok(hash)
    }

    /// Fetch + decrypt `hash` under `doc`'s DEK, or `None` if absent. Returns the plaintext bytes + mime (held
    /// in memory; the webview wraps them in a `Blob`).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if `doc` is locked/closed; [`HostError::Core`] if the sealed bytes fail to open;
    /// [`HostError::Store`] on a read failure.
    pub fn blob_get(&self, doc: &str, hash: &str) -> Result<Option<BlobData>, HostError> {
        let Some((sealed, mime)) = self
            .media_store(doc)?
            .get_sealed(hash)
            .map_err(HostError::Store)?
        else {
            return Ok(None);
        };
        let bytes = self.with_core(doc, |c| Ok(c.open_media(&sealed)?))?;
        Ok(Some(BlobData { bytes, mime }))
    }

    /// Seal arbitrary client-owned secret bytes under `doc`'s tree DEK (OPE-453), returning the wire envelope
    /// the webview stores in place of the plaintext (the durable invite mint record — OPE-447 native parity).
    /// Unlike media, nothing is persisted here: the caller owns the sealed bytes.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if `doc` is locked/closed; [`HostError::Core`] on a seal failure.
    pub fn seal_app_secret(&self, doc: &str, bytes: &[u8]) -> Result<Vec<u8>, HostError> {
        self.with_core(doc, |c| Ok(c.seal_app_secret(bytes)?))
    }

    /// Open an app-secret envelope sealed by [`seal_app_secret`](Self::seal_app_secret) under `doc`'s DEK.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if `doc` is locked/closed; [`HostError::Core`] if the envelope is the wrong
    /// kind/scope/epoch or fails to open.
    pub fn open_app_secret(&self, doc: &str, sealed: &[u8]) -> Result<Vec<u8>, HostError> {
        self.with_core(doc, |c| Ok(c.open_app_secret(sealed)?))
    }

    /// Whether `doc` has a blob for `hash` (no decryption).
    ///
    /// # Errors
    /// [`HostError::Store`] on a read failure.
    pub fn blob_has(&self, doc: &str, hash: &str) -> Result<bool, HostError> {
        self.media_store(doc)?.has(hash).map_err(HostError::Store)
    }

    /// `hash`'s metadata (mime / dimensions / plaintext size / created), or `None` (no decryption).
    ///
    /// # Errors
    /// [`HostError::Store`] on a read failure.
    pub fn blob_meta(&self, doc: &str, hash: &str) -> Result<Option<BlobMeta>, HostError> {
        self.media_store(doc)?.meta(hash).map_err(HostError::Store)
    }

    /// Delete `hash` from `doc`'s media store (idempotent; no decryption).
    ///
    /// # Errors
    /// [`HostError::Store`] on a write failure.
    pub fn blob_delete(&self, doc: &str, hash: &str) -> Result<(), HostError> {
        self.media_store(doc)?
            .delete(hash)
            .map_err(HostError::Store)
    }

    /// Every stored blob hash for `doc` (no decryption).
    ///
    /// # Errors
    /// [`HostError::Store`] on a read failure.
    pub fn blob_list(&self, doc: &str) -> Result<Vec<String>, HostError> {
        self.media_store(doc)?.list().map_err(HostError::Store)
    }

    /// Rebuild `doc`'s engine from its durable local log — call once after [`unlock`](Self::unlock) on open,
    /// so a mint committed offline in a previous session is folded back in. (A re-open uses a FRESH replica id,
    /// so the previous session's entries are pulled as a peer rather than skipped as "our own".)
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store/merge fault.
    pub fn bootstrap(&self, doc: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.bootstrap()?))
    }

    /// Buffer an identity-anchor mint into `doc`'s intention; [`commit`](Self::commit) seals + persists it.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Tree`] if the mint can't be canonicalized.
    pub fn assert_anchor(&self, doc: &str, id: &str, type_uri: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| {
            Ok(c.tree_mut().assert_anchor(id, type_uri, now_millis())?)
        })
    }

    /// Seal + persist `doc`'s buffered mint batch to its local store (advancing the log + head pointer).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if sealing/persisting fails.
    pub fn commit(&self, doc: &str) -> Result<(), HostError> {
        self.with_core(doc, |c| Ok(c.commit()?))
    }

    /// Open a historical delta envelope to its op-batch JSON (the decrypted change) for the change-history feed.
    /// Errors if the epoch is unreachable — the caller renders it as an un-viewable change.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if the envelope can't be opened.
    pub fn open_history_delta(&self, doc: &str, envelope: &[u8]) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.open_history_delta(envelope)?))
    }

    /// The write-side role pre-check (a UX guard): whether `doc` may commit directly (solo, or a current
    /// Maintainer+) or must route its edit to a [`propose`](Self::propose) (an Editor/Viewer on a shared tree).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open.
    pub fn can_commit_directly(&self, doc: &str) -> Result<bool, HostError> {
        self.with_core(doc, |c| Ok(c.can_commit_directly()))
    }

    /// Editor path: seal `doc`'s buffered intention as a `Kind::Proposal` for a Maintainer to review; returns
    /// the envelope bytes (EMPTY if nothing was minted). Off the authoritative log — the ops stay optimistically
    /// applied to the local tree but are not committed. The caller uploads the bytes to the proposals channel.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if flushing/sealing fails.
    pub fn propose(&self, doc: &str) -> Result<Vec<u8>, HostError> {
        self.with_core(doc, |c| Ok(c.propose()?.unwrap_or_default()))
    }

    /// Maintainer path: verify an editor's `proposal` and commit it as an attributed delta under this member's
    /// authority (persisted to the local log); returns how many ops were committed. Refuses (errors) a forged or
    /// misattributed proposal, leaving it untouched for an explicit reject.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if the proposal fails verification / the
    /// attribution cross-check, or opening / sealing / appending fails.
    pub fn approve_proposal(&self, doc: &str, proposal: &[u8]) -> Result<usize, HostError> {
        self.with_core(doc, |c| Ok(c.approve_proposal(proposal)?))
    }

    /// Fold `doc`'s local store through the §B3 gate — merges own + peer writes into the projection. Returns
    /// how many entries folded.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store read fault.
    pub fn fold(&self, doc: &str) -> Result<usize, HostError> {
        self.with_core(doc, |c| Ok(c.fold()?))
    }

    /// `doc`'s materialized read model as a JSON string (the webview renders it).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] if the projection can't be serialized.
    pub fn project(&self, doc: &str) -> Result<String, HostError> {
        self.with_core(doc, |c| Ok(c.project_json()?))
    }

    /// One sync tick against a caller-supplied remote snapshot: mirror the remote's objects into `doc`'s local
    /// store, fold/adopt them through the §B3 gate, maybe compact (when `compact_k > 0`), and return the
    /// objects the remote is missing (for the webview/host to PUT). The webview ferries the ciphertext + drives
    /// the fetch; the DEK, the fold, and the plaintext store stay native (Full-A). Returns the [`SyncOut`] the
    /// webview PUTs: each upload with its `pointer` flag (decided by the core, not a key the webview inspects) +
    /// the `covered` GC-header frontier for the snapshot.
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open; [`HostError::Core`] on a store/merge fault.
    pub fn sync(
        &self,
        doc: &str,
        remote: &[StoredObject],
        present: &[String],
        compact_k: u32,
    ) -> Result<SyncOut, HostError> {
        self.with_core(doc, |c| {
            let tick = c.sync_tick(remote, present, compact_k)?;
            Ok(SyncOut {
                uploads: tick
                    .uploads
                    .into_iter()
                    .map(|u| UploadObject {
                        key: u.key,
                        bytes: u.bytes,
                        pointer: u.pointer,
                    })
                    .collect(),
                folded: tick.folded,
                covered: tick.covered,
            })
        })
    }

    /// From a LIST of the remote's keys, the subset `doc` must still FETCH — it drops immutable log objects it
    /// already pulled (OPE-464) so the webview doesn't re-download the whole retained log each tick. The webview
    /// GETs only the returned keys, then passes the fetched bytes + the full LIST (`present`) to [`sync`](Self::sync).
    ///
    /// # Errors
    /// [`HostError::NoCore`] if the doc isn't open.
    pub fn plan_fetch(&self, doc: &str, keys: &[String]) -> Result<Vec<String>, HostError> {
        self.with_core(doc, |c| Ok(c.plan_fetch(keys)))
    }

    /// The live core for `doc` (for the ops not yet surfaced as host methods), if it has been
    /// provisioned/unlocked this session.
    pub fn core(&self, doc: &str) -> Option<CoreHandle> {
        self.lock_cores().get(doc).cloned()
    }

    /// Run `f` against `doc`'s locked core (poison-tolerant).
    fn with_core<T>(
        &self,
        doc: &str,
        f: impl FnOnce(&mut AppCore<FsBlob>) -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        let handle = self
            .core(doc)
            .ok_or_else(|| HostError::NoCore(doc.to_string()))?;
        let mut guard = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Register a freshly-opened core for `doc`. If a core is ALREADY live for this doc (a re-open while a
    /// previous session's core is still registered — a recover / unlock / join / member-unlock), swap the new
    /// core in IN PLACE through the existing `Arc` rather than inserting a fresh one, so any op holding a clone
    /// `Arc` (e.g. a background sync) is serialized against the swap and never keeps running on the stale core
    /// (design-review F1/F3). Callers hold this doc's op-lock, so two opens never race here.
    fn register(&self, doc: &str, core: AppCore<FsBlob>) {
        let existing = self.lock_cores().get(doc).cloned();
        if let Some(handle) = existing {
            let mut guard = handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = core;
        } else {
            self.lock_cores()
                .insert(doc.to_string(), Arc::new(Mutex::new(core)));
        }
    }

    /// Lock the registry, recovering from a poisoned mutex (a panic in one op must not brick every later op —
    /// the map itself is not left in a torn state).
    fn lock_cores(&self) -> std::sync::MutexGuard<'_, CoreMap> {
        self.cores
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountRecord, AccountStatus, AppCoreHost, HostError, TreeId, VaultStore};
    use openom_crypto::{Passphrase, RecoveryCode};
    use openom_keyring_api::EngineKind;
    use openom_vault_host::{
        AccountBackupVersion, AccountBinding, AccountBlobHash, AccountGeneration, AccountMemberId,
        AccountRecordRevision, AccountRemoteCheckpoint, PendingAccountBackup, PendingBackupKind,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    type Rows = HashMap<String, (Vec<u8>, Vec<u8>)>;

    fn adoption_context(
        member_id: &str,
        version: openom_app_core::AccountBackupVersion,
    ) -> (AccountMemberId, AccountBinding, AccountRemoteCheckpoint) {
        let member_id = AccountMemberId::new(member_id);
        let binding = AccountBinding::new("https://issuer", "subject", member_id.clone());
        let version = AccountBackupVersion::new(
            AccountGeneration::new(version.generation().get()),
            AccountBlobHash::new(*version.blob_hash().as_bytes()),
        );
        (
            member_id,
            binding,
            AccountRemoteCheckpoint::new("\"remote\"", Some(version)),
        )
    }

    /// An in-memory [`VaultStore`] fake — the same shape the durable `SQLite` impl backs.
    #[derive(Default)]
    struct MemStore {
        rows: Mutex<Rows>,
        account: Mutex<Option<AccountRecord>>,
        fail_account_commit: AtomicBool,
    }
    impl VaultStore for MemStore {
        fn load_keyring(&self, tree_key: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(tree_key)
                .map(|(k, _)| k.clone()))
        }
        fn watermark(&self, tree_key: &str) -> Result<Vec<u8>, String> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(tree_key)
                .map(|(_, w)| w.clone())
                .unwrap_or_default())
        }
        fn commit_keyring(
            &self,
            tree_key: &str,
            anchor: &[u8],
            watermark: &[u8],
        ) -> Result<(), String> {
            self.rows
                .lock()
                .unwrap()
                .insert(tree_key.to_string(), (anchor.to_vec(), watermark.to_vec()));
            Ok(())
        }
        fn load_account(&self) -> Result<Option<AccountRecord>, String> {
            Ok(self.account.lock().unwrap().clone())
        }
        fn commit_account(
            &self,
            account: &AccountRecord,
            expected_revision: Option<AccountRecordRevision>,
        ) -> Result<(), String> {
            if self.fail_account_commit.load(Ordering::Relaxed) {
                return Err("injected account commit failure".into());
            }
            let mut stored = self.account.lock().unwrap();
            let found = stored.as_ref().map(AccountRecord::revision);
            if found != expected_revision {
                return Err("account record conflict".into());
            }
            let required = expected_revision.map_or(AccountRecordRevision::INITIAL, |revision| {
                revision.checked_next().unwrap()
            });
            if account.revision() != required {
                return Err("account record revision is not next".into());
            }
            if let Some(previous) = stored.as_ref() {
                account.preserves_custody_from(previous)?;
            }
            *stored = Some(account.clone());
            Ok(())
        }
    }

    fn temp_dir() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openom-host-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The owner's SELF-CERTIFYING on-tree `member_id` (OPE-543): `derive_member_id(account key)`, read from the
    /// persisted durable-account keystore. `provision` derives the owner id from the account key (ignoring the
    /// caller's label), so the owner-path ops (unlock / recover / membership) must be keyed by this id.
    fn owner_mid<St: VaultStore>(host: &AppCoreHost<St>, _doc: &str) -> String {
        openom_vault::AccountKeystore::from_bytes(
            host.store()
                .load_account()
                .unwrap()
                .unwrap()
                .identity()
                .keystore()
                .as_bytes(),
        )
        .unwrap()
        .member_id
    }

    #[test]
    fn provision_persists_the_keyring_natively_and_unlock_reads_it_not_from_the_webview() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [9u8; 16];

        let p = host
            .provision("doc-1", &tree_id, "acct-owner", &pass)
            .unwrap();
        assert!(!p.did_key.is_empty(), "and the author did:key");
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "doc-1");
        // The keyring is persisted NATIVELY — in this model the webview never holds it.
        assert!(
            host.store().load_keyring("doc-1").unwrap().is_some(),
            "keyring persisted natively on provision"
        );
        assert!(
            host.core("doc-1").is_some(),
            "the provisioned core is registered"
        );

        // Unlock reads the keyring FROM THE NATIVE STORE — no webview-supplied anchor — and re-derives the same
        // identity. (This is the security boundary: an XSS calling unlock can't substitute a stale/forged
        // keyring, because the host ignores any client-supplied anchor and reads its own; the replica id is
        // host-minted, so the webview can't pin a fork either.)
        let u = host.unlock("doc-1", &tree_id, &owner, &pass).unwrap();
        assert_eq!(
            u.did_key, p.did_key,
            "unlock re-derives the same identity from the native keyring"
        );

        // A wrong passphrase is refused.
        assert!(matches!(
            host.unlock(
                "doc-1",
                &tree_id,
                &owner,
                &Passphrase::new(b"wrong".to_vec())
            ),
            Err(HostError::Vault(_))
        ));
        // A tree the host has no keyring for can't be unlocked.
        assert!(matches!(
            host.unlock("doc-unknown", &tree_id, "acct-owner", &pass),
            Err(HostError::NoKeyring(_))
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    const PERSON: &str = "openom.org/core/person/v1";

    #[test]
    fn account_status_and_lock_follow_native_custody() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let passphrase = Passphrase::new(b"profile passphrase".to_vec());

        assert_eq!(host.account_status().unwrap(), AccountStatus::None);
        host.account_create(&passphrase).unwrap();
        assert_eq!(host.account_status().unwrap(), AccountStatus::Unlocked);

        let tree_id = TreeId::new([29; 16]);
        host.provision_tree("tree", &tree_id).unwrap();
        host.account_lock();
        assert!(host.core("tree").is_none());
        assert_eq!(host.account_status().unwrap(), AccountStatus::Locked);

        host.account_unlock(&passphrase).unwrap();
        assert_eq!(host.account_status().unwrap(), AccountStatus::Unlocked);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_backup_journal_compare_clears_only_the_exact_pending_version() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let passphrase = Passphrase::new(b"profile passphrase".to_vec());
        host.account_create(&passphrase).unwrap();
        let member_id = host.account_public_identity().unwrap().member_id;
        let binding = AccountBinding::new(
            "https://issuer",
            "subject-a",
            openom_vault_host::AccountMemberId::new(member_id.clone()),
        );

        let bound = host.account_confirm_binding(binding.clone()).unwrap();
        assert_eq!(bound.record.unwrap().revision, 2);
        let staged = host
            .account_stage_backup(PendingBackupKind::Backup, binding.clone())
            .unwrap();
        let wire = serde_json::to_value(&staged).unwrap();
        assert_eq!(wire["record"]["identity"]["memberId"], member_id);
        assert_eq!(wire["storagePersistence"], "native");
        assert_eq!(staged.record.unwrap().revision, 3);
        let stored = host.store().load_account().unwrap().unwrap();
        let expected = stored.pending_backup().unwrap().clone();
        let stale = PendingAccountBackup::new(
            PendingBackupKind::Backup,
            AccountBackupVersion::new(
                AccountGeneration::new(expected.version().generation().get() + 1),
                expected.version().blob_hash(),
            ),
            binding.clone(),
        );
        let stale_result = host
            .account_acknowledge_backup(
                &stale,
                AccountRemoteCheckpoint::new("\"etag\"", Some(expected.version())),
            )
            .unwrap();
        assert!(!stale_result.cleared);

        let acknowledged = host
            .account_acknowledge_backup(
                &expected,
                AccountRemoteCheckpoint::new("\"etag\"", Some(expected.version())),
            )
            .unwrap();
        assert!(acknowledged.cleared);
        assert!(acknowledged.record.unwrap().pending_backup.is_none());

        let revoke = host
            .account_stage_backup(PendingBackupKind::Revoke, binding.clone())
            .unwrap();
        let downgrade = host
            .account_stage_backup(PendingBackupKind::Backup, binding)
            .unwrap();
        assert_eq!(
            downgrade.record.unwrap().revision,
            revoke.record.unwrap().revision
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credential_mutations_journal_operation_specific_intent() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let initial = Passphrase::new(b"profile passphrase".to_vec());
        let created = host.account_create(&initial).unwrap();
        let member_id = host.account_public_identity().unwrap().member_id;
        let binding = AccountBinding::new(
            "https://issuer",
            "subject-a",
            AccountMemberId::new(member_id),
        );
        host.account_confirm_binding(binding).unwrap();

        let replacement = Passphrase::new(b"replacement passphrase".to_vec());
        let changed = host.account_change_passphrase(&replacement).unwrap();
        let changed_record = host.store().load_account().unwrap().unwrap();
        assert_eq!(changed.generation, created.generation);
        assert_eq!(
            changed_record.pending_backup().unwrap().kind(),
            PendingBackupKind::Backup
        );

        let rotated = host.account_rotate_root(&replacement).unwrap();
        let rotated_record = host.store().load_account().unwrap().unwrap();
        assert_eq!(rotated.generation, changed.generation + 1);
        assert_eq!(
            rotated_record.pending_backup().unwrap().kind(),
            PendingBackupKind::Revoke
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_gate_blocks_account_dependent_tree_lifecycle() {
        let dir = temp_dir();
        let host = Arc::new(AppCoreHost::new(
            MemStore::default(),
            &dir,
            EngineKind::Chain,
        ));
        host.account_create(&Passphrase::new(b"profile passphrase".to_vec()))
            .unwrap();
        let operation = host.account_op();
        let worker = Arc::clone(&host);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(
                    worker
                        .provision_tree("tree", &TreeId::new([27; 16]))
                        .is_ok(),
                )
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());

        drop(operation);
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap());
        thread.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn candidate_adoption_commits_before_replacing_native_custody() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let local_passphrase = Passphrase::new(b"local profile passphrase".to_vec());
        host.account_create(&local_passphrase).unwrap();
        let local_member = host.account_public_identity().unwrap().member_id;
        host.provision_tree("tree", &TreeId::new([28; 16])).unwrap();

        let remote_passphrase = Passphrase::new(b"remote profile passphrase".to_vec());
        let remote = openom_app_core::account_create(&remote_passphrase).unwrap();
        let remote_member = remote.handle.member_id().as_str().to_string();
        let remote_version = openom_app_core::account_snapshot(&remote.handle).version();
        let adoption = || adoption_context(&remote_member, remote_version);
        assert_ne!(local_member, remote_member);

        let (expected_member, binding, checkpoint) = adoption();
        assert!(host
            .account_adopt_candidate(
                &expected_member,
                &remote.keystore,
                &Passphrase::new(b"wrong passphrase".to_vec()),
                binding,
                checkpoint,
            )
            .is_err());
        assert_eq!(
            host.account_public_identity().unwrap().member_id,
            local_member
        );
        assert!(host.core("tree").is_some());

        let (_, binding, checkpoint) = adoption();
        let mismatch = match host.account_adopt_candidate(
            &AccountMemberId::new("member-not-the-candidate"),
            &remote.keystore,
            &remote_passphrase,
            binding,
            checkpoint,
        ) {
            Err(error) => error,
            Ok(_) => panic!("mismatched candidate was accepted"),
        };
        assert!(
            matches!(mismatch, HostError::IdentityConflict(_)),
            "unexpected mismatch error: {mismatch:?}"
        );
        assert_eq!(super::error_code(&mismatch), "identity_conflict");
        assert_eq!(
            host.account_public_identity().unwrap().member_id,
            local_member
        );

        host.store()
            .fail_account_commit
            .store(true, Ordering::Relaxed);
        let (expected_member, binding, checkpoint) = adoption();
        let commit_failure = match host.account_adopt_candidate(
            &expected_member,
            &remote.keystore,
            &remote_passphrase,
            binding,
            checkpoint,
        ) {
            Err(error) => error,
            Ok(_) => panic!("injected commit failure was accepted"),
        };
        assert!(matches!(commit_failure, HostError::AccountStorage(_)));
        assert_eq!(super::error_code(&commit_failure), "storage_blocked");
        assert_eq!(
            host.account_public_identity().unwrap().member_id,
            local_member
        );
        assert!(host.core("tree").is_some());

        host.store()
            .fail_account_commit
            .store(false, Ordering::Relaxed);
        let (expected_member, binding, checkpoint) = adoption();
        let adopted = host
            .account_adopt_candidate(
                &expected_member,
                &remote.keystore,
                &remote_passphrase,
                binding,
                checkpoint,
            )
            .unwrap();
        assert_eq!(adopted.member_id, remote_member);
        assert_eq!(
            host.account_public_identity().unwrap().member_id,
            remote_member
        );
        let sync = host.account_sync_state().unwrap().record.unwrap();
        assert_eq!(sync.retained_identities.len(), 1);
        assert_eq!(sync.retained_identities[0].member_id, local_member);
        assert!(host.core("tree").is_none());
        let snapshot = host.account_snapshot().unwrap();
        assert_eq!(snapshot.generation, adopted.generation);
        assert_eq!(snapshot.blob_hash, adopted.blob_hash);
        assert_eq!(snapshot.keystore, remote.keystore);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recovery_candidate_rotates_before_native_adoption() {
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let remote_passphrase = Passphrase::new(b"remote profile passphrase".to_vec());
        let remote = openom_app_core::account_create(&remote_passphrase).unwrap();
        let remote_member = remote.handle.member_id().as_str().to_string();
        let old_recovery = RecoveryCode::new(remote.recovery_code);
        let new_passphrase = Passphrase::new(b"recovered profile passphrase".to_vec());
        let remote_version = openom_app_core::account_snapshot(&remote.handle).version();
        let (expected_member, binding, checkpoint) =
            adoption_context(&remote_member, remote_version);

        let adopted = host
            .account_adopt_recovery_candidate(
                &expected_member,
                &remote.keystore,
                &old_recovery,
                &new_passphrase,
                binding,
                checkpoint,
            )
            .unwrap();

        assert_eq!(adopted.member_id, remote_member);
        assert_eq!(adopted.generation, remote.generation.get() + 1);
        assert_ne!(adopted.recovery_code, old_recovery.expose());
        assert_eq!(
            host.account_sync_state()
                .unwrap()
                .record
                .unwrap()
                .pending_backup
                .unwrap()
                .kind,
            PendingBackupKind::Revoke
        );
        host.account_lock();
        assert!(host
            .account_recover(
                &old_recovery,
                &Passphrase::new(b"second recovery passphrase".to_vec()),
            )
            .is_err());
        assert_eq!(
            host.account_unlock(&new_passphrase).unwrap().member_id,
            remote_member
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn one_native_account_owns_multiple_trees_and_changes_its_passphrase_once() {
        for (engine_index, engine) in [EngineKind::Chain, EngineKind::Dag].into_iter().enumerate() {
            let dir = temp_dir();
            let host = AppCoreHost::new(MemStore::default(), &dir, engine);
            let old = Passphrase::new(b"one profile passphrase".to_vec());
            let new = Passphrase::new(b"one changed profile passphrase".to_vec());
            let created = host.account_create(&old).unwrap();
            assert_eq!(
                host.store().load_account().unwrap().unwrap().revision(),
                AccountRecordRevision::INITIAL
            );
            let member_id = host.account_public_identity().unwrap().member_id;
            let first = TreeId::new([30 + engine_index as u8; 16]);
            let second = TreeId::new([40 + engine_index as u8; 16]);

            let first_open = host.provision_tree("first", &first).unwrap();
            let second_open = host.provision_tree("second", &second).unwrap();
            assert_eq!(first_open.did_key, second_open.did_key);

            host.account_change_passphrase(&new).unwrap();
            let changed_record = host.store().load_account().unwrap().unwrap();
            assert_eq!(changed_record.revision().get(), 2);
            assert_eq!(
                changed_record.identity().version().generation().get(),
                created.generation,
                "record revision advances independently of credential generation"
            );
            host.close("first");
            host.close("second");
            assert!(host.account_unlock(&old).is_err());
            assert_eq!(host.account_unlock(&new).unwrap().member_id, member_id);
            assert_eq!(
                host.open_tree("first", &first).unwrap().did_key,
                first_open.did_key
            );
            assert_eq!(
                host.open_tree("second", &second).unwrap().did_key,
                second_open.did_key
            );
            assert_eq!(
                host.account_register_proof("https://issuer", "subject", 1_700_000_000)
                    .unwrap()
                    .len(),
                64
            );
            let rotated = host.account_rotate_root(&new).unwrap();
            assert_eq!(rotated.generation, created.generation + 1);
            let rotated_record = host.store().load_account().unwrap().unwrap();
            assert_eq!(rotated_record.revision().get(), 3);
            assert_eq!(
                rotated_record.identity().version().generation().get(),
                rotated.generation
            );
            assert_eq!(host.account_public_identity().unwrap().member_id, member_id);

            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn an_offline_mint_survives_a_native_re_open_under_a_fresh_replica() {
        // OPE-431: provision + mint + commit OFFLINE (no sync), then re-open the SAME tree and bootstrap — the
        // mint is recovered from the durable local store. The host MINTS a fresh replica id per open, so the
        // re-opened core pulls its own persisted entries as a peer rather than skipping them as "our own"
        // (reusing the same replica would skip them); push_delta already writes the local head pointer on commit.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [3u8; 16];

        host.provision("t", &tree_id, "acct-owner", &pass).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        assert!(
            host.project("t").unwrap().contains("pAlice"),
            "the source session projects its own mint"
        );

        // Re-open (the durable keyring is read natively, a fresh replica is host-minted) + bootstrap.
        host.unlock("t", &tree_id, &owner, &pass).unwrap();
        host.bootstrap("t").unwrap();
        assert!(
            host.project("t").unwrap().contains("pAlice"),
            "the offline mint survives a native re-open under a fresh replica"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_native_hosts_converge_through_a_shared_remote() {
        // The distributed path, all native: two hosts (two devices of the SAME owner, the keyring distributed
        // to each native store), one mints + pushes to a shared remote snapshot, the other pulls + folds it.
        let (dir_a, dir_b) = (temp_dir(), temp_dir());
        let host_a = AppCoreHost::new(MemStore::default(), &dir_a, EngineKind::Chain);
        let host_b = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Chain);
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        let tree_id = [4u8; 16];

        host_a.provision("t", &tree_id, "owner", &pass).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host_a, "t");
        // Device B: same owner, the keyring AND the durable account keystore (OPE-543) distributed to B's
        // native store (B unlocks the owner account + keyring natively). Each host mints its own fresh replica
        // id, so A's and B's cores are distinct peers.
        let keyring = host_a.store().load_keyring("t").unwrap().unwrap();
        let account = host_a.store().load_account().unwrap().unwrap();
        host_b.store().commit_keyring("t", &keyring, &[]).unwrap();
        host_b.store().commit_account(&account, None).unwrap();
        host_b.unlock("t", &tree_id, &owner, &pass).unwrap();

        // A mints, commits, and pushes to the shared remote (empty → all of A's objects are uploads).
        host_a.assert_anchor("t", "pAlice", PERSON).unwrap();
        host_a.commit("t").unwrap();
        let remote: Vec<_> = host_a
            .sync("t", &[], &[], 0)
            .unwrap()
            .uploads
            .into_iter()
            .map(|u| (u.key, u.bytes))
            .collect();
        assert!(!remote.is_empty(), "A has objects to push to the remote");

        // B pulls the remote + folds → converges on A's mint.
        let present: Vec<String> = remote.iter().map(|(k, _)| k.clone()).collect();
        host_b.sync("t", &remote, &present, 0).unwrap();
        assert!(
            host_b.project("t").unwrap().contains("pAlice"),
            "B converges on A's mint via native sync"
        );

        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn recover_re_keys_natively_and_the_new_passphrase_unlocks() {
        // Recovery loads the stored keyring + the durable account keystore from NATIVE custody (never a webview
        // arg), restores the SAME durable identity via the account recovery code, re-wraps the account keystore
        // under a new passphrase, and persists it — so the new passphrase unlocks and the old one no longer does.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [9u8; 16];
        let old = Passphrase::new(b"the old passphrase here".to_vec());
        let account = host.account_create(&old).unwrap();
        host.provision_tree("t", &TreeId::new(tree_id)).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");

        let new = Passphrase::new(b"a brand new passphrase".to_vec());
        let r = host
            .recover(
                "t",
                &tree_id,
                &owner,
                &RecoveryCode::new(account.recovery_code),
                &new,
            )
            .unwrap();
        // Account recovery rotates the account root and returns one new account-level recovery code while the
        // owner identity is restored, not freshly minted.
        assert!(
            !r.recovery_code.is_empty(),
            "account recovery rotates the recovery code"
        );
        assert!(
            !r.did_key.is_empty(),
            "and yields the (restored) owner identity"
        );

        assert!(
            host.unlock("t", &tree_id, &owner, &new).is_ok(),
            "the new passphrase unlocks the re-keyed keyring from native custody"
        );
        assert!(
            host.unlock("t", &tree_id, &owner, &old).is_err(),
            "the old passphrase no longer unlocks"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn change_passphrase_re_wraps_natively_and_only_the_new_passphrase_unlocks() {
        // change-passphrase re-wraps the durable account keystore under a new passphrase (the tree DEK + anchor
        // unchanged) and persists it natively — so the new passphrase unlocks and the old one no longer does,
        // with no re-open of the running core.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [12u8; 16];
        let a = Passphrase::new(b"the first passphrase here".to_vec());
        host.provision("t", &tree_id, "owner", &a).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");

        let b = Passphrase::new(b"the second passphrase now".to_vec());
        let r = host
            .change_passphrase("t", &tree_id, &owner, &a, &b)
            .unwrap();
        // OPE-543 durable identity: a passphrase change is account-keystore-mediated — no per-tree recovery code.
        assert!(
            r.recovery_code.is_empty(),
            "change-passphrase mints no per-tree recovery code (account-mediated)"
        );

        assert!(
            host.unlock("t", &tree_id, &owner, &b).is_ok(),
            "the new passphrase unlocks the re-wrapped keyring"
        );
        assert!(
            host.unlock("t", &tree_id, &owner, &a).is_err(),
            "the old passphrase no longer unlocks"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_traversal_or_invalid_doc_id_is_refused_before_touching_the_filesystem() {
        // The webview supplies the doc id, so one that could escape data_dir (or is otherwise malformed) must be
        // rejected rather than joined onto the FsBlob path.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [1u8; 16];
        let pass = Passphrase::new(b"correct horse battery staple".to_vec());
        for bad in ["../escape", "a/b", "a\\b", "..", ""] {
            assert!(
                matches!(
                    host.provision(bad, &tree_id, "owner", &pass),
                    Err(HostError::Store(_))
                ),
                "the traversal/invalid doc id {bad:?} is refused"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn provision_member_mints_an_account_from_a_passphrase() {
        // The joining member's first step (before an owner admits them): stateless, no tree touched.
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let m = host
            .provision_member(&Passphrase::new(b"a joining member passphrase".to_vec()))
            .unwrap();
        assert!(
            m.kdf_params.is_empty(),
            "durable accounts need no per-tree member KDF custody"
        );
        assert!(
            !m.author_public_key.is_empty(),
            "the Ed25519 author key to hand the owner"
        );
        assert!(
            !m.hpke_public_key.is_empty(),
            "the X25519 HPKE key to hand the owner"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn add_member_admits_a_joiner_and_re_opens_the_owner_core_in_place() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let tree_id = [5u8; 16];
        host.provision("t", &tree_id, "owner", &owner_pass).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");

        // A joiner mints their account OOB; the owner admits them.
        let joiner = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        let member = MemberToAdd {
            member_id: openom_keyring_api::derive_member_id(&joiner.author_public_key),
            role: "editor".into(),
            author_public_key: joiner.author_public_key,
            hpke_public_key: joiner.hpke_public_key,
        };
        let added = host
            .add_member("t", &tree_id, &owner, &owner_pass, &member)
            .unwrap();
        assert!(
            !added.keyring.is_empty(),
            "a new keyring revision to publish"
        );
        assert!(
            host.store().load_keyring("t").unwrap().unwrap() == added.keyring,
            "the shared keyring is persisted natively"
        );

        // The owner core was re-opened IN PLACE on the shared keyring — it still mints + projects, proof it
        // came back as a signing, §B3-gated shared core (not the stale solo sealer).
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        assert!(
            host.project("t").unwrap().contains("pAlice"),
            "the re-opened shared owner core still writes + folds its own attributed mint"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_member_rotates_the_epoch_and_re_opens_the_owner_under_it() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let tree_id = [6u8; 16];
        host.provision("t", &tree_id, "owner", &owner_pass).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");

        // Share the tree, THEN mint (so the write is signed under the shared epoch, not the solo sealer).
        let joiner = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&joiner.author_public_key);
        let bob = MemberToAdd {
            member_id: bob_id.clone(),
            role: "editor".into(),
            author_public_key: joiner.author_public_key,
            hpke_public_key: joiner.hpke_public_key,
        };
        let added = host
            .add_member("t", &tree_id, &owner, &owner_pass, &bob)
            .unwrap();
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();

        // Remove bob: forward-secure rotation + owner re-open under the NEW epoch.
        let removed = host
            .remove_member("t", &tree_id, &owner, &owner_pass, &bob_id)
            .unwrap();
        assert!(
            !removed.keyring.is_empty(),
            "a rotated keyring revision to publish"
        );
        assert!(
            removed.keyring != added.keyring,
            "the removal rotated the keyring to a fresh epoch"
        );
        assert!(
            host.store().load_keyring("t").unwrap().unwrap() == removed.keyring,
            "the rotated keyring is persisted natively"
        );

        // The owner core re-opened under the NEW epoch — it still writes, and prior + post-removal history both
        // project (proof the re-opened core signs under the fresh epoch and hydrated the pinned history).
        host.assert_anchor("t", "pCarol", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        let proj = host.project("t").unwrap();
        assert!(
            proj.contains("pCarol"),
            "post-removal owner write projects under the rotated epoch"
        );
        assert!(
            proj.contains("pAlice"),
            "pre-removal history still projects after the rotation"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn change_role_promotes_then_demotes_without_rotating_the_epoch() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let tree_id = [7u8; 16];
        host.provision("t", &tree_id, "owner", &owner_pass).unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&host, "t");
        let joiner = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        // OPE-543: a member id self-certifies its author key.
        let bob_id = openom_keyring_api::derive_member_id(&joiner.author_public_key);
        let bob = MemberToAdd {
            member_id: bob_id.clone(),
            role: "editor".into(),
            author_public_key: joiner.author_public_key,
            hpke_public_key: joiner.hpke_public_key,
        };
        host.add_member("t", &tree_id, &owner, &owner_pass, &bob)
            .unwrap();
        host.assert_anchor("t", "pAlice", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();

        // Promote bob to co-owner, then demote back to editor — both change the keyring but NOT the epoch.
        let promoted = host
            .change_role("t", &tree_id, &owner, &owner_pass, &bob_id, "co-owner")
            .unwrap();
        assert!(!promoted.demote, "co-owner is a promote");
        let demoted = host
            .change_role("t", &tree_id, &owner, &owner_pass, &bob_id, "editor")
            .unwrap();
        assert!(demoted.demote, "a non-co-owner role is a demote");
        assert!(
            demoted.keyring != promoted.keyring,
            "each role change is a fresh keyring revision"
        );

        // No re-open, no epoch rotation: the owner core keeps writing and prior history stays projected.
        host.assert_anchor("t", "pBob", PERSON).unwrap();
        host.commit("t").unwrap();
        host.fold("t").unwrap();
        let proj = host.project("t").unwrap();
        assert!(
            proj.contains("pAlice") && proj.contains("pBob"),
            "history survives the promote + demote (no epoch rotation)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_member_joins_on_a_second_host_writes_and_converges_with_the_owner() {
        use super::MemberToAdd;
        let (dir_o, dir_b) = (temp_dir(), temp_dir());
        let owner_host = AppCoreHost::new(MemStore::default(), &dir_o, EngineKind::Chain);
        let bob_host = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Chain);
        let tree_id = [8u8; 16];
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let bob_pass = Passphrase::new(b"bob's own passphrase here".to_vec());

        // Bob mints his account on HIS device; the owner admits him as a Maintainer (can commit directly).
        let bob_acct = bob_host.provision_member(&bob_pass).unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&bob_acct.author_public_key);
        owner_host
            .provision("t", &tree_id, "acct-owner", &owner_pass)
            .unwrap();
        let bob_member = MemberToAdd {
            member_id: bob_id.clone(),
            role: "maintainer".into(),
            author_public_key: bob_acct.author_public_key.clone(),
            hpke_public_key: bob_acct.hpke_public_key.clone(),
        };
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let added = owner_host
            .add_member(
                "t",
                &tree_id,
                &owner_mid(&owner_host, "t"),
                &owner_pass,
                &bob_member,
            )
            .unwrap();

        // The owner publishes the keyring history; bob pulls it as hops (genesis + shared) + the OOB pin (genesis
        // hash). The genesis body is in the owner's native retention (revision 1).
        let genesis = owner_host
            .retained_revisions("t")
            .unwrap()
            .into_iter()
            .find(|(r, _)| *r == 1)
            .expect("genesis revision retained")
            .1;
        let hops =
            openom_vault::sharing::frame_keyring_hops(&[genesis.clone(), added.keyring.clone()]);
        let pin = openom_vault::sharing::chain_keyring_pin(&genesis).unwrap();

        // Bob JOINS on his device (verify walk vs the pin, unlock, establish native custody), then mints + pushes.
        bob_host
            .join_as_member(
                "t",
                &tree_id,
                &bob_id,
                &bob_pass,
                &bob_acct.kdf_params,
                &hops,
                1,
                &pin,
            )
            .unwrap();
        bob_host.assert_anchor("t", "pBob", PERSON).unwrap();
        bob_host.commit("t").unwrap();
        let remote: Vec<_> = bob_host
            .sync("t", &[], &[], 0)
            .unwrap()
            .uploads
            .into_iter()
            .map(|u| (u.key, u.bytes))
            .collect();

        // The owner pulls bob's write + folds → converges on the member's ATTRIBUTED collaborator write.
        let present: Vec<String> = remote.iter().map(|(k, _)| k.clone()).collect();
        owner_host.sync("t", &remote, &present, 0).unwrap();
        assert!(
            owner_host.project("t").unwrap().contains("pBob"),
            "the owner converges on the joined member's attributed write"
        );

        // Closing the last tree drops the resident account; one account unlock then drives unified role-based
        // reopen from the verified keyring, without a member context or per-tree KDF.
        bob_host.close("t");
        bob_host.account_unlock(&bob_pass).unwrap();
        assert!(
            bob_host.open_tree("t", &TreeId::new(tree_id)).is_ok(),
            "re-unlock from account custody"
        );
        assert!(
            bob_host
                .join_as_member(
                    "t",
                    &tree_id,
                    &bob_id,
                    &bob_pass,
                    &bob_acct.kdf_params,
                    &hops,
                    1,
                    &pin
                )
                .is_err(),
            "re-joining an already-joined tree is refused"
        );

        std::fs::remove_dir_all(&dir_o).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn a_member_joins_a_dag_tree_by_anchor_and_converges_with_the_owner() {
        use super::MemberToAdd;
        let (dir_o, dir_b) = (temp_dir(), temp_dir());
        let owner_host = AppCoreHost::new(MemStore::default(), &dir_o, EngineKind::Dag);
        let bob_host = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Dag);
        let tree_id = [21u8; 16];
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let bob_pass = Passphrase::new(b"bob's own passphrase here".to_vec());

        // Bob mints his account; the owner (dag) admits him as a Maintainer.
        let bob_acct = bob_host.provision_member(&bob_pass).unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&bob_acct.author_public_key);
        owner_host
            .provision("t", &tree_id, "acct-owner", &owner_pass)
            .unwrap();
        let bob_member = MemberToAdd {
            member_id: bob_id.clone(),
            role: "maintainer".into(),
            author_public_key: bob_acct.author_public_key.clone(),
            hpke_public_key: bob_acct.hpke_public_key.clone(),
        };
        let added = owner_host
            .add_member("t", &tree_id, "acct-owner", &owner_pass, &bob_member)
            .unwrap();

        // Dag: the published anchor is self-contained (no genesis-walk). The SERVED form is the MembershipEnvelope
        // the server stores (== the payload the owner publishes); bob receives that + the OOB dag pin, and joins by
        // verifying the anchor against the pin — the v3 native dag member-join path.
        let served =
            openom_keyring_api::MembershipEnvelope::wrap(EngineKind::Dag, added.keyring.clone())
                .encode();
        let pin = owner_host.invite_pin("t").unwrap();
        bob_host
            .join_dag_anchor(
                "t",
                &tree_id,
                &bob_id,
                &bob_pass,
                &bob_acct.kdf_params,
                &served,
                &pin,
            )
            .unwrap();
        assert!(
            bob_host.store().load_keyring("t").unwrap().is_some(),
            "the verified anchor is committed as native custody"
        );

        // Bob writes as an attributed member; the owner pulls + folds → converges on his write.
        bob_host.assert_anchor("t", "pBob", PERSON).unwrap();
        bob_host.commit("t").unwrap();
        let remote: Vec<_> = bob_host
            .sync("t", &[], &[], 0)
            .unwrap()
            .uploads
            .into_iter()
            .map(|u| (u.key, u.bytes))
            .collect();
        let present: Vec<String> = remote.iter().map(|(k, _)| k.clone()).collect();
        owner_host.sync("t", &remote, &present, 0).unwrap();
        assert!(
            owner_host.project("t").unwrap().contains("pBob"),
            "the owner converges on the joined dag member's attributed write"
        );

        // Re-open from account custody works; a second join is refused by the re-join guard.
        bob_host.close("t");
        bob_host.account_unlock(&bob_pass).unwrap();
        assert!(
            bob_host.open_tree("t", &TreeId::new(tree_id)).is_ok(),
            "re-unlock from account custody"
        );
        assert!(
            bob_host
                .join_dag_anchor(
                    "t",
                    &tree_id,
                    &bob_id,
                    &bob_pass,
                    &bob_acct.kdf_params,
                    &served,
                    &pin
                )
                .is_err(),
            "re-joining an already-joined dag tree is refused"
        );

        std::fs::remove_dir_all(&dir_o).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn a_removed_member_can_no_longer_unlock_the_rotated_keyring() {
        use super::MemberToAdd;
        let (dir_o, dir_b) = (temp_dir(), temp_dir());
        let owner_host = AppCoreHost::new(MemStore::default(), &dir_o, EngineKind::Chain);
        let bob_host = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Chain);
        let tree_id = [14u8; 16];
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let bob_pass = Passphrase::new(b"bob's own passphrase here".to_vec());

        let bob_acct = bob_host.provision_member(&bob_pass).unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&bob_acct.author_public_key);
        owner_host
            .provision("t", &tree_id, "acct-owner", &owner_pass)
            .unwrap();
        let bob_member = MemberToAdd {
            member_id: bob_id.clone(),
            role: "maintainer".into(),
            author_public_key: bob_acct.author_public_key.clone(),
            hpke_public_key: bob_acct.hpke_public_key.clone(),
        };
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&owner_host, "t");
        let added = owner_host
            .add_member("t", &tree_id, &owner, &owner_pass, &bob_member)
            .unwrap();
        let genesis = owner_host
            .retained_revisions("t")
            .unwrap()
            .into_iter()
            .find(|(r, _)| *r == 1)
            .unwrap()
            .1;
        let hops =
            openom_vault::sharing::frame_keyring_hops(&[genesis.clone(), added.keyring.clone()]);
        let pin = openom_vault::sharing::chain_keyring_pin(&genesis).unwrap();
        bob_host
            .join_as_member(
                "t",
                &tree_id,
                &bob_id,
                &bob_pass,
                &bob_acct.kdf_params,
                &hops,
                1,
                &pin,
            )
            .unwrap();
        assert!(
            bob_host
                .unlock_as_member("t", &tree_id, &bob_id, &bob_pass)
                .is_ok(),
            "bob unlocks while he is still a member"
        );

        // Owner removes bob (a forward-secure epoch rotation).
        let removed = owner_host
            .remove_member("t", &tree_id, &owner, &owner_pass, &bob_id)
            .unwrap();

        // Bob accepts the rotated keyring into his custody (as a keyring sync would) and can no longer unlock:
        // his DEK wrap is gone from the fresh epoch, so the member unwrap fails (forward secrecy).
        let bob_wm = bob_host.store().watermark("t").unwrap();
        bob_host
            .store()
            .commit_keyring("t", &removed.keyring, &bob_wm)
            .unwrap();
        assert!(
            bob_host
                .unlock_as_member("t", &tree_id, &bob_id, &bob_pass)
                .is_err(),
            "a removed member cannot unlock the rotated keyring (forward-secure)"
        );

        std::fs::remove_dir_all(&dir_o).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn a_membership_op_swaps_the_core_in_place_not_a_fresh_arc() {
        use super::MemberToAdd;
        let dir = temp_dir();
        let host = AppCoreHost::new(MemStore::default(), &dir, EngineKind::Chain);
        let tree_id = [15u8; 16];
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        host.provision("t", &tree_id, "acct-owner", &owner_pass)
            .unwrap();
        let bob = host
            .provision_member(&Passphrase::new(b"the joiner passphrase".to_vec()))
            .unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&bob.author_public_key);
        let member = MemberToAdd {
            member_id: bob_id,
            role: "editor".into(),
            author_public_key: bob.author_public_key,
            hpke_public_key: bob.hpke_public_key,
        };

        // The per-doc core handle BEFORE the membership op...
        let before = host.core("t").unwrap();
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        host.add_member("t", &tree_id, &owner_mid(&host, "t"), &owner_pass, &member)
            .unwrap();
        let after = host.core("t").unwrap();
        // ...is the SAME Arc afterward: add_member replaced the inner AppCore IN PLACE under the held lock, never
        // inserted a fresh Arc — so a concurrent op that already cloned `before` is serialized against the swap
        // rather than left running on a stale, pre-rotation core (design-review F1/F3).
        assert!(
            std::sync::Arc::ptr_eq(&before, &after),
            "a membership op swaps the core in place, preserving the per-doc Arc"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_member_adopts_a_newer_keyring_revision_on_sync() {
        use super::MemberToAdd;
        let (dir_o, dir_b) = (temp_dir(), temp_dir());
        let owner_host = AppCoreHost::new(MemStore::default(), &dir_o, EngineKind::Chain);
        let bob_host = AppCoreHost::new(MemStore::default(), &dir_b, EngineKind::Chain);
        let tree_id = [16u8; 16];
        let owner_pass = Passphrase::new(b"the owner passphrase now".to_vec());
        let bob_pass = Passphrase::new(b"bob's own passphrase here".to_vec());

        // Owner + bob joined (bob's anchor = revision 2).
        let bob_acct = bob_host.provision_member(&bob_pass).unwrap();
        let bob_id = openom_keyring_api::derive_member_id(&bob_acct.author_public_key);
        owner_host
            .provision("t", &tree_id, "acct-owner", &owner_pass)
            .unwrap();
        let bob_member = MemberToAdd {
            member_id: bob_id.clone(),
            role: "maintainer".into(),
            author_public_key: bob_acct.author_public_key.clone(),
            hpke_public_key: bob_acct.hpke_public_key.clone(),
        };
        // OPE-543: the owner's on-tree id is the account keystore's SELF-CERTIFYING `member_id`, not the label.
        let owner = owner_mid(&owner_host, "t");
        let rev2 = owner_host
            .add_member("t", &tree_id, &owner, &owner_pass, &bob_member)
            .unwrap();
        let genesis = owner_host
            .retained_revisions("t")
            .unwrap()
            .into_iter()
            .find(|(r, _)| *r == 1)
            .unwrap()
            .1;
        let hops =
            openom_vault::sharing::frame_keyring_hops(&[genesis.clone(), rev2.keyring.clone()]);
        let pin = openom_vault::sharing::chain_keyring_pin(&genesis).unwrap();
        bob_host
            .join_as_member(
                "t",
                &tree_id,
                &bob_id,
                &bob_pass,
                &bob_acct.kdf_params,
                &hops,
                1,
                &pin,
            )
            .unwrap();

        // Owner admits carol (revision 3); bob syncs the keyring (the successor hop).
        let carol = owner_host
            .provision_member(&Passphrase::new(b"carol's own passphrase".to_vec()))
            .unwrap();
        let carol_id = openom_keyring_api::derive_member_id(&carol.author_public_key);
        let carol_member = MemberToAdd {
            member_id: carol_id,
            role: "editor".into(),
            author_public_key: carol.author_public_key,
            hpke_public_key: carol.hpke_public_key,
        };
        let rev3 = owner_host
            .add_member("t", &tree_id, &owner, &owner_pass, &carol_member)
            .unwrap();
        let successor =
            openom_vault::sharing::frame_keyring_hops(std::slice::from_ref(&rev3.keyring));
        bob_host
            .sync_keyring("t", &TreeId::new(tree_id), &successor)
            .unwrap();

        assert_eq!(
            bob_host.store().load_keyring("t").unwrap().unwrap(),
            rev3.keyring,
            "bob adopted the newer keyring head"
        );
        assert!(
            bob_host
                .retained_revisions("t")
                .unwrap()
                .iter()
                .any(|(r, _)| *r == 3),
            "bob retained the new revision for the §B3 look-behind"
        );
        assert!(
            bob_host
                .unlock_as_member("t", &tree_id, &bob_id, &bob_pass)
                .is_ok(),
            "bob still unlocks under the adopted keyring"
        );

        std::fs::remove_dir_all(&dir_o).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }
}
