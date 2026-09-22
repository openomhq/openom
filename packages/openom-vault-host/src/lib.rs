#![doc = include_str!("../README.md")]

#[cfg(feature = "sqlite")]
pub mod sqlite;

use sha2::{Digest, Sha256};

/// Opaque serialized account-keystore bytes. A distinct type prevents keyring, watermark, and account bytes
/// from being interchanged at the public persistence boundary.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AccountKeystore(Vec<u8>);

impl AccountKeystore {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Highest authenticated account-keystore generation observed by this profile.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
)]
#[serde(transparent)]
pub struct AccountGeneration(u64);

impl AccountGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Highest authenticated account generation accepted for one durable identity.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
)]
#[serde(transparent)]
pub struct AccountGenerationFloor(u64);

impl AccountGenerationFloor {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Portable revision of the complete local account record. It is not a keystore generation or store CAS token.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct AccountRecordRevision(u64);

impl AccountRecordRevision {
    pub const INITIAL: Self = Self(1);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Stable self-certifying member id whose generation floor this record protects.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AccountMemberId(String);

impl AccountMemberId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 digest of the exact wrapped account bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AccountBlobHash([u8; 32]);

impl AccountBlobHash {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Credential-authenticated identity of one wrapped account blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBackupVersion {
    generation: AccountGeneration,
    blob_hash: AccountBlobHash,
}

impl AccountBackupVersion {
    #[must_use]
    pub const fn new(generation: AccountGeneration, blob_hash: AccountBlobHash) -> Self {
        Self {
            generation,
            blob_hash,
        }
    }

    #[must_use]
    pub const fn generation(self) -> AccountGeneration {
        self.generation
    }

    #[must_use]
    pub const fn blob_hash(self) -> AccountBlobHash {
        self.blob_hash
    }
}

/// Wrapped account custody plus the anti-rollback floor scoped to its stable identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountIdentityRecord {
    member_id: AccountMemberId,
    keystore: AccountKeystore,
    version: AccountBackupVersion,
    floor: AccountGenerationFloor,
}

impl AccountIdentityRecord {
    #[must_use]
    pub fn new(
        member_id: AccountMemberId,
        keystore: AccountKeystore,
        version: AccountBackupVersion,
        floor: AccountGenerationFloor,
    ) -> Self {
        Self {
            member_id,
            keystore,
            version,
            floor: AccountGenerationFloor::new(floor.get().max(version.generation().get())),
        }
    }

    #[must_use]
    pub const fn member_id(&self) -> &AccountMemberId {
        &self.member_id
    }

    #[must_use]
    pub const fn keystore(&self) -> &AccountKeystore {
        &self.keystore
    }

    #[must_use]
    pub const fn version(&self) -> AccountBackupVersion {
        self.version
    }

    #[must_use]
    pub const fn persisted_floor(&self) -> AccountGenerationFloor {
        self.floor
    }

    #[must_use]
    pub fn effective_floor(&self) -> AccountGenerationFloor {
        AccountGenerationFloor::new(self.floor.get().max(self.version.generation().get()))
    }

    fn advance_floor(&mut self, floor: AccountGenerationFloor) {
        self.floor = AccountGenerationFloor::new(self.effective_floor().get().max(floor.get()));
    }
}

/// Last auth-provider subject confirmed to be bound to an account identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBinding {
    issuer: String,
    subject: String,
    member_id: AccountMemberId,
}

impl AccountBinding {
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        member_id: AccountMemberId,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
            member_id,
        }
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub const fn member_id(&self) -> &AccountMemberId {
        &self.member_id
    }
}

/// Last server backup state acknowledged for the confirmed binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRemoteCheckpoint {
    etag: String,
    version: Option<AccountBackupVersion>,
}

impl AccountRemoteCheckpoint {
    #[must_use]
    pub fn new(etag: impl Into<String>, version: Option<AccountBackupVersion>) -> Self {
        Self {
            etag: etag.into(),
            version,
        }
    }

    #[must_use]
    pub fn etag(&self) -> &str {
        &self.etag
    }

    #[must_use]
    pub const fn version(&self) -> Option<AccountBackupVersion> {
        self.version
    }
}

/// Why a local account version must still be uploaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PendingBackupKind {
    Backup,
    Revoke,
}

/// Durable upload intent pinned to both an exact blob version and auth binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAccountBackup {
    kind: PendingBackupKind,
    version: AccountBackupVersion,
    binding: AccountBinding,
}

impl PendingAccountBackup {
    #[must_use]
    pub const fn new(
        kind: PendingBackupKind,
        version: AccountBackupVersion,
        binding: AccountBinding,
    ) -> Self {
        Self {
            kind,
            version,
            binding,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PendingBackupKind {
        self.kind
    }

    #[must_use]
    pub const fn version(&self) -> AccountBackupVersion {
        self.version
    }

    #[must_use]
    pub const fn binding(&self) -> &AccountBinding {
        &self.binding
    }
}

/// Complete singleton profile account record, committed as one revision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRecord {
    revision: AccountRecordRevision,
    identity: AccountIdentityRecord,
    binding: Option<AccountBinding>,
    acknowledged_backup: Option<AccountRemoteCheckpoint>,
    pending_backup: Option<PendingAccountBackup>,
}

impl AccountRecord {
    #[must_use]
    pub const fn new(identity: AccountIdentityRecord) -> Self {
        Self {
            revision: AccountRecordRevision::INITIAL,
            identity,
            binding: None,
            acknowledged_backup: None,
            pending_backup: None,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> AccountRecordRevision {
        self.revision
    }

    #[must_use]
    pub const fn identity(&self) -> &AccountIdentityRecord {
        &self.identity
    }

    #[must_use]
    pub const fn binding(&self) -> Option<&AccountBinding> {
        self.binding.as_ref()
    }

    #[must_use]
    pub const fn acknowledged_backup(&self) -> Option<&AccountRemoteCheckpoint> {
        self.acknowledged_backup.as_ref()
    }

    #[must_use]
    pub const fn pending_backup(&self) -> Option<&PendingAccountBackup> {
        self.pending_backup.as_ref()
    }

    /// Build the next revision around verified identity bytes. Metadata survives only for the same identity.
    ///
    /// # Errors
    /// Returns an error if the portable record revision is exhausted.
    pub fn next_identity(&self, mut identity: AccountIdentityRecord) -> Result<Self, String> {
        let revision = self
            .revision
            .checked_next()
            .ok_or_else(|| "account record revision exhausted".to_string())?;
        if identity.member_id == self.identity.member_id {
            if identity.version.generation().get() < self.identity.effective_floor().get() {
                return Err("account generation rollback".into());
            }
            identity.advance_floor(self.identity.effective_floor());
            let pending_backup = self
                .pending_backup
                .clone()
                .filter(|pending| pending.version == identity.version);
            Ok(Self {
                revision,
                identity,
                binding: self.binding.clone(),
                acknowledged_backup: self.acknowledged_backup.clone(),
                pending_backup,
            })
        } else {
            Ok(Self {
                revision,
                identity,
                binding: None,
                acknowledged_backup: None,
                pending_backup: None,
            })
        }
    }

    /// Validate identity scoping after deserializing an untrusted/corrupt local record.
    ///
    /// # Errors
    /// Returns an error when binding or pending metadata belongs to another identity.
    pub fn validate(&self) -> Result<(), String> {
        if self.revision.get() == 0 {
            return Err("account record revision must be non-zero".into());
        }
        if self.identity.member_id.as_str().is_empty() {
            return Err("account member id must not be empty".into());
        }
        let actual_hash: [u8; 32] = Sha256::digest(self.identity.keystore.as_bytes()).into();
        if actual_hash != *self.identity.version.blob_hash().as_bytes() {
            return Err("account blob hash does not match wrapped bytes".into());
        }
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.member_id != self.identity.member_id)
        {
            return Err("account binding belongs to another identity".into());
        }
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.issuer.is_empty() || binding.subject.is_empty())
        {
            return Err("account binding issuer and subject must not be empty".into());
        }
        if self.acknowledged_backup.is_some() && self.binding.is_none() {
            return Err("acknowledged account backup has no confirmed binding".into());
        }
        if self
            .acknowledged_backup
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.etag.is_empty())
        {
            return Err("acknowledged account backup ETag must not be empty".into());
        }
        if self
            .pending_backup
            .as_ref()
            .is_some_and(|pending| pending.binding.member_id != self.identity.member_id)
        {
            return Err("pending account backup belongs to another identity".into());
        }
        if self
            .pending_backup
            .as_ref()
            .is_some_and(|pending| self.binding.as_ref() != Some(&pending.binding))
        {
            return Err("pending account backup binding is not confirmed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod account_record_tests {
    use super::*;

    fn identity(member_id: &str, generation: u64, byte: u8) -> AccountIdentityRecord {
        let keystore = vec![byte; 4];
        AccountIdentityRecord::new(
            AccountMemberId::new(member_id),
            AccountKeystore::new(keystore.clone()),
            AccountBackupVersion::new(
                AccountGeneration::new(generation),
                AccountBlobHash::new(Sha256::digest(&keystore).into()),
            ),
            AccountGenerationFloor::new(generation),
        )
    }

    #[test]
    fn effective_floor_self_heals_a_lower_persisted_value() {
        let record = AccountRecord::new(identity("member-a", 7, 7));
        let mut encoded = serde_json::to_value(&record).unwrap();
        encoded["identity"]["floor"] = serde_json::json!(3);
        let restored: AccountRecord = serde_json::from_value(encoded).unwrap();

        assert_eq!(restored.identity().persisted_floor().get(), 3);
        assert_eq!(restored.identity().effective_floor().get(), 7);
    }

    #[test]
    fn a_different_identity_gets_its_own_floor_and_drops_remote_state() {
        let mut record = AccountRecord::new(identity("member-a", 7, 7));
        let binding = AccountBinding::new(
            "https://issuer",
            "subject-a",
            AccountMemberId::new("member-a"),
        );
        record.binding = Some(binding.clone());
        record.acknowledged_backup = Some(AccountRemoteCheckpoint::new(
            "\"etag-a\"",
            Some(record.identity().version()),
        ));
        record.pending_backup = Some(PendingAccountBackup::new(
            PendingBackupKind::Backup,
            record.identity().version(),
            binding,
        ));
        record.validate().unwrap();

        let replacement = record.next_identity(identity("member-b", 1, 1)).unwrap();

        assert_eq!(replacement.identity().member_id().as_str(), "member-b");
        assert_eq!(replacement.identity().effective_floor().get(), 1);
        assert!(replacement.binding().is_none());
        assert!(replacement.acknowledged_backup().is_none());
        assert!(replacement.pending_backup().is_none());
    }

    #[test]
    fn a_changed_blob_keeps_the_remote_base_but_not_a_stale_pending_intent() {
        let mut record = AccountRecord::new(identity("member-a", 7, 7));
        let binding = AccountBinding::new(
            "https://issuer",
            "subject-a",
            AccountMemberId::new("member-a"),
        );
        let remote_version = record.identity().version();
        record.binding = Some(binding.clone());
        record.acknowledged_backup = Some(AccountRemoteCheckpoint::new(
            "\"etag-a\"",
            Some(remote_version),
        ));
        record.pending_backup = Some(PendingAccountBackup::new(
            PendingBackupKind::Backup,
            remote_version,
            binding,
        ));

        let replacement = record.next_identity(identity("member-a", 7, 8)).unwrap();

        assert_eq!(
            replacement
                .acknowledged_backup()
                .and_then(AccountRemoteCheckpoint::version),
            Some(remote_version)
        );
        assert_ne!(
            replacement
                .acknowledged_backup()
                .and_then(AccountRemoteCheckpoint::version),
            Some(replacement.identity().version())
        );
        assert!(replacement.pending_backup().is_none());
    }

    #[test]
    fn validation_rejects_a_blob_hash_for_different_wrapped_bytes() {
        let record = AccountRecord::new(identity("member-a", 1, 1));
        let mut encoded = serde_json::to_value(&record).unwrap();
        encoded["identity"]["keystore"] = serde_json::json!([2, 2, 2, 2]);
        let corrupted: AccountRecord = serde_json::from_value(encoded).unwrap();

        assert!(corrupted.validate().is_err());
    }
}

// ---------------------------------------------------------------- storage seam

/// Persistence for the keyring (a wrapped DEK — not secret, needs durability) and the keyring-revision
/// watermark (anti-rollback state).
///
/// Injected so the native host is testable with an in-memory fake and, on Tauri, backs onto durable `SQLite`
/// ([`sqlite::SqliteVaultStore`]). Account blob/version, floor, binding, acknowledgement, and pending intent
/// cross this seam as one revisioned value; keyring custody remains independently per tree.
///
/// (This crate was also the home of the older thin-custody `VaultHost`, which the native full-core
/// [`openom-app-core-host`](https://docs.rs/openom-app-core-host) superseded and which has been removed — only
/// this custody seam and its `SQLite` implementation remain.)
pub trait VaultStore: Send + Sync {
    /// The current keyring anchor to unlock from (the head record — one blob per tree; `None` if none).
    ///
    /// # Errors
    /// Returns an error string if the host store read fails.
    fn load_keyring(&self, tree_key: &str) -> std::result::Result<Option<Vec<u8>>, String>;
    /// The engine-OPAQUE anti-rollback watermark for this tree (empty = none). The order check lives INSIDE the
    /// engine, so the store just persists these bytes and hands them back as the floor.
    ///
    /// # Errors
    /// Returns an error string if the host store read fails.
    fn watermark(&self, tree_key: &str) -> std::result::Result<Vec<u8>, String>;
    /// **Atomically** persist a newly-accepted keyring `anchor` and its `watermark` cursor, in ONE durable
    /// transaction — so a crash can never leave the stored anchor and its cursor disagreeing.
    ///
    /// # Errors
    /// Returns an error string if the host store write fails (e.g. a CAS conflict).
    fn commit_keyring(
        &self,
        tree_key: &str,
        anchor: &[u8],
        watermark: &[u8],
    ) -> std::result::Result<(), String>;

    /// The singleton profile account record (`None` before account creation).
    ///
    /// # Errors
    /// Returns an error string if the host store read fails.
    fn load_account(&self) -> std::result::Result<Option<AccountRecord>, String>;

    /// Atomically commit the complete account record when its portable revision follows `expected_revision`.
    ///
    /// # Errors
    /// Returns an error string if the host store write fails.
    fn commit_account(
        &self,
        account: &AccountRecord,
        expected_revision: Option<AccountRecordRevision>,
    ) -> std::result::Result<(), String>;
}
