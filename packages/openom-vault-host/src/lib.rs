#![doc = include_str!("../README.md")]

#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Opaque serialized account-keystore bytes. A distinct type prevents keyring, watermark, and account bytes
/// from being interchanged at the public persistence boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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

/// The singleton profile account record. Keystore and generation are committed atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    pub keystore: AccountKeystore,
    pub generation: AccountGeneration,
}

// ---------------------------------------------------------------- storage seam

/// Persistence for the keyring (a wrapped DEK — not secret, needs durability) and the keyring-revision
/// watermark (anti-rollback state).
///
/// Injected so the native host is testable with an in-memory fake and, on Tauri, backs onto durable `SQLite`
/// ([`sqlite::SqliteVaultStore`]). The snapshot-hash replay window (a separate, sync-layer concern) is
/// intentionally NOT here — the vault flows only need the keyring anchor + its anti-rollback floor.
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

    /// Atomically persist the singleton account keystore and its authenticated generation.
    ///
    /// # Errors
    /// Returns an error string if the host store write fails.
    fn commit_account(&self, account: &AccountRecord) -> std::result::Result<(), String>;
}
