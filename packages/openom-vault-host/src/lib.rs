#![doc = include_str!("../README.md")]

#[cfg(feature = "sqlite")]
pub mod sqlite;

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

    /// The persisted durable-account keystore blob (OPE-542/543) for this tree (`None` if none). OPAQUE bytes —
    /// the account's wrapped identity/root; no crypto lives here, the store just durably holds the blob the dag
    /// (owner-as-member) engine hands back at provision and needs again on unlock / recover / passphrase change.
    /// Empty / `None` for the chain engine, which has no account keystore.
    ///
    /// # Errors
    /// Returns an error string if the host store read fails.
    fn load_keystore(&self, tree_key: &str) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Persist the account keystore blob for this tree (write-through opaque bytes; last write wins). Called
    /// at provision and after any flow that re-wraps the account (recover / change-passphrase).
    ///
    /// # Errors
    /// Returns an error string if the host store write fails.
    fn commit_keystore(&self, tree_key: &str, keystore: &[u8]) -> std::result::Result<(), String>;
}
