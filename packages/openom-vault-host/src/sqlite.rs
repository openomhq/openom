//! A durable [`VaultStore`] on `SQLite`, for the Tauri host.
//!
//! Holds the revisioned profile-account record, each keyring (a wrapped DEK — not secret, needs only
//! durability), and the keyring-revision watermark (anti-rollback state) in the app data dir. Keep this in its
//! OWN file (`vault.sqlite`), separate
//! from the doc store's `tree.sqlite`, so copying/restoring the tree database can't drag the
//! watermark back with it.
//!
//! [`commit_keyring`] writes the keyring and advances the watermark in ONE transaction, so a
//! crash can never leave them disagreeing. The unlock path uses [`observe_keyring_revision`] to
//! re-assert the floor without touching the keyring.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use store_schema::ResetPolicy;

use crate::{AccountRecord, AccountRecordRevision, VaultStore};

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS keyrings (
       tree_key TEXT PRIMARY KEY,
       bytes    BLOB NOT NULL
     );
     CREATE TABLE IF NOT EXISTS watermarks (
       tree_key  TEXT PRIMARY KEY,
       watermark BLOB NOT NULL
     );
     CREATE TABLE IF NOT EXISTS account (
       singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
       record     BLOB NOT NULL
     );";

/// The schema version stamped in the DB header (`PRAGMA user_version`). BUMP THIS whenever [`SCHEMA`] changes
/// (the golden-shape test enforces it). Anti-drift: on a version mismatch, `open` self-heals in DEBUG (renaming
/// the stale DB to a `.bak` — this store holds the only local wrapped-DEK copy + the anti-rollback watermark, so
/// it is NEVER destroyed) and FAILS CLOSED in release (errors, touches nothing). See [`store_schema`].
///
/// v4: replaced the split account columns with one revisioned, identity-scoped custody/sync record.
const SCHEMA_VERSION: i64 = 4;

pub struct SqliteVaultStore {
    conn: Mutex<Connection>,
}

impl SqliteVaultStore {
    /// Durable, file-backed (WAL). Use the app data dir on Tauri. Versioned via [`store_schema::open_versioned`]
    /// with the [`ResetPolicy::Preserve`] policy (a schema mismatch renames the stale DB to a recoverable `.bak`
    /// in debug, and fails closed in release — never destroying the keyring/watermark).
    ///
    /// # Errors
    /// Returns an error string if the database can't be opened, or (release) if the on-disk schema version
    /// doesn't match this build.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = store_schema::open_versioned(
            path.as_ref(),
            SCHEMA_VERSION,
            SCHEMA,
            ResetPolicy::Preserve,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Flüchtig — für Tests. No on-disk drift is possible, so it just creates the schema and stamps the version.
    ///
    /// # Errors
    /// Returns an error string if the in-memory database can't be opened or the schema can't be applied.
    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(&format!(
            "{SCHEMA}\nPRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl VaultStore for SqliteVaultStore {
    fn load_keyring(&self, tree_key: &str) -> Result<Option<Vec<u8>>, String> {
        self.conn()
            .query_row(
                "SELECT bytes FROM keyrings WHERE tree_key = ?1",
                params![tree_key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.to_string()),
            })
    }

    fn watermark(&self, tree_key: &str) -> Result<Vec<u8>, String> {
        // Engine-OPAQUE bytes (the anti-rollback order check lives inside the engine); read + return.
        self.conn()
            .query_row(
                "SELECT watermark FROM watermarks WHERE tree_key = ?1",
                params![tree_key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(Vec::new()),
                other => Err(other.to_string()),
            })
    }

    fn commit_keyring(
        &self,
        tree_key: &str,
        anchor: &[u8],
        watermark: &[u8],
    ) -> Result<(), String> {
        // One transaction: the keyring write and the watermark advance land together or not at all,
        // so a crash can never leave a saved keyring with a stale cursor (or vice versa). The cursor
        // is write-through opaque bytes (the engine owns the order), so no MAX here.
        let mut guard = self.conn();
        let tx = guard.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO keyrings (tree_key, bytes) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET bytes = excluded.bytes",
            params![tree_key, anchor],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO watermarks (tree_key, watermark) VALUES (?1, ?2)
             ON CONFLICT(tree_key) DO UPDATE SET watermark = excluded.watermark",
            params![tree_key, watermark],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn load_account(&self) -> Result<Option<AccountRecord>, String> {
        let bytes: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT record FROM account WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        bytes
            .map(|bytes| {
                let record: AccountRecord =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    fn commit_account(
        &self,
        account: &AccountRecord,
        expected_revision: Option<AccountRecordRevision>,
    ) -> Result<(), String> {
        account.validate()?;
        let mut connection = self.conn();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current_bytes: Option<Vec<u8>> = tx
            .query_row(
                "SELECT record FROM account WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current = current_bytes
            .map(|bytes| {
                serde_json::from_slice::<AccountRecord>(&bytes).map_err(|error| error.to_string())
            })
            .transpose()?;
        if let Some(record) = &current {
            record.validate()?;
        }
        let current_revision = current.as_ref().map(AccountRecord::revision);
        if current_revision != expected_revision {
            return Err(format!(
                "account record conflict: expected {expected_revision:?}, found {current_revision:?}"
            ));
        }
        let required_revision = match expected_revision {
            Some(revision) => revision
                .checked_next()
                .ok_or_else(|| "account record revision exhausted".to_string())?,
            None => AccountRecordRevision::INITIAL,
        };
        if account.revision() != required_revision {
            return Err("account record revision is not the next revision".into());
        }
        if let Some(stored) = &current {
            account.preserves_custody_from(stored)?;
        }
        let encoded = serde_json::to_vec(account).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO account (singleton, record) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET record = excluded.record",
            params![encoded],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountBackupVersion, AccountBlobHash, AccountGeneration, AccountGenerationFloor,
        AccountIdentityRecord, AccountKeystore, AccountMemberId,
    };
    use sha2::{Digest, Sha256};

    fn account_identity(member_id: &str, generation: u64, byte: u8) -> AccountIdentityRecord {
        let keystore = vec![byte; 8];
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
    fn keyring_and_watermark_persist_across_reopen() {
        let path = std::env::temp_dir().join(format!("openom-vault-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            // The watermark is engine-opaque write-through bytes — last write wins (the engine, not the
            // store, owns anti-rollback), and the keyring + its cursor land in one transaction.
            s.commit_keyring("my-tree", b"kr-bytes", &[0, 0, 0, 1])
                .unwrap();
            s.commit_keyring("my-tree", b"kr-bytes", &[0, 0, 0, 3])
                .unwrap();
            let account = AccountRecord::new(account_identity("member-a", 7, 7));
            s.commit_account(&account, None).unwrap();
        }
        {
            let s = SqliteVaultStore::open(&path).unwrap();
            assert_eq!(
                s.load_keyring("my-tree").unwrap().as_deref(),
                Some(&b"kr-bytes"[..])
            );
            assert_eq!(s.watermark("my-tree").unwrap(), vec![0, 0, 0, 3]);
            assert_eq!(s.load_keyring("absent").unwrap(), None);
            assert!(s.watermark("absent").unwrap().is_empty());
            assert_eq!(
                s.load_account().unwrap(),
                Some(AccountRecord::new(account_identity("member-a", 7, 7)))
            );
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(path.with_extension(format!("sqlite{suffix}")));
        }
    }

    #[test]
    fn account_record_cas_rejects_conflicts_and_identity_scoped_floor_rollback() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let first = AccountRecord::new(account_identity("member-a", 7, 7));
        store.commit_account(&first, None).unwrap();

        let next = first
            .next_identity(account_identity("member-a", 8, 8))
            .unwrap();
        assert!(store.commit_account(&next, None).is_err());
        store.commit_account(&next, Some(first.revision())).unwrap();

        assert!(next
            .next_identity(account_identity("member-a", 6, 6))
            .is_err());
        let replacement = next
            .next_identity(account_identity("member-b", 1, 1))
            .unwrap();
        store
            .commit_account(&replacement, Some(next.revision()))
            .unwrap();
        assert_eq!(
            replacement.retained_identities()[0].member_id().as_str(),
            "member-a"
        );
        let mut dropped = serde_json::to_value(&replacement).unwrap();
        dropped["revision"] = serde_json::json!(replacement.revision().get() + 1);
        dropped["retainedIdentities"] = serde_json::json!([]);
        let dropped: AccountRecord = serde_json::from_value(dropped).unwrap();
        assert!(store
            .commit_account(&dropped, Some(replacement.revision()))
            .is_err());
        let mut substituted = serde_json::to_value(&replacement).unwrap();
        substituted["revision"] = serde_json::json!(replacement.revision().get() + 1);
        let substituted_bytes = vec![99_u8; 8];
        substituted["retainedIdentities"][0]["blob"]["keystore"] =
            serde_json::json!(substituted_bytes);
        substituted["retainedIdentities"][0]["blob"]["blobHash"] =
            serde_json::json!(<[u8; 32]>::from(Sha256::digest([99_u8; 8])));
        let substituted: AccountRecord = serde_json::from_value(substituted).unwrap();
        assert!(store
            .commit_account(&substituted, Some(replacement.revision()))
            .is_err());
        assert_eq!(store.load_account().unwrap(), Some(replacement));
    }

    /// Golden-shape tripwire: if [`SCHEMA`] changes, this assertion breaks and forces the author to update it —
    /// AND, deliberately, to bump [`SCHEMA_VERSION`] in the same edit (the pair is asserted together). Compares
    /// the semantic column shape, not the literal `CREATE TABLE` text, so a pure reformat doesn't trip it.
    #[test]
    fn schema_shape_is_pinned_to_the_version() {
        let s = SqliteVaultStore::in_memory().unwrap();
        let conn = s.conn();
        let shape = store_schema::schema_shape(&conn).unwrap();
        assert_eq!(
            (SCHEMA_VERSION, shape.as_str()),
            (
                4,
                "account(singleton:INTEGER nn=0 pk=1, record:BLOB nn=1 pk=0)\n\
                 keyrings(tree_key:TEXT nn=0 pk=1, bytes:BLOB nn=1 pk=0)\n\
                 watermarks(tree_key:TEXT nn=0 pk=1, watermark:BLOB nn=1 pk=0)\n"
            ),
            "SCHEMA changed: update this golden AND bump SCHEMA_VERSION"
        );
    }
}
