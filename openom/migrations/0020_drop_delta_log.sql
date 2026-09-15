-- Drop the V2 delta-log schema. The change-history feature it was the substrate for now
-- lives on the blob data channel (retention-aware GC in `gc.rs`, history read API in
-- `blobs.rs`), and the V1 snapshot CAS path (`put_tree`/`get_tree`/`cas_*`) is gone — the
-- tree's encrypted state lives entirely in `tree_blob_index`. See OPE-448 / design.faas-server §1.

-- The append-only delta log (payload index + author attribution). Nothing FK-references it.
DROP TABLE IF EXISTS tree_log;

-- Per-tree delta-log sequence allocator — only the delta log consumed it.
ALTER TABLE trees DROP COLUMN IF EXISTS next_log_seq;

-- V1 snapshot CAS token (R2 ETag). The blob channel carries its own opaque version tokens;
-- no reader remains. The zeroed placeholder columns `create_tree` still writes (object_key,
-- aead, size_bytes, covers_through_seq) stay — they satisfy the NOT NULL schema.
ALTER TABLE trees DROP COLUMN IF EXISTS snapshot_version;
