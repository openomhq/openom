-- Retention-tier-aware GC: the per-plan change-history depth.
--
-- The blob data channel compacts + GCs old raw delta objects (`log/{replica}/{counter}`) below the covered
-- frontier — fine for SYNC, but it destroys the per-change history the paid *change-history / review-changes*
-- feature reads. Compaction (the signed snapshot checkpoint) and reaping (deletion) are already separate steps:
-- `compact()` marks coverage, `run_log_gc` reaps. This column gates the REAP so raw deltas inside the owner's
-- plan history window survive even below the covered floor; they are still counted by the existing tree-byte
-- meter (credited back only when finally reaped), so deeper history is a real paid capacity.
--
-- Owner-pays: keyed on the tree owner's account. Default 0 = no retention = the current reap-everything-below-
-- the-floor behavior (free tier); a paid tier sets a deeper window (e.g. 30 / 90 / 365 days).
ALTER TABLE accounts
    ADD COLUMN retained_history_days INTEGER NOT NULL DEFAULT 0; -- days of raw-delta history retained past compaction
