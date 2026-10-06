-- The authenticated owner-tree index used to restore a selected tree when a device has no local cache.
-- The engine is learned from the first verified keyring update and is immutable thereafter.
ALTER TABLE trees ADD COLUMN keyring_engine TEXT;
ALTER TABLE trees ADD CONSTRAINT trees_keyring_engine_valid
    CHECK (keyring_engine IS NULL OR keyring_engine IN ('chain', 'dag'));

