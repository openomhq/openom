-- Record the authenticated uploader on each blob-index row, for the change-history feed.
--
-- A per-replica `log/{replica}/{counter}` object is PUT by that replica's own device, so the authenticated
-- caller IS the delta's author. Recording it lets `GET /trees/{id}/history` render "who changed what, when"
-- from metadata alone — zero-knowledge holds (the server sees author/size/time, never the sealed content).
-- Nullable: rows written before this migration carry NULL (unknown author); new writes populate it.
ALTER TABLE tree_blob_index
    ADD COLUMN member_id UUID; -- the authenticated uploader (the delta's author, for a log/ object)
