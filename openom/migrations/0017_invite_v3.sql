-- Invite model v3 (plan/sharing/design.invite-model-v3.md): the short link carries only `invite_id` + `s`; the
-- rest of the invite's trust anchor moves server-side, AUTHENTICATED by a MAC under s_mac the server can't forge.
--
--  * engine   — 'chain' | 'dag'; bound in meta_mac, so the server can't relabel it.
--  * pin      — the OPAQUE engine-specific trust anchor (chain: rev(u32 BE)||kh(32); dag: the dagAnchorPin bytes).
--  * meta_mac — HMAC(s_mac_meta, framed(invite_id || uuid || role || engine || pin)); the owner sets it at mint.
--
-- The server never holds s / s_mac, so it can serve the real (pin, meta_mac) or fail the joiner's verify, never
-- forge. These are additive columns (pre-release; the 0012 columns are days old). NULLable so an in-flight v2
-- row (none exist pre-release) doesn't block the migration; v3 always writes them.
ALTER TABLE pending_invites ADD COLUMN engine   TEXT;
ALTER TABLE pending_invites ADD COLUMN pin      BYTEA;
ALTER TABLE pending_invites ADD COLUMN meta_mac BYTEA;

-- The invite lifecycle now has a third state: 'open' -> 'claimed' -> 'admitted'. Admit no longer DELETEs the row
-- (the joiner still needs GET /meta to COMPLETE the join, which happens after admit) — it marks it admitted, and
-- a scheduled sweep GCs expired/consumed rows. `status` is free TEXT, so this needs no type change; documented
-- here for the record. A row is joinable while status IN ('open','claimed','admitted') and unexpired.

-- Per-tree invite mint policy: who may CREATE an invite. 'signer' (default) = owner/co-owner only (they can also
-- admit — no unfulfillable invites); 'maintainer' = Maintainer+ may mint, a signer still admits. Admit is always
-- signer-only regardless. Set at tree creation / owner settings; defaults to the stricter 'signer'.
ALTER TABLE trees ADD COLUMN invite_mint_policy TEXT NOT NULL DEFAULT 'signer';
