-- OPE-545: reverse `member_id == auth_sub`. Supabase (and any OIDC issuer) becomes a PURE JWT issuer;
-- the server maps the token subject (`auth_sub`) onto the client's self-certifying, key-derived
-- `member_id` = uuid8(SHA-256(author_pubkey)). See plan/accounts-auth/design.durable-identity-auth.md §5/§6.
--
-- The row is written ONCE, at `POST /register` (the sole binder), and treated as immutable
-- (`auth_sub → member_id` never changes) — the server only ever positive-caches it. `member_id UNIQUE`
-- is the squat gate at the DB layer: a second `auth_sub` binding an already-claimed `member_id` is a
-- unique violation, surfaced as a 409. `author_pubkey` lets the binding be re-verified against the
-- self-certifying id. `keystore` is the E2E-wrapped account-keystore backup (§6) — ciphertext the
-- server never opens — and `generation` is the monotonic anti-rollback floor (OPE-549): a keystore
-- PUT whose generation is below the stored one is refused.
CREATE TABLE identities (
    auth_sub      TEXT        PRIMARY KEY,                       -- the JWT `sub` (Supabase user id / OIDC subject)
    member_id     UUID        NOT NULL UNIQUE REFERENCES accounts(id),
    author_pubkey BYTEA       NOT NULL,                          -- Ed25519 identity pubkey `member_id` derives from
    keystore      BYTEA,                                         -- E2E-wrapped account-keystore backup (server-opaque)
    generation    BIGINT      NOT NULL DEFAULT 0,                -- monotonic keystore anti-rollback floor
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
