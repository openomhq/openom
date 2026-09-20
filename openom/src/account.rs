//! Account binding + the E2E keystore backup (OPE-545 / OPE-549).
//!
//! Three routes realize `design.durable-identity-auth.md` §5/§6:
//! - `POST /register` — the SOLE binder. Guarded by [`crate::auth::RawJwt`] (a verified token, but no
//!   `sub → member_id` mapping yet — the mapping is what this creates). It proves the caller controls the
//!   author private key behind `member_id` via a domain-tagged, length-framed Ed25519 proof-of-possession
//!   over a signed timestamp (no challenge/nonce endpoint — Lambda is stateless), checks the id is
//!   self-certifying (`member_id == derive_member_id(author_pubkey)`), and inserts `(auth_sub → member_id)`
//!   idempotently.
//! - `GET /me` — the caller's `member_id` + their stored E2E keystore backup + its generation (device restore).
//! - `PUT/GET /account/keystore` — store / fetch the E2E-wrapped keystore blob, enforcing the monotonic
//!   generation floor (a rollback PUT is refused — the load-bearing anti-rollback for the durable identity).
//!
//! The server is zero-knowledge about the keystore: it stores and returns opaque ciphertext.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use openom_keyring_api::derive_member_id;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{Identity, RawJwt};
use crate::AppState;

/// The domain tag every `/register` proof-of-possession is prefixed with. A FROZEN constant: the client's
/// signer must prepend exactly these bytes, so the author key's signature can never be confused with a
/// keyring/attribution signature under the same key (cross-protocol separation). Never a bare concat.
/// The replay window for the signed timestamp: ±5 minutes. Wide enough for clock skew + a slow request,
/// narrow enough that a captured proof is useless minutes later. There is no nonce (stateless Lambda), and a
/// replayed *successful* bind is an idempotent no-op anyway — the window only bounds a bind to a NEW
/// (unregistered) `member_id`, which a replay can't create because the id is self-certifying.
const REGISTER_TS_WINDOW_SECS: i64 = 300;

/// The exact bytes the client's author key signs for `POST /register` — the single source of truth shared by
/// the server (verify) and any client/JS signer (produce). **Domain-tagged + length-framed**, never a bare
/// concat:
///
/// ```text
/// "openom:register:v1"
///   ‖ u32_be(len(iss))  ‖ iss_bytes      // the token's `iss` claim, or "" when absent
///   ‖ u32_be(len(sub))  ‖ sub_bytes      // the token's `sub` claim, verbatim
///   ‖ member_id_bytes                    // the 16 raw bytes of the member_id UUID
///   ‖ i64_be(ts)                         // unix seconds
/// ```
///
/// `iss`/`sub` are length-framed (variable length) so no boundary is ambiguous; `member_id` (fixed 16) and
/// `ts` (fixed 8) need no frame. `iss`/`sub` are bound VERBATIM — the client reads them straight out of its
/// own JWT and the server reconstructs them from the SAME authenticated claims, so there is no normalization
/// to drift on (this is why the layout keeps them raw rather than lowercased).
#[must_use]
pub fn register_signing_bytes(iss: &str, sub: &str, member_id: Uuid, ts: i64) -> Vec<u8> {
    openom_crypto::aad::registration_signing_bytes(iss, sub, *member_id.as_bytes(), ts)
}

/// Current unix time in seconds (for the replay window). Monotonicity isn't needed — the window is symmetric.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A `{ "error": "<code>" }` body at `status`. The register/keystore codes are server-local (they are not in
/// the generated client error registry yet — that is the T3 client-seam follow-up); the wire is a plain JSON
/// object so a client can branch on the code without RFC-9457 machinery.
fn err(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}
fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `POST /register` body: the self-certifying `member_id`, the Ed25519 author public key + the
/// proof-of-possession signature (both base64-standard), and the signed unix timestamp.
#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    pub member_id: Uuid,
    /// base64(Ed25519 author public key, 32 bytes).
    pub author_pubkey: String,
    /// base64(Ed25519 signature over [`register_signing_bytes`], 64 bytes).
    pub signature: String,
    /// Unix seconds; must be within ±5 min of the server clock.
    pub ts: i64,
}

/// `POST /register` — bind `auth_sub → member_id` (the sole binder). See the module docs for the full flow.
///
/// # Errors
/// `400 invalid_request` (bad body / key / signature length), `401 stale_timestamp`, `400 member_id_mismatch`
/// (id not self-certifying), `401 bad_signature`, `409 identity_conflict` (this `sub` — or this `member_id` —
/// is already bound differently), `500 internal`.
pub async fn register(
    State(state): State<AppState>,
    raw: RawJwt,
    Json(body): Json<RegisterBody>,
) -> Response {
    // (1) decode + length-check the key material.
    let Some(pubkey) = b64_decode(&body.author_pubkey).filter(|b| b.len() == 32) else {
        return err(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(sig_bytes) = b64_decode(&body.signature).filter(|b| b.len() == 64) else {
        return err(StatusCode::BAD_REQUEST, "invalid_request");
    };

    // (2) replay window — a captured PoP is useless outside ±5 min.
    if (now_unix() - body.ts).abs() > REGISTER_TS_WINDOW_SECS {
        return err(StatusCode::UNAUTHORIZED, "stale_timestamp");
    }

    // (3) self-certifying: the id MUST be the hash of the presented key, so a squatter can't bind an id they
    // don't hold the key for (and can't diverge the two).
    let derived = derive_member_id(&pubkey);
    if Uuid::parse_str(&derived) != Ok(body.member_id) {
        return err(StatusCode::BAD_REQUEST, "member_id_mismatch");
    }

    // (4) proof-of-possession: the author key signed THIS (iss, sub, member_id, ts) — domain-tagged + framed.
    // Fixed-size conversions (never panic — lengths were checked above; expressed fallibly so no `expect`).
    let (Ok(pubkey_arr), Ok(sig_arr)) = (
        <[u8; 32]>::try_from(pubkey.as_slice()),
        <[u8; 64]>::try_from(sig_bytes.as_slice()),
    ) else {
        return err(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(vk) = edsign::VerifyingKey::from_bytes(&pubkey_arr) else {
        return err(StatusCode::BAD_REQUEST, "invalid_request"); // not a valid curve point
    };
    let msg = register_signing_bytes(raw.iss.as_deref().unwrap_or(""), &raw.sub, body.member_id, body.ts);
    if vk.verify(&msg, &edsign::Signature::from_bytes(&sig_arr)).is_err() {
        return err(StatusCode::UNAUTHORIZED, "bad_signature");
    }

    // (5) insert-then-reread. The speculative free-tier `accounts` row is rolled back if the `identities`
    // bind doesn't take (a conflict), so a losing register leaves no orphan account.
    match bind_identity(&state, &raw.sub, body.member_id, &pubkey).await {
        Ok(BindOutcome::Bound | BindOutcome::Idempotent) => {
            // Positive-cache the immutable mapping so the caller's very next request skips the DB.
            state.identity_cache.write().await.insert(raw.sub.clone(), body.member_id);
            tracing::info!(event = "identity_registered", sub = %raw.sub, member = %body.member_id);
            (StatusCode::OK, Json(json!({ "member_id": body.member_id }))).into_response()
        }
        Ok(BindOutcome::Conflict) => {
            tracing::info!(event = "identity_conflict", sub = %raw.sub, member = %body.member_id);
            err(StatusCode::CONFLICT, "identity_conflict")
        }
        Err(e) => {
            tracing::warn!(%e, "register bind failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

/// The classification of an insert-then-reread bind.
enum BindOutcome {
    /// A fresh `(auth_sub → member_id)` row was created.
    Bound,
    /// The exact same `(sub, member_id, author_pubkey)` was already present — an idempotent re-register.
    Idempotent,
    /// This `sub` is bound to a different `member_id`, or this `member_id` is claimed by another `sub`.
    Conflict,
}

/// Insert `accounts` (free-tier) + `identities` in one txn; classify the result by re-reading the `sub` row.
async fn bind_identity(
    state: &AppState,
    sub: &str,
    member_id: Uuid,
    pubkey: &[u8],
) -> Result<BindOutcome, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    // Free-tier account (all columns default). Speculative — rolled back below if the identity bind loses.
    sqlx::query("INSERT INTO accounts (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
        .bind(member_id)
        .execute(&mut *tx)
        .await?;
    let inserted = sqlx::query(
        "INSERT INTO identities (auth_sub, member_id, author_pubkey, generation)
         VALUES ($1, $2, $3, 0) ON CONFLICT DO NOTHING",
    )
    .bind(sub)
    .bind(member_id)
    .bind(pubkey)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 1 {
        tx.commit().await?;
        return Ok(BindOutcome::Bound);
    }

    // A conflict on either unique key (auth_sub PK or member_id UNIQUE) → nothing bound. Undo the speculative
    // account insert, then re-read the sub's row to tell an idempotent re-register from a real conflict.
    tx.rollback().await?;
    let existing: Option<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT member_id, author_pubkey FROM identities WHERE auth_sub = $1")
            .bind(sub)
            .fetch_optional(&state.db)
            .await?;
    Ok(match existing {
        Some((mid, pk)) if mid == member_id && pk == pubkey => BindOutcome::Idempotent,
        _ => BindOutcome::Conflict,
    })
}

/// `GET /me` — the caller's `member_id`, their stored E2E keystore backup (if any), and its generation.
///
/// # Errors
/// `500 internal` on a DB failure.
pub async fn me(State(state): State<AppState>, id: Identity) -> Response {
    let row: Option<(Option<Vec<u8>>, i64)> =
        match sqlx::query_as("SELECT keystore, generation FROM identities WHERE member_id = $1")
            .bind(id.member_id)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%e, "GET /me read failed");
                return err(StatusCode::INTERNAL_SERVER_ERROR, "internal");
            }
        };
    // A dev-auth caller (or a jwt caller resolved via a mapping but with no backup yet) has no keystore row:
    // report member_id with a null backup + generation 0.
    let (keystore, generation) = row.unwrap_or((None, 0));
    Json(json!({
        "member_id": id.member_id,
        "keystore": keystore.as_deref().map(b64_encode),
        "generation": generation,
    }))
    .into_response()
}

/// `PUT /account/keystore` body: the E2E-wrapped keystore blob (base64) + its monotonic generation.
#[derive(Debug, Deserialize)]
pub struct KeystoreBody {
    /// base64(the E2E-wrapped account keystore — server-opaque ciphertext).
    pub keystore: String,
    /// The keystore's monotonic generation (the client's anti-rollback floor). A PUT below the stored
    /// generation is refused.
    pub generation: i64,
}

/// `PUT /account/keystore` — store the E2E keystore backup, enforcing the generation floor.
///
/// A PUT whose `generation` is below the stored one is a rollback and is refused (`409`) — the load-bearing
/// anti-rollback the review flagged (a party who unwrapped an old keystore can't push the stale blob back to
/// re-arm a revoked recovery code). Equal generation is allowed (an idempotent re-PUT / a same-gen re-wrap
/// such as change-passphrase).
///
/// # Errors
/// `400 invalid_request`, `403 unregistered` (no `identities` row — dev auth, or a `member_id` that never
/// registered a backup target), `409 generation_rollback`, `500 internal`.
pub async fn put_keystore(
    State(state): State<AppState>,
    id: Identity,
    Json(body): Json<KeystoreBody>,
) -> Response {
    let Some(blob) = b64_decode(&body.keystore) else {
        return err(StatusCode::BAD_REQUEST, "invalid_request");
    };
    // Conditional on the floor: only advance when the incoming generation is >= the stored one.
    let updated = match sqlx::query(
        "UPDATE identities SET keystore = $1, generation = $2, updated_at = now()
         WHERE member_id = $3 AND generation <= $2",
    )
    .bind(&blob)
    .bind(body.generation)
    .bind(id.member_id)
    .execute(&state.db)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!(%e, "keystore PUT failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    };
    if updated == 1 {
        return Json(json!({ "generation": body.generation })).into_response();
    }
    // 0 rows: either no identities row (unregistered) or the floor rejected a rollback. Disambiguate.
    let stored: Option<i64> = sqlx::query_scalar("SELECT generation FROM identities WHERE member_id = $1")
        .bind(id.member_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    match stored {
        Some(_) => err(StatusCode::CONFLICT, "generation_rollback"),
        None => err(StatusCode::FORBIDDEN, "unregistered"),
    }
}

/// `GET /account/keystore` — the stored E2E keystore backup + its generation.
///
/// # Errors
/// `403 unregistered` (no `identities` row), `500 internal`.
pub async fn get_keystore(State(state): State<AppState>, id: Identity) -> Response {
    let row: Option<(Option<Vec<u8>>, i64)> =
        match sqlx::query_as("SELECT keystore, generation FROM identities WHERE member_id = $1")
            .bind(id.member_id)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%e, "keystore GET failed");
                return err(StatusCode::INTERNAL_SERVER_ERROR, "internal");
            }
        };
    match row {
        Some((keystore, generation)) => Json(json!({
            "keystore": keystore.as_deref().map(b64_encode),
            "generation": generation,
        }))
        .into_response(),
        None => err(StatusCode::FORBIDDEN, "unregistered"),
    }
}
