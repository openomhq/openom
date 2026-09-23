//! Account binding + the E2E keystore backup (OPE-545 / OPE-549).
//!
//! Three routes realize `design.durable-identity-auth.md` §5/§6:
//! - `POST /register` — the SOLE binder. Guarded by [`crate::auth::RawJwt`] (a verified token, but no
//!   `sub → member_id` mapping yet — the mapping is what this creates). It proves the caller controls the
//!   author private key behind `member_id` via a domain-tagged, length-framed Ed25519 proof-of-possession
//!   over a signed timestamp (no challenge/nonce endpoint — Lambda is stateless), checks the id is
//!   self-certifying (`member_id == derive_member_id(author_pubkey)`), and inserts `(auth_sub → member_id)`
//!   idempotently.
//! - `GET /me` — the caller's `member_id` + their stored E2E keystore backup + its generation (device restore),
//!   with a strong `ETag` for conditional backup writes.
//! - `PUT/GET /account/keystore` — store / fetch the E2E-wrapped keystore blob, enforcing both the monotonic
//!   generation floor and `If-Match` compare-and-swap.
//!
//! The server is zero-knowledge about the keystore: it stores and returns opaque ciphertext.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::header::{ETAG, IF_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use openom_keyring_api::derive_member_id;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api_error::ApiError;
use crate::auth::{Identity, RawJwt};
use crate::error_codes as ec;
use crate::AppState;

/// The replay window for the signed timestamp: ±5 minutes. Wide enough for clock skew + a slow request,
/// narrow enough that a captured proof is useless minutes later. There is no nonce (stateless Lambda), and a
/// replayed *successful* bind is an idempotent no-op anyway — the window only bounds a bind to a NEW
/// (unregistered) `member_id`, which a replay can't create because the id is self-certifying.
const REGISTER_TS_WINDOW_SECS: u64 = 300;

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

fn invalid_json(rejection: &JsonRejection) -> ApiError {
    ApiError::coded(
        rejection.status(),
        ec::INVALID_REQUEST,
        "invalid JSON request",
    )
}

// A value-to-value conversion used as a `.map_err(fn)` argument.
#[allow(clippy::needless_pass_by_value)]
fn internal(error: sqlx::Error) -> ApiError {
    ApiError::Internal(error.to_string())
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}
fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn account_etag(keystore: Option<&[u8]>, generation: i64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"openom:account-backup:v1");
    digest.update(generation.to_be_bytes());
    match keystore {
        Some(bytes) => {
            digest.update([1]);
            digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(bytes);
        }
        None => digest.update([0]),
    }
    let hex = digest
        .finalize()
        .iter()
        .fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        });
    format!("\"{hex}\"")
}

fn json_with_etag(body: serde_json::Value, etag: &str) -> Response {
    let mut response = Json(body).into_response();
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(ETAG, value);
    }
    response
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
/// is already bound differently), `500 unavailable`. Every failure uses the shared RFC 9457 problem-details
/// contract and a code from [`crate::error_codes`].
pub async fn register(
    State(state): State<AppState>,
    raw: RawJwt,
    body: Result<Json<RegisterBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|rejection| invalid_json(&rejection))?;
    // (1) decode + length-check the key material.
    let Some(pubkey) = b64_decode(&body.author_pubkey).filter(|b| b.len() == 32) else {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "registration key is not valid base64 Ed25519 material",
        ));
    };
    let Some(sig_bytes) = b64_decode(&body.signature).filter(|b| b.len() == 64) else {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "registration signature is not valid base64 Ed25519 material",
        ));
    };

    // (2) replay window — a captured PoP is useless outside ±5 min.
    let server_time = now_unix();
    if server_time.abs_diff(body.ts) > REGISTER_TS_WINDOW_SECS {
        return Err(ApiError::coded_with_args(
            StatusCode::UNAUTHORIZED,
            ec::STALE_TIMESTAMP,
            "registration timestamp is outside the accepted window",
            json!({ "server_time": u64::try_from(server_time).unwrap_or_default() }),
        ));
    }

    // (3) self-certifying: the id MUST be the hash of the presented key, so a squatter can't bind an id they
    // don't hold the key for (and can't diverge the two).
    let derived = derive_member_id(&pubkey);
    if Uuid::parse_str(&derived) != Ok(body.member_id) {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::MEMBER_ID_MISMATCH,
            "member id does not derive from the supplied author key",
        ));
    }

    // (4) proof-of-possession: the author key signed THIS (iss, sub, member_id, ts) — domain-tagged + framed.
    // Fixed-size conversions (never panic — lengths were checked above; expressed fallibly so no `expect`).
    let (Ok(pubkey_arr), Ok(sig_arr)) = (
        <[u8; 32]>::try_from(pubkey.as_slice()),
        <[u8; 64]>::try_from(sig_bytes.as_slice()),
    ) else {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "registration key material has an invalid length",
        ));
    };
    let Ok(vk) = edsign::VerifyingKey::from_bytes(&pubkey_arr) else {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "registration key is not a valid Ed25519 point",
        ));
    };
    let msg = register_signing_bytes(
        raw.iss.as_deref().unwrap_or(""),
        &raw.sub,
        body.member_id,
        body.ts,
    );
    if vk
        .verify(&msg, &edsign::Signature::from_bytes(&sig_arr))
        .is_err()
    {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            ec::BAD_SIGNATURE,
            "registration proof signature is invalid",
        ));
    }

    // (5) insert-then-reread. The speculative free-tier `accounts` row is rolled back if the `identities`
    // bind doesn't take (a conflict), so a losing register leaves no orphan account.
    match bind_identity(&state, &raw.sub, body.member_id, &pubkey).await {
        Ok(BindOutcome::Bound | BindOutcome::Idempotent) => {
            // Positive-cache the immutable mapping so the caller's very next request skips the DB.
            state
                .identity_cache
                .write()
                .await
                .insert(raw.sub.clone(), body.member_id);
            tracing::info!(event = "identity_registered", sub = %raw.sub, member = %body.member_id);
            Ok((StatusCode::OK, Json(json!({ "member_id": body.member_id }))).into_response())
        }
        Ok(BindOutcome::Conflict) => {
            tracing::info!(event = "identity_conflict", sub = %raw.sub, member = %body.member_id);
            Err(ApiError::conflict(
                ec::IDENTITY_CONFLICT,
                "subject or member id is already bound differently",
            ))
        }
        Err(error) => Err(ApiError::Internal(error.to_string())),
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

/// `GET /me` — the caller's `member_id`, their stored E2E keystore backup (if any), its generation, and a
/// strong `ETag` for conditional backup writes.
///
/// # Errors
/// `403 unregistered` (no `identities` row), `500 unavailable` on a DB failure.
pub async fn me(State(state): State<AppState>, id: Identity) -> Result<Response, ApiError> {
    let row: Option<(Option<Vec<u8>>, i64)> =
        sqlx::query_as("SELECT keystore, generation FROM identities WHERE member_id = $1")
            .bind(id.member_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    let Some((keystore, generation)) = row else {
        return Err(ApiError::forbidden(
            ec::UNREGISTERED,
            "account identity is not registered",
        ));
    };
    let etag = account_etag(keystore.as_deref(), generation);
    Ok(json_with_etag(
        json!({
            "member_id": id.member_id,
            "keystore": keystore.as_deref().map(b64_encode),
            "generation": generation,
        }),
        &etag,
    ))
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

/// `PUT /account/keystore` — store the E2E keystore backup, enforcing generation and `If-Match` floors.
///
/// A PUT whose `generation` is below the stored one is a rollback and is refused (`409`) — the load-bearing
/// anti-rollback the review flagged (a party who unwrapped an old keystore can't push the stale blob back to
/// re-arm a revoked recovery code). A changed write must also match the current strong `ETag`; an exact replay
/// succeeds even with a stale tag so a lost success response can be retried safely.
///
/// # Errors
/// `400 invalid_request`, `403 unregistered` (no `identities` row — dev auth, or a `member_id` that never
/// registered a backup target), `409 generation_rollback`, `412 account_backup_precondition_failed`,
/// `500 unavailable`.
pub async fn put_keystore(
    State(state): State<AppState>,
    id: Identity,
    headers: HeaderMap,
    body: Result<Json<KeystoreBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|rejection| invalid_json(&rejection))?;
    let Some(blob) = b64_decode(&body.keystore) else {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "keystore is not valid base64",
        ));
    };
    if body.generation < 0 {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            ec::INVALID_REQUEST,
            "keystore generation must be non-negative",
        ));
    }
    let if_match = headers
        .get(IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::coded(
                StatusCode::BAD_REQUEST,
                ec::INVALID_REQUEST,
                "If-Match is required",
            )
        })?;

    let mut tx = state.db.begin().await.map_err(internal)?;
    let stored: Option<(Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT keystore, generation FROM identities WHERE member_id = $1 FOR UPDATE",
    )
    .bind(id.member_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some((stored_blob, stored_generation)) = stored else {
        return Err(ApiError::forbidden(
            ec::UNREGISTERED,
            "account identity is not registered",
        ));
    };
    if body.generation < stored_generation {
        return Err(ApiError::conflict(
            ec::GENERATION_ROLLBACK,
            "keystore generation is below the server floor",
        ));
    }

    let current_etag = account_etag(stored_blob.as_deref(), stored_generation);
    if stored_generation == body.generation && stored_blob.as_deref() == Some(blob.as_slice()) {
        return Ok(json_with_etag(
            json!({ "generation": stored_generation }),
            &current_etag,
        ));
    }
    if if_match != current_etag {
        return Err(ApiError::coded(
            StatusCode::PRECONDITION_FAILED,
            ec::ACCOUNT_BACKUP_PRECONDITION_FAILED,
            "account backup changed since it was read",
        ));
    }

    sqlx::query(
        "UPDATE identities SET keystore = $1, generation = $2, updated_at = now()
         WHERE member_id = $3",
    )
    .bind(&blob)
    .bind(body.generation)
    .bind(id.member_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    let new_etag = account_etag(Some(&blob), body.generation);
    Ok(json_with_etag(
        json!({ "generation": body.generation }),
        &new_etag,
    ))
}

/// `GET /account/keystore` — the stored E2E keystore backup + its generation and strong `ETag`.
///
/// # Errors
/// `403 unregistered` (no `identities` row), `500 unavailable`.
pub async fn get_keystore(
    State(state): State<AppState>,
    id: Identity,
) -> Result<Response, ApiError> {
    let row: Option<(Option<Vec<u8>>, i64)> =
        sqlx::query_as("SELECT keystore, generation FROM identities WHERE member_id = $1")
            .bind(id.member_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    match row {
        Some((keystore, generation)) => {
            let etag = account_etag(keystore.as_deref(), generation);
            Ok(json_with_etag(
                json!({
                    "keystore": keystore.as_deref().map(b64_encode),
                    "generation": generation,
                }),
                &etag,
            ))
        }
        None => Err(ApiError::forbidden(
            ec::UNREGISTERED,
            "account identity is not registered",
        )),
    }
}
