//! Tree-row creation.
//!
//! A tree's encrypted state lives entirely on the blob data channel (`blobs.rs`);
//! this module mints the owning Postgres `trees` row. `POST /trees/{tree_id}` is the
//! ONE place a row is created: it is entitlement-gated on the owner's `max_trees`
//! and makes the caller owner. The server never decrypts — it only owns the row.

use axum::extract::{Path, State};
use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::auth::Identity;
use crate::AppState;

/// Per-object ceiling.
///
/// The Lambda proxy path tops out around 6 MB (§9.9); tree
/// snapshots are far smaller, but the limit is enforced so a client can't wedge the
/// proxy. Media (large) takes the presigned path instead, never this one.
pub const MAX_OBJECT_BYTES: usize = 6 * 1024 * 1024;

/// `POST /trees/{tree_id}` — explicitly create the tree row (OPE-407, decision 3-B), entitlement-gated on
/// the owner's `max_trees`; the caller becomes owner. This is the ONE place a `trees` row is minted for the
/// data-channel path — `put_blob` no longer mints (it `404`s on a missing tree). The row carries zeroed
/// placeholder columns (empty `object_key`, zeroed `aead` / `size_bytes` / `covers_through_seq`) purely to
/// satisfy the `trees` schema's NOT NULL constraints; nothing reads them — the tree's encrypted state lives
/// entirely on the blob data channel.
///
/// Idempotent for the owner: a re-provision / returning device that already minted this tree gets a `2xx`
/// (`200`), not an error — the client provisioning flow may call it more than once. A tree that already
/// exists under a DIFFERENT owner is refused (`403`), the standard "exists, not mine"
/// convention. Over `max_trees` → [`ApiError::QuotaExceeded`] (`403`, a countable product signal).
///
/// # Errors
/// Returns [`ApiError`] if the account is unknown or over its `max_trees`, or the tree exists under another
/// owner.
pub async fn create_tree(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("tree.create");
    let caller = identity.member_id;

    // OPE-408: rate-gate the create in its own committed per-account bucket BEFORE the entitlement tx, so even a
    // rejected attempt (over-quota / forbidden) consumes a token — POST /trees is otherwise the only write with
    // no backoff, a scriptable DB-load vector. 429s the caller when the bucket is empty.
    state.meter.charge_create(&state.db, caller).await?;

    // Serialize concurrent creates for this owner by locking the accounts row for the duration of the
    // check-and-insert. A bare `count(*) < max_trees` guard then INSERT races under READ COMMITTED: two
    // concurrent creates of DIFFERENT ids by the same owner each read the pre-insert count and both pass,
    // busting the entitlement. The row lock makes the gate atomic w.r.t. a sibling create (different owners
    // lock different rows, so they don't contend) — the same row-atomic discipline the blob byte meter uses.
    // Requires an explicit tx: an autocommit `FOR UPDATE` would release the lock immediately.
    let mut tx = state.db.begin().await.map_err(internal)?;
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(caller)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;

    // Entitlement-gated create-only insert (count < max_trees, ON CONFLICT DO NOTHING); the snapshot columns
    // are zeroed placeholders — a data-channel tree has no scalar snapshot.
    let res = sqlx::query(
        "INSERT INTO trees (id, owner_id, object_key, envelope_version, aead, size_bytes, covers_through_seq)
         SELECT $1, $2, '', 0, 0, 0, 0
         WHERE (SELECT count(*) FROM trees WHERE owner_id = $2)
             < (SELECT max_trees FROM accounts WHERE id = $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tree_id)
    .bind(caller)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if res.rows_affected() == 1 {
        tx.commit().await.map_err(internal)?;
        tracing::info!(event = "tree_created", %tree_id, owner = %caller);
        return Ok(StatusCode::CREATED.into_response());
    }

    // 0 rows: the tree already exists, or the entitlement/account gate blocked the insert. Disambiguate
    // inside the same locked tx.
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
    let outcome = match existing {
        // Already ours → idempotent success (a returning device / a re-provision).
        Some(o) if o == caller => Ok(StatusCode::OK.into_response()),
        // Exists under someone else → never hijack an existing tree.
        Some(_) => Err(ApiError::Forbidden),
        // Doesn't exist → the entitlement gate blocked the insert. Separate over-quota (a countable signal)
        // from an unknown account.
        None => {
            let limits: Option<(i64, i32)> = sqlx::query_as(
                "SELECT (SELECT count(*) FROM trees WHERE owner_id = $1), a.max_trees
                   FROM accounts a WHERE a.id = $1",
            )
            .bind(caller)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
            match limits {
                Some((count, max)) if count >= i64::from(max) => {
                    tracing::info!(event = "quota_rejected", resource = "trees", owner = %caller);
                    Err(ApiError::QuotaExceeded)
                }
                None => Err(ApiError::Forbidden), // unknown account
                Some(_) => Err(ApiError::Conflict), // guard passed yet insert lost — retry
            }
        }
    };
    tx.commit().await.map_err(internal)?;
    outcome
}

// A value->value error conversion used as a `.map_err(fn)` argument; `&` would force a closure per call.
#[allow(clippy::needless_pass_by_value)]
fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Handler error → HTTP status. Internal causes are logged, never leaked.
pub enum ApiError {
    Forbidden,
    NotFound,
    Conflict,
    QuotaExceeded,
    /// Append rate exceeded (abuse gate). Carries a Retry-After hint in seconds. A
    /// 429 — distinct from `QuotaExceeded`'s 403 — because it's transient: the client
    /// should back off and retry, not treat it as a plan limit (§17).
    TooManyRequests(u64),
    /// The requested log tail is no longer retained — the client must bootstrap from a snapshot.
    Gone(String),
    BadRequest(String),
    /// An RFC 9457-shaped error carrying a typed, machine-readable `code`
    /// (`plan/sync/design.http-error-model.md`). The GC / metering paths (OPE-409) need a discriminator
    /// beyond the coarse status — a below-floor write and a reaped read are both about the GC ratchet but
    /// differ by `(status, code)` (`409 below_gc_floor`, `410 below_gc_floor`, `409 covered_anomaly`, …).
    /// Rendered as `application/problem+json`; `code` is a stable `&'static str` from the closed registry
    /// (`error_codes.rs`). Every `ApiError` variant now renders through this same 9457 body.
    Coded {
        status: StatusCode,
        code: &'static str,
        detail: String,
        /// Optional RFC 9457 extension member rendered under `args` — a JSON object of typed interpolation
        /// values (e.g. `quota_exceeded`'s role-gated `{limit, used}`). `Null` for the common no-args case.
        args: serde_json::Value,
    },
    Internal(String),
}

impl ApiError {
    /// A `409 Conflict` with a typed `code` — the GC write-guards (below-floor log/snapshot writes, over-claim,
    /// monotonicity). See `plan/sync/design.http-error-model.md`.
    #[must_use]
    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Coded {
            status: StatusCode::CONFLICT,
            code,
            detail: detail.into(),
            args: serde_json::Value::Null,
        }
    }

    /// A `410 Gone` with a typed `code` — a reaped (GC-reclaimed) blob (`below_gc_floor`, action BOOTSTRAP).
    #[must_use]
    pub fn reaped(detail: impl Into<String>) -> Self {
        Self::Coded {
            status: StatusCode::GONE,
            code: crate::error_codes::BELOW_GC_FLOOR,
            detail: detail.into(),
            args: serde_json::Value::Null,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_codes as ec;
        // EVERY variant renders one uniform RFC 9457 `application/problem+json` body carrying a stable,
        // machine-readable `code` from the closed registry (`error_codes.rs`) — so an openom-free client
        // localizes on `code`, never the prose. `title`/`detail` are operator-controlled (never request
        // bytes or backend causes — zero-knowledge). A 429 additionally carries Retry-After. Internal causes
        // are logged, never sent. (QuotaExceeded stays a 403 — entitlement is an authorization decision,
        // not a payment handshake, §9.9 — but now also a machine code.)
        let null = serde_json::Value::Null;
        let (status, code, detail, retry_after, args): (StatusCode, &'static str, String, Option<u64>, serde_json::Value) =
            match self {
                Self::Forbidden => (StatusCode::FORBIDDEN, ec::ACCESS_DENIED, "forbidden".into(), None, null),
                Self::NotFound => (StatusCode::NOT_FOUND, ec::NOT_FOUND, "not found".into(), None, null),
                Self::Conflict => (
                    StatusCode::CONFLICT,
                    ec::VERSION_CONFLICT,
                    "version conflict — pull the current snapshot and retry".into(),
                    None,
                    null,
                ),
                Self::QuotaExceeded => (
                    StatusCode::FORBIDDEN,
                    ec::QUOTA_EXCEEDED,
                    "account resource limit reached".into(),
                    None,
                    null,
                ),
                Self::TooManyRequests(secs) => (
                    StatusCode::TOO_MANY_REQUESTS,
                    ec::RATE_LIMITED,
                    "append rate exceeded — retry after the indicated delay".into(),
                    Some(secs),
                    null,
                ),
                Self::Gone(m) => (StatusCode::GONE, ec::BELOW_GC_FLOOR, m, None, null),
                Self::BadRequest(m) => (StatusCode::BAD_REQUEST, ec::INVALID_REQUEST, m, None, null),
                Self::Coded { status, code, detail, args } => (status, code, detail, None, args),
                Self::Internal(m) => {
                    tracing::error!(error = %m, "tree handler internal error");
                    (StatusCode::INTERNAL_SERVER_ERROR, ec::UNAVAILABLE, "internal error".into(), None, null)
                }
            };
        // RFC 9457: `title` is the STABLE per-type summary (from the registry), `detail` the per-occurrence
        // explanation; `args` (a typed object) rides as an extension member only when present.
        let mut body = serde_json::json!({
            "type": format!("/errors/{code}"),
            "title": ec::title_for(code),
            "status": status.as_u16(),
            "code": code,
            "detail": detail,
        });
        if !args.is_null() {
            body["args"] = args;
        }
        let mut resp = (status, axum::Json(body)).into_response();
        resp.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(secs) = retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(RETRY_AFTER, v);
            }
        }
        resp
    }
}
