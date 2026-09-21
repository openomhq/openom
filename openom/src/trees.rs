//! Tree-row creation.
//!
//! A tree's encrypted state lives entirely on the blob data channel (`blobs.rs`);
//! this module mints the owning Postgres `trees` row. `POST /trees/{tree_id}` is the
//! ONE place a row is created: it is entitlement-gated on the owner's `max_trees`
//! and makes the caller owner. The server never decrypts — it only owns the row.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::api_error::ApiError;
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
