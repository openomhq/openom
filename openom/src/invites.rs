//! Mode A share invites — the pending-invite transport for the two-channel invite protocol
//! (plan/sharing/design.mode-a-client-flow.md §2/§7).
//!
//! Authentication rides the invite LINK, a second channel the server never sees: the server stores only
//! an OPEN invite the owner minted and the invitee's MAC'd public-key claim, and the REAL membership
//! change is the client's signed keyring PUT (admitted by the `ChainVerifier`). So this layer is advisory
//! transport + spam control, NEVER the security boundary — a malicious server can drop or fabricate a
//! row but can't forge the MAC (it lacks the link secret `s`) or the owner's keyring signature.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::{authorize, Access};
use crate::trees::ApiError;
use crate::AppState;
use openom_roles::{ROLE_CO_OWNER, ROLE_EDITOR, ROLE_MAINTAINER, ROLE_OWNER, ROLE_VIEWER};

// Invite v3 caps (design.invite-model-v3.md §6a/§8): bound the abuse surface the shorter link + GET /meta open up.
const MAX_INVITE_TTL_MS: i64 = 90 * 24 * 3600 * 1000; // an invite lives at most 90 days; clamp a caller's expiry
const MAX_OPEN_INVITES_PER_TREE: i64 = 50; // a hostile/buggy client can't flood the invites table

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// The client's role STRING → the numeric role rank (power-descending, owner=1). The server otherwise treats role
// as an opaque string; it needs the rank ONLY to stop a minter granting a role stronger than its own.
fn role_rank(role: &str) -> Option<i16> {
    match role {
        "owner" => Some(ROLE_OWNER),
        "co-owner" => Some(ROLE_CO_OWNER),
        "maintainer" => Some(ROLE_MAINTAINER),
        "editor" => Some(ROLE_EDITOR),
        "viewer" => Some(ROLE_VIEWER),
        _ => None,
    }
}

/// The caller's role rank for a tree (owner fast-path = strongest), or `None` if not a member.
async fn caller_rank(db: &sqlx::PgPool, tree_id: Uuid, owner: Uuid, caller: Uuid) -> Result<Option<i16>, ApiError> {
    if caller == owner {
        return Ok(Some(ROLE_OWNER));
    }
    sqlx::query_scalar("SELECT role FROM tree_access WHERE tree_id = $1 AND member_id = $2")
        .bind(tree_id)
        .bind(caller)
        .fetch_optional(db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ApiError::BadRequest("invalid base64".into()))
}

async fn tree_owner(db: &sqlx::PgPool, tree_id: Uuid) -> Result<Uuid, ApiError> {
    sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct CreateInvite {
    invite_id: String, // base64url of 16 CSPRNG bytes
    role: String,
    engine: String,    // 'chain' | 'dag'
    pin: String,       // base64 (STANDARD) — the opaque engine-specific trust anchor
    meta_mac: String,  // base64 (STANDARD) — HMAC(s_mac_meta, framed(invite_id||uuid||role||engine||pin))
    #[serde(default)]
    recipient_pin: Option<String>,
    expiry: i64,
}

fn unb64url(s: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ApiError::BadRequest("invalid base64url".into()))
}

/// `POST /trees/{tree_id}/invites` — mint a pending invite (invite model v3). Authority is the tree's
/// `invite_mint_policy`: 'signer' (default) = owner/co-owner only; 'maintainer' = Maintainer+. Admit is always
/// signer-only, so 'signer' avoids minting invites nobody can admit. A minter may not grant a role stronger than
/// its own. The server holds no secret (`s`/`s_mac` never reach it); `pin`/`meta_mac` are opaque, client-
/// authenticated bytes. Hardened per §6a/§8: `invite_id` must be 16 bytes, `expiry` is clamped, open invites are
/// capped per tree.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized, the fields are invalid, or the store access fails.
pub async fn create_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    Json(body): Json<CreateInvite>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = tree_owner(&state.db, tree_id).await?;

    // Field validation up front (fail closed before any authority query).
    if unb64url(&body.invite_id)?.len() != 16 {
        return Err(ApiError::BadRequest("invite_id must be 16 bytes (base64url)".into()));
    }
    if body.engine != "chain" && body.engine != "dag" {
        return Err(ApiError::BadRequest("engine must be 'chain' or 'dag'".into()));
    }
    let minted_rank = role_rank(&body.role).ok_or_else(|| ApiError::BadRequest("unknown role".into()))?;
    let pin = unb64(&body.pin)?;
    let meta_mac = unb64(&body.meta_mac)?;
    if pin.is_empty() || pin.len() > 4096 || meta_mac.len() != 32 {
        return Err(ApiError::BadRequest("invalid pin/meta_mac".into()));
    }

    // Authority: per-tree mint policy, plus the "can't grant above yourself" rule.
    let policy: String = sqlx::query_scalar("SELECT invite_mint_policy FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;
    if policy == "maintainer" {
        authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    }
    // A signer check (owner/co-owner) covers BOTH the 'signer' policy and the role-ceiling rule below.
    let rank = caller_rank(&state.db, tree_id, owner, identity.member_id)
        .await?
        .ok_or(ApiError::Forbidden)?;
    if policy != "maintainer" && rank > ROLE_CO_OWNER {
        return Err(ApiError::Forbidden); // 'signer' policy: only owner/co-owner may mint
    }
    if minted_rank < rank {
        return Err(ApiError::Forbidden); // may not mint a role stronger than your own
    }

    // Clamp the expiry to a bounded TTL so a caller can't mint an effectively immortal invite.
    let expiry = body.expiry.min(now_ms() + MAX_INVITE_TTL_MS);

    // Cap the open invites per tree (DB-bloat / enumeration surface).
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pending_invites WHERE tree_id = $1 AND status = 'open'",
    )
    .bind(tree_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    if open >= MAX_OPEN_INVITES_PER_TREE {
        return Err(ApiError::BadRequest("too many open invites for this tree".into()));
    }

    sqlx::query(
        "INSERT INTO pending_invites
             (invite_id, tree_id, owner_member_id, role, engine, pin, meta_mac, recipient_pin, expiry)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&body.invite_id)
    .bind(tree_id)
    .bind(identity.member_id)
    .bind(&body.role)
    .bind(&body.engine)
    .bind(&pin)
    .bind(&meta_mac)
    .bind(&body.recipient_pin)
    .bind(expiry)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({ "invite_id": body.invite_id })))
}

#[derive(Serialize)]
pub struct InviteMeta {
    uuid: String,
    role: String,
    engine: String,
    pin: String,      // base64 (STANDARD)
    meta_mac: String, // base64 (STANDARD)
    expiry: i64,
    status: String,
}

/// `GET /invites/{invite_id}/meta` — the invitee (signed in) fetches the invite's authenticated metadata to
/// verify `meta_mac` with `s_mac_meta` (from the link's `s`) and then join. All trust rides that MAC, not this
/// endpoint. Returns an identical `404` for a missing OR expired/consumed invite (no existence oracle).
///
/// # Errors
/// Returns [`ApiError::NotFound`] if the invite is missing/expired, or [`ApiError`] on a store error.
pub async fn get_invite_meta(
    State(state): State<AppState>,
    _identity: Identity,
    Path(invite_id): Path<String>,
) -> Result<Json<InviteMeta>, ApiError> {
    type Row = (Uuid, String, Option<String>, Option<Vec<u8>>, Option<Vec<u8>>, i64, String);
    let row: Option<Row> = sqlx::query_as(
        "SELECT tree_id, role, engine, pin, meta_mac, expiry, status FROM pending_invites WHERE invite_id = $1",
    )
    .bind(&invite_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    let (tree_id, role, engine, pin, meta_mac, expiry, status) = row.ok_or(ApiError::NotFound)?;
    // Expired (or a pre-v3 row missing the anchor) reads as absent — the joiner can't proceed without the anchor.
    let (Some(engine), Some(pin), Some(meta_mac)) = (engine, pin, meta_mac) else {
        return Err(ApiError::NotFound);
    };
    if now_ms() > expiry {
        return Err(ApiError::NotFound);
    }
    Ok(Json(InviteMeta {
        uuid: tree_id.to_string(),
        role,
        engine,
        pin: b64(&pin),
        meta_mac: b64(&meta_mac),
        expiry,
        status,
    }))
}

#[derive(Deserialize)]
pub struct ClaimBody {
    member_id: String,
    hpke_public: String,
    author_public: String,
    tag: String,
}

/// `PUT /invites/{invite_id}/claim` — the invitee (signed in) submits its MAC'd public keys.
///
/// The server
/// enforces `member_id == the JWT sub`, the invite is OPEN + unexpired, and ONE live claim. It does NOT
/// verify the MAC (only the owner, holding the link secret, can) — this is the honest-server gate; the
/// real defense is the owner's tag check at admit.
///
/// # Errors
/// Returns [`ApiError`] if the invite is missing/expired or the store access fails.
pub async fn claim_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
    Json(body): Json<ClaimBody>,
) -> Result<StatusCode, ApiError> {
    let member_id = Uuid::parse_str(&body.member_id)
        .map_err(|_| ApiError::BadRequest("member_id is not a uuid".into()))?;
    if member_id != identity.member_id {
        return Err(ApiError::Forbidden); // may only claim as yourself (== the JWT sub)
    }
    let hpke = unb64(&body.hpke_public)?;
    let author = unb64(&body.author_public)?;
    let tag = unb64(&body.tag)?;
    if hpke.len() != 32 || author.len() != 32 {
        return Err(ApiError::BadRequest("keys must be 32 bytes".into()));
    }
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT status, expiry FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let (status, expiry) = row.ok_or(ApiError::NotFound)?;
    if status != "open" {
        return Err(ApiError::Conflict); // already claimed — one live claim
    }
    if now_ms() > expiry {
        return Err(ApiError::Forbidden); // expired
    }
    // CAS the claim in (WHERE status='open' so a race resolves to exactly one claimant).
    let done = sqlx::query(
        "UPDATE pending_invites
         SET status='claimed', claim_member_id=$1, claim_hpke_public=$2, claim_author_public=$3,
             claim_tag=$4, claimed_at=$5
         WHERE invite_id=$6 AND status='open'",
    )
    .bind(member_id)
    .bind(&hpke)
    .bind(&author)
    .bind(&tag)
    .bind(now_ms())
    .bind(&invite_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    if done.rows_affected() == 0 {
        return Err(ApiError::Conflict); // lost the claim race
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct ClaimView {
    member_id: String,
    hpke_public: String,
    author_public: String,
    tag: String,
}

#[derive(Serialize)]
pub struct InviteView {
    invite_id: String,
    role: String,
    recipient_pin: Option<String>,
    expiry: i64,
    status: String,
    claim: Option<ClaimView>,
}

type InviteRow = (
    String,
    String,
    Option<String>,
    i64,
    String,
    Option<Uuid>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// `GET /trees/{tree_id}/invites` — the owner lists its pending invites + any claims (to admit).
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized or the store access fails.
pub async fn list_invites(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
) -> Result<Json<Vec<InviteView>>, ApiError> {
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    let rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT invite_id, role, recipient_pin, expiry, status,
                claim_member_id, claim_hpke_public, claim_author_public, claim_tag
         FROM pending_invites WHERE tree_id = $1 ORDER BY created_at",
    )
    .bind(tree_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    let out = rows
        .into_iter()
        .map(|(invite_id, role, recipient_pin, expiry, status, cm, ch, ca, ct)| {
            let claim = match (cm, ch, ca, ct) {
                (Some(m), Some(h), Some(a), Some(t)) => Some(ClaimView {
                    member_id: m.to_string(),
                    hpke_public: b64(&h),
                    author_public: b64(&a),
                    tag: b64(&t),
                }),
                _ => None,
            };
            InviteView { invite_id, role, recipient_pin, expiry, status, claim }
        })
        .collect();
    Ok(Json(out))
}

/// `POST /invites/{invite_id}/admit` — the owner marks a claimed invite ADMITTED after landing the member in the
/// keyring. This REPLACES delete-at-admit: the joiner still needs `GET /meta` to COMPLETE the join, so the row
/// must survive admit (a scheduled sweep GCs it at expiry). Advisory only — the real admission is the signed
/// keyring change. Idempotent.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized or the store access fails.
pub async fn admit_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let tree_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tree_id FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let Some(tree_id) = tree_id else {
        return Ok(StatusCode::NO_CONTENT); // already gone — idempotent
    };
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    sqlx::query("UPDATE pending_invites SET status = 'admitted' WHERE invite_id = $1 AND status = 'claimed'")
        .bind(&invite_id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /invites/{invite_id}/reopen` — the owner resets a `claimed` invite back to `open`, clearing the claim.
/// Use when a claim's MAC failed verification (a garbage/hostile claim burned the slot): `s` was never
/// compromised — the MAC failed precisely because the claimant lacked it — so the SAME link stays valid, turning
/// slot-burning from "re-deliver a new link" into one click. Only reopens from `claimed` (an `admitted` invite
/// stays admitted).
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized or the store access fails.
pub async fn reopen_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let tree_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tree_id FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let tree_id = tree_id.ok_or(ApiError::NotFound)?;
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    sqlx::query(
        "UPDATE pending_invites
         SET status = 'open', claim_member_id = NULL, claim_hpke_public = NULL, claim_author_public = NULL,
             claim_tag = NULL, claimed_at = NULL
         WHERE invite_id = $1 AND status = 'claimed'",
    )
    .bind(&invite_id)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /invites/{invite_id}` — the owner consumes/cancels an invite after admitting it. Idempotent.
///
/// # Errors
/// Returns [`ApiError`] if the caller isn't authorized or the store access fails.
pub async fn delete_invite(
    State(state): State<AppState>,
    identity: Identity,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let tree_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tree_id FROM pending_invites WHERE invite_id = $1")
            .bind(&invite_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    let Some(tree_id) = tree_id else {
        return Ok(StatusCode::NO_CONTENT); // already gone — idempotent
    };
    let owner = tree_owner(&state.db, tree_id).await?;
    authorize(&state.db, tree_id, owner, identity.member_id, Access::Administer).await?;
    sqlx::query("DELETE FROM pending_invites WHERE invite_id = $1")
        .bind(&invite_id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
