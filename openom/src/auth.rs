//! Authentication.
//!
//! Two axes meet here (see [`crate::config`]):
//! - `AUTH=dev` (fake auth): the real crypto is bypassed — a bearer that parses as a UUID impersonates
//!   that member (otherwise the default one). There is no `sub → member_id` mapping in dev: the bearer
//!   UUID **is** the member id, so the local/CI harness needs no `identities` row (and no Supabase).
//! - `AUTH=jwt`: a provider-neutral JWT (Supabase ES256/JWKS in staging+prod, HS256 self-mint in dev/CI —
//!   see [`crate::jwks`]) is verified locally with no DB round-trip. Since OPE-545 the issuer is a PURE
//!   token issuer: the verified `sub` is mapped to the client's self-certifying `member_id` via the
//!   `identities` table (written once at `POST /register`). A `sub` with no mapping is **unregistered** —
//!   a fail-closed 403 (today's shape), distinct from a signature failure (401).
//!
//! The mapping is IMMUTABLE (`auth_sub → member_id` never changes), so it is only ever **positive-cached**
//! in-process: a hit skips the DB; a miss is never cached (an unregistered `sub` that later registers must
//! resolve on its next request, not stay 403 until the cache recycles).

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
use uuid::Uuid;

use crate::AppState;

/// The authenticated caller: the account id, plus the provider-VERIFIED email when one is present (OPE-451).
/// `verified_email` is `Some` only when the JWT carried `email_verified == true` (or, in dev, an explicit
/// dev-email header) — it is what the invite `recipient_pin` is checked against, and never a bare `email` claim.
#[derive(Debug, Clone)]
pub struct Identity {
    pub member_id: Uuid,
    pub verified_email: Option<String>,
}

/// The `Bearer` token, from `Openom-Auth` (preferred, behind the locked origin) or `Authorization`.
///
/// Behind the locked-origin setup (`CloudFront` OAC) the CDN overwrites `Authorization` with its own origin
/// signature, so the client carries the JWT in `Openom-Auth`; everywhere else (local, dev, tests, a
/// non-CDN host) plain `Authorization` still works. Both carry the same `Bearer <jwt>` value.
fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("openom-auth")
        .or_else(|| parts.headers.get(AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Dev-only: an `x-openom-dev-email` header stands in for a provider-verified email, so a pinned invite
/// (OPE-451) is exercisable in local/dev + tests. Ignored entirely outside dev mode.
fn dev_verified_email(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("x-openom-dev-email")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

/// Resolve a verified `sub` to its `member_id` via the `identities` mapping, positive-caching a hit.
///
/// A miss is `Ok(None)` (the `sub` is unregistered) and is NEVER cached — see the module docs.
///
/// # Errors
/// Returns the underlying `sqlx::Error` on a DB failure (the caller maps it to a 500).
pub(crate) async fn resolve_member(
    state: &AppState,
    sub: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    if let Some(mid) = state.identity_cache.read().await.get(sub).copied() {
        return Ok(Some(mid));
    }
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT member_id FROM identities WHERE auth_sub = $1")
            .bind(sub)
            .fetch_optional(&state.db)
            .await?;
    if let Some(mid) = found {
        state.identity_cache.write().await.insert(sub.to_string(), mid);
    }
    Ok(found)
}

impl FromRequestParts<AppState> for Identity {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = bearer(parts);

        if state.config.auth_is_dev() {
            // Fake auth: no signature check, no mapping. A bearer token that parses as a UUID lets a test
            // impersonate a specific member; otherwise the default one. The UUID IS the member id.
            let id = bearer
                .and_then(|t| Uuid::parse_str(t.trim()).ok())
                .unwrap_or(state.config.local_member_id);
            // OPE-335: a fresh dev UUID has no `accounts` row, so its first `PUT /trees` would 403
            // (FK + per-owner quota gate). Provision it idempotently here — the one place every
            // dev-authed path passes through — so every dev account works.
            crate::provision_dev_account(&state.db, id).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "dev account provisioning failed",
                )
            })?;
            return Ok(Self { member_id: id, verified_email: dev_verified_email(parts) });
        }

        let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let verifier = state.jwt_verifier.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "jwt verifier not configured",
        ))?;
        let claims = verifier
            .verify(token)
            .await
            .map_err(|msg| (StatusCode::UNAUTHORIZED, msg))?;
        // OPE-545: map the verified `sub` onto the client's self-certifying member id. A `sub` with no
        // `identities` row is unregistered — fail closed with a DISTINCT 403 (not the 401 a bad signature
        // gets) so the client knows to prompt sign-in/register rather than re-authenticate.
        let member_id = resolve_member(state, &claims.sub)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "identity lookup failed"))?
            .ok_or((StatusCode::FORBIDDEN, "unregistered"))?;
        Ok(Self { member_id, verified_email: claims.verified_email })
    }
}

/// A verified JWT WITHOUT the `sub → member_id` mapping — the raw token subject + issuer + verified email.
///
/// Used **only** to guard `POST /register` (the sole binder). At registration time the mapping does not
/// exist yet, so the normal [`Identity`] extractor would 403 the very request that creates it. `RawJwt`
/// stops one hop earlier: it proves the caller holds a valid token and hands the handler the `sub`/`iss` it
/// binds the proof-of-possession to. No other route uses it, so registration is the ONE place a `sub` can
/// bind a `member_id`.
#[derive(Debug, Clone)]
pub struct RawJwt {
    /// The issuer's opaque subject (a Supabase UUID / OIDC subject) — the value `/register` binds.
    pub sub: String,
    /// The token issuer (`iss`), bound into the proof-of-possession so it can't be replayed across issuers.
    /// `None` when the token (or a dev bearer) carries no issuer.
    pub iss: Option<String>,
    /// The provider-verified email, if any (same rule as [`Identity`]).
    pub verified_email: Option<String>,
}

impl FromRequestParts<AppState> for RawJwt {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = bearer(parts);

        if state.config.auth_is_dev() {
            // Dev parity: the bearer UUID (or the default) stands in for the token subject, so `/register`
            // is callable in the local harness. There is no issuer.
            let sub = bearer.map_or_else(
                || state.config.local_member_id.to_string(),
                |t| t.trim().to_string(),
            );
            return Ok(Self { sub, iss: None, verified_email: dev_verified_email(parts) });
        }

        let token = bearer.ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let verifier = state.jwt_verifier.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "jwt verifier not configured",
        ))?;
        let claims = verifier
            .verify(token)
            .await
            .map_err(|msg| (StatusCode::UNAUTHORIZED, msg))?;
        Ok(Self { sub: claims.sub, iss: claims.iss, verified_email: claims.verified_email })
    }
}
