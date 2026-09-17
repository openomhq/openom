//! Runtime configuration.
//!
//! Three INDEPENDENT axes, so a deployment can mix them (the point of the split):
//! - `STORAGE` — `local` (`MinIO`) vs `cloud` (R2). Also gates the dev-key refusal.
//! - `AUTH` — `dev` (fake auth: a bearer that parses as a UUID = that member) vs `jwt`
//!   (a real verified token; the `aud` default keys on this).
//! - runtime — a long-running local HTTP server (+ pretty logs, dev routes) vs a deployed
//!   serverless function (+ JSON logs, no dev routes). Tracks `OPENOM_RUNTIME` (`local` vs
//!   `remote`) — vendor-neutral: `remote` is a serverless function today (AWS Lambda), but
//!   the value names *where* the API runs, not the vendor.
//!
//! `OPENOM_RUNTIME` is a convenience PRESET: `local` → {storage=local, auth=dev, local server};
//! `remote` → {storage=cloud, auth=jwt, deployed}. `STORAGE` / `AUTH` override their axis
//! independently — e.g. `OPENOM_RUNTIME=local` + `AUTH=jwt` + `AUTH_JWT_SECRET=…` is "local
//! Supabase" (real JWT verification over local `MinIO`). Everything is read from the environment.

use std::env;
use uuid::Uuid;

/// Where the API process runs. `Local` = a long-running local HTTP server (+ pretty logs +
/// dev routes); `Remote` = a deployed serverless function (+ JSON logs + no dev routes). Also
/// the default source for the storage/auth axes. Selected by `OPENOM_RUNTIME` (`local` |
/// `remote`) — the deployment sets `remote`; everything else defaults to `local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Local,
    Remote,
}

/// Parse the `OPENOM_RUNTIME` preset. Unset/empty → `Local` (the default); `local`/`remote`
/// select their mode. An **unrecognized** value is a hard startup panic — a switch that
/// controls dev-routes and fake-auth must never silently fall back to `Local` on a real
/// deployment (dev routes registered, pretty logs, OTEL export skipped).
fn parse_runtime(raw: Option<&str>) -> Runtime {
    match raw.map(str::trim) {
        None | Some("" | "local") => Runtime::Local,
        Some("remote") => Runtime::Remote,
        Some(other) => {
            panic!("config: OPENOM_RUNTIME={other:?} is not recognized — set `local` or `remote`")
        }
    }
}

/// Where encrypted tree bytes live. `Cloud` additionally refuses the reserved dev `key_id`
/// (§16) so a dev key can never seal real user data at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Local,
    Cloud,
}

/// How a request is authenticated. `Dev` = fake auth (a UUID bearer is that member, no
/// signature). `Jwt` = the real provider-neutral verifier (Supabase/Clerk/self-hosted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Dev,
    Jwt,
}

/// The JWT verifier algorithm (when `AUTH=jwt`). `Hs256` = a shared secret (Supabase / dev).
///
/// `Rs256` = asymmetric keys (RS256/ES256) fetched from a JWKS URL (Clerk / Auth0 / OIDC /
/// self-hosted). The issuer is never baked in — it's a deployment config choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlg {
    Hs256,
    Rs256,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Runtime preset (local server vs deployed serverless). See the module docs.
    pub runtime: Runtime,
    /// Storage axis (independent of `runtime`; defaults from it, `STORAGE` overrides).
    pub storage: StorageMode,
    /// Auth axis (independent of `runtime`; defaults from it, `AUTH` overrides).
    pub auth: AuthMode,
    /// Address the local HTTP server binds. Ignored when deployed.
    pub http_addr: String,
    /// Postgres connection string (Neon in prod, a local container in dev).
    pub database_url: String,
    /// S3-compatible endpoint the *server* uses for proxy ops (R2 in prod, `MinIO` in dev).
    pub s3_endpoint: String,
    /// Endpoint baked into presigned URLs handed to clients — must be client-reachable.
    pub s3_public_endpoint: String,
    /// Bucket that holds the encrypted tree envelopes.
    pub s3_bucket: String,
    /// S3 region.
    pub s3_region: String,
    /// S3 access key id.
    pub s3_access_key: String,
    /// S3 secret access key.
    pub s3_secret_key: String,
    /// The JWT verifier algorithm when `AUTH=jwt`. `AUTH_JWT_ALG` (`HS256`|`RS256`); default `HS256`
    /// (Supabase/dev back-compat).
    pub jwt_alg: JwtAlg,
    /// JWT verifier shared secret (HS256 — Supabase/dev). `AUTH_JWT_SECRET`, alias
    /// `SUPABASE_JWT_SECRET`. Required when `AUTH=jwt` and `AUTH_JWT_ALG=HS256`.
    pub jwt_secret: Option<String>,
    /// JWKS URL for the asymmetric arm (RS256/ES256 — Clerk/Auth0/OIDC/self-hosted). `AUTH_JWKS_URL`.
    /// Required when `AUTH=jwt` and `AUTH_JWT_ALG=RS256`.
    pub jwks_url: Option<String>,
    /// Expected JWT `iss` claim. `Some` → the token's issuer must match; `None` → skip. `AUTH_JWT_ISS`.
    /// A deployment choice — never baked into code.
    pub jwt_issuer: Option<String>,
    /// Expected JWT `aud` claim. `Some` → the token's audience must match; `None` → skip.
    /// Defaults to `"authenticated"` (Supabase) when `AUTH=jwt`; `AUTH_JWT_AUD` (alias
    /// `SUPABASE_JWT_AUD`) overrides, and an explicit empty value opts out.
    pub jwt_audience: Option<String>,
    /// The account fake-auth maps a bearer-less local request to (`AUTH=dev`).
    pub local_member_id: Uuid,

    /// Export spans over OTLP (opt-in, `OPENOM_OTEL=1`).
    pub otel_enabled: bool,
    /// OTLP/HTTP base endpoint.
    pub otlp_endpoint: String,
    /// Extra OTLP headers as `k1=v1,k2=v2` — a secret, never logged.
    pub otlp_headers: Option<String>,
    /// Shared secret gating the internal scheduled-GC trigger (`POST /internal/gc`, OPE-415). `None` (unset)
    /// → the trigger is refused (fail-closed): only a deployment that sets `OPENOM_INTERNAL_GC_TOKEN` — and
    /// the EventBridge/scheduler caller that presents it in `x-openom-internal-token` — can run the sweep.
    /// Never logged.
    pub internal_gc_token: Option<String>,
}

impl Config {
    /// Build the config from environment variables, with dev-safe defaults.
    ///
    /// # Panics
    /// On an unrecognized `OPENOM_RUNTIME` (fail-fast). Otherwise never in practice: the only
    /// unwrap is on a hardcoded, valid UUID literal.
    #[must_use]
    pub fn from_env() -> Self {
        let runtime = parse_runtime(env::var("OPENOM_RUNTIME").ok().as_deref());
        // Each axis defaults from the OPENOM_RUNTIME preset, then its own env overrides it.
        let storage = match env::var("STORAGE").ok().as_deref() {
            Some("cloud") => StorageMode::Cloud,
            Some("local") => StorageMode::Local,
            _ => match runtime {
                Runtime::Remote => StorageMode::Cloud,
                Runtime::Local => StorageMode::Local,
            },
        };
        let auth = match env::var("AUTH").ok().as_deref() {
            Some("jwt") => AuthMode::Jwt,
            Some("dev") => AuthMode::Dev,
            _ => match runtime {
                Runtime::Remote => AuthMode::Jwt,
                Runtime::Local => AuthMode::Dev,
            },
        };
        let s3_endpoint =
            env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
        let s3_public_endpoint =
            env::var("S3_PUBLIC_ENDPOINT").unwrap_or_else(|_| s3_endpoint.clone());
        let config = Self {
            runtime,
            storage,
            auth,
            http_addr: env::var("OPENOM_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:6060".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://openom:openom@localhost:5432/openom".into()),
            s3_endpoint,
            s3_public_endpoint,
            s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "openom-trees".into()),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "openom".into()),
            s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_else(|_| "openompw123".into()),
            jwt_alg: match env::var("AUTH_JWT_ALG").ok().as_deref() {
                Some("RS256" | "rs256" | "ES256" | "es256") => JwtAlg::Rs256,
                _ => JwtAlg::Hs256,
            },
            jwt_secret: env::var("AUTH_JWT_SECRET")
                .or_else(|_| env::var("SUPABASE_JWT_SECRET"))
                .ok(),
            jwks_url: env::var("AUTH_JWKS_URL").ok().filter(|s| !s.trim().is_empty()),
            jwt_issuer: env::var("AUTH_JWT_ISS").ok().filter(|s| !s.trim().is_empty()),
            jwt_audience: match env::var("AUTH_JWT_AUD").or_else(|_| env::var("SUPABASE_JWT_AUD")) {
                Ok(v) if v.trim().is_empty() => None, // explicit opt-out
                Ok(v) => Some(v),
                // Default the audience check ON for the real-JWT axis (Supabase's "authenticated").
                // Keyed on AUTH, not OPENOM_RUNTIME, so local-Supabase (OPENOM_RUNTIME=local, AUTH=jwt) is hardened.
                Err(_) if auth == AuthMode::Jwt => Some("authenticated".into()),
                Err(_) => None,
            },
            local_member_id: env::var("OPENOM_LOCAL_MEMBER_ID")
                .ok()
                .and_then(|s| Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
                }),
            otel_enabled: matches!(env::var("OPENOM_OTEL").as_deref(), Ok("1" | "true")),
            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4318".into()),
            otlp_headers: env::var("OTEL_EXPORTER_OTLP_HEADERS").ok(),
            internal_gc_token: env::var("OPENOM_INTERNAL_GC_TOKEN").ok().filter(|s| !s.trim().is_empty()),
        };
        config.validate();
        config
    }

    /// True on the local storage axis (`MinIO`). Gates bucket bootstrap; its inverse gates
    /// the dev-key refusal.
    #[must_use]
    pub fn storage_is_local(&self) -> bool {
        self.storage == StorageMode::Local
    }
    /// True on the cloud storage axis (R2) — refuse the reserved dev `key_id` at rest (§16).
    #[must_use]
    pub fn storage_is_cloud(&self) -> bool {
        self.storage == StorageMode::Cloud
    }
    /// True on the fake-auth axis (a UUID bearer is that member; no signature).
    #[must_use]
    pub fn auth_is_dev(&self) -> bool {
        self.auth == AuthMode::Dev
    }
    /// True on the real-JWT axis.
    #[must_use]
    pub fn auth_is_jwt(&self) -> bool {
        self.auth == AuthMode::Jwt
    }
    /// The API runs as a deployed serverless function (JSON logs, no dev routes). A local
    /// server otherwise.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        self.runtime == Runtime::Remote
    }
    /// Dev-only routes (`/dev/media/gc`, later `/dev/auth/token`) are registered only on the
    /// local runtime — never on a deployed one.
    #[must_use]
    pub fn dev_routes_enabled(&self) -> bool {
        self.runtime == Runtime::Local
    }

    /// Refuse illegal axis combinations at startup (fail fast, never at request time).
    fn validate(&self) {
        // Fake auth over real user data must be unrepresentable.
        assert!(
            !(self.auth == AuthMode::Dev && self.storage == StorageMode::Cloud),
            "config: AUTH=dev with STORAGE=cloud is refused — fake auth must never guard real user data"
        );
        // The real-JWT axis needs verifier material for its algorithm: HS256 a shared secret, RS256 a
        // JWKS URL. Fail fast at startup rather than 500 on the first request.
        if self.auth == AuthMode::Jwt {
            match self.jwt_alg {
                JwtAlg::Hs256 => assert!(
                    self.jwt_secret.is_some(),
                    "config: AUTH=jwt AUTH_JWT_ALG=HS256 requires AUTH_JWT_SECRET (a shared secret)"
                ),
                JwtAlg::Rs256 => assert!(
                    self.jwks_url.is_some(),
                    "config: AUTH=jwt AUTH_JWT_ALG=RS256 requires AUTH_JWKS_URL (the issuer's JWKS endpoint)"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_runtime, Runtime};

    #[test]
    fn runtime_unset_or_empty_defaults_to_local() {
        assert_eq!(parse_runtime(None), Runtime::Local);
        assert_eq!(parse_runtime(Some("")), Runtime::Local);
        assert_eq!(parse_runtime(Some("   ")), Runtime::Local);
    }

    #[test]
    fn runtime_recognized_values() {
        assert_eq!(parse_runtime(Some("local")), Runtime::Local);
        assert_eq!(parse_runtime(Some("remote")), Runtime::Remote);
        assert_eq!(parse_runtime(Some(" remote ")), Runtime::Remote); // trimmed
    }

    #[test]
    #[should_panic(expected = "not recognized")]
    fn runtime_unrecognized_panics_not_silent_local() {
        // A typo (or a vendor word like "lambda") must fail fast — never silently boot the
        // Local preset on a real deployment.
        let _ = parse_runtime(Some("lambda"));
    }
}
