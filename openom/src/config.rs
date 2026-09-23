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
use std::fmt;

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

/// Environment *identity* — orthogonal to [`Runtime`] (you can run any env locally). Drives
/// payment sandbox-vs-live, the telemetry `deployment.environment` tag, and `noindex`. A
/// **closed** 3-value set: widening it touches every exhaustive `match` + alerting query.
/// `OPENOM_ENV` (`development` | `staging` | `production`); required when `OPENOM_RUNTIME=remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenomEnv {
    Development,
    Staging,
    Production,
}

impl OpenomEnv {
    /// The lowercase name, for the OTEL `deployment.environment` attribute + logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OpenomEnv::Development => "development",
            OpenomEnv::Staging => "staging",
            OpenomEnv::Production => "production",
        }
    }
    /// True only in the live production environment (gates live payments, etc.).
    #[must_use]
    pub fn is_production(self) -> bool {
        matches!(self, OpenomEnv::Production)
    }
}

/// Parse `OPENOM_ENV`. `None` when unset/empty (the caller picks the default vs a required
/// panic per runtime); a known value → `Some`; an unrecognized value → a hard startup panic.
fn parse_env(raw: Option<&str>) -> Option<OpenomEnv> {
    match raw.map(str::trim) {
        None | Some("") => None,
        Some("development") => Some(OpenomEnv::Development),
        Some("staging") => Some(OpenomEnv::Staging),
        Some("production") => Some(OpenomEnv::Production),
        Some(other) => panic!(
            "config: OPENOM_ENV={other:?} is not recognized — set development, staging, or production"
        ),
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

#[derive(Clone)]
pub struct Config {
    /// Runtime preset (local server vs deployed serverless). See the module docs.
    pub runtime: Runtime,
    /// Environment identity (`OPENOM_ENV`). Required when `runtime == Remote`; defaults to
    /// `Development` locally. Drives sandbox-vs-live payments, the telemetry env tag, noindex.
    pub env: OpenomEnv,
    /// Free-form deployment/stack label (`OPENOM_STACK` = the Terraform `stack_name`), surfaced
    /// as the OTEL `service.instance.id` so preview/branch traffic is separable from laptops.
    pub stack: Option<String>,
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

    /// Browser origins allowed for cross-origin fetch (CORS) — `OPENOM_WEB_ORIGINS`, a comma-separated
    /// list of exact origins (`https://staging.openom.org`) and/or single-label wildcard patterns
    /// (`https://*.<project>.pages.dev`). A deployment input, NOT derived from `OPENOM_ENV` (like
    /// `jwt_issuer`) — and the SAME value is the one source of truth the R2 bucket CORS and the Pages
    /// CSP `connect-src` also read, so they can't drift. Empty (unset) → no cross-origin (same-origin).
    pub web_origins: Vec<String>,
}

impl fmt::Debug for Config {
    /// Hand-rolled so secrets are REDACTED (presence preserved) — a stray `{:?}` in a log or panic
    /// must never leak the DB password, the S3 keys, or the JWT/OTLP/GC secrets. Non-secret fields
    /// print normally. Keep in sync when adding a field: a new SECRET must be redacted here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("Config")
            .field("runtime", &self.runtime)
            .field("env", &self.env)
            .field("stack", &self.stack)
            .field("storage", &self.storage)
            .field("auth", &self.auth)
            .field("http_addr", &self.http_addr)
            .field("database_url", &"<redacted>") // embeds the Postgres password
            .field("s3_endpoint", &self.s3_endpoint)
            .field("s3_public_endpoint", &self.s3_public_endpoint)
            .field("s3_bucket", &self.s3_bucket)
            .field("s3_region", &self.s3_region)
            .field("s3_access_key", &"<redacted>")
            .field("s3_secret_key", &"<redacted>")
            .field("jwt_alg", &self.jwt_alg)
            .field("jwt_secret", &redact(&self.jwt_secret))
            .field("jwks_url", &self.jwks_url)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("local_member_id", &self.local_member_id)
            .field("otel_enabled", &self.otel_enabled)
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field("otlp_headers", &redact(&self.otlp_headers)) // Axiom ingest token
            .field("internal_gc_token", &redact(&self.internal_gc_token))
            .field("web_origins", &self.web_origins)
            .finish()
    }
}

/// Parse `OPENOM_WEB_ORIGINS` — a comma-separated CORS allow-list of browser origins. Trims each
/// entry, drops a stray trailing slash (an `Origin` header never has one), and skips empties; an
/// unset/blank value yields no origins (same-origin only).
fn parse_web_origins(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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
        // Environment identity: required when deployed (defaulting to `development` inside a real
        // deploy is wrong-by-default); a local run defaults to `development`.
        let openom_env = parse_env(env::var("OPENOM_ENV").ok().as_deref()).unwrap_or_else(|| {
            match runtime {
                Runtime::Remote => panic!(
                    "config: OPENOM_ENV is required when OPENOM_RUNTIME=remote — set development, staging, or production"
                ),
                Runtime::Local => OpenomEnv::Development,
            }
        });
        let stack = env::var("OPENOM_STACK")
            .ok()
            .filter(|s| !s.trim().is_empty());
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
            env: openom_env,
            stack,
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
            jwks_url: env::var("AUTH_JWKS_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            jwt_issuer: env::var("AUTH_JWT_ISS")
                .ok()
                .filter(|s| !s.trim().is_empty()),
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
            internal_gc_token: env::var("OPENOM_INTERNAL_GC_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            web_origins: parse_web_origins(env::var("OPENOM_WEB_ORIGINS").ok().as_deref()),
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
    use super::{parse_env, parse_runtime, OpenomEnv, Runtime};

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

    #[test]
    fn env_parses_the_three_values() {
        assert_eq!(parse_env(Some("development")), Some(OpenomEnv::Development));
        assert_eq!(parse_env(Some("staging")), Some(OpenomEnv::Staging));
        assert_eq!(parse_env(Some(" production ")), Some(OpenomEnv::Production)); // trimmed
        assert_eq!(parse_env(None), None);
        assert_eq!(parse_env(Some("")), None);
    }

    #[test]
    #[should_panic(expected = "not recognized")]
    fn env_unrecognized_panics() {
        // A near-miss like "prod" must fail fast, not silently pick an environment.
        let _ = parse_env(Some("prod"));
    }

    #[test]
    fn web_origins_parse_trims_slashes_and_drops_empties() {
        use super::parse_web_origins;
        assert!(parse_web_origins(None).is_empty());
        assert!(parse_web_origins(Some("  ")).is_empty());
        assert_eq!(
            parse_web_origins(Some(" https://a.com/ , ,https://b.com ")),
            vec!["https://a.com".to_string(), "https://b.com".to_string()],
        );
    }

    #[test]
    fn debug_redacts_every_secret() {
        use super::{AuthMode, Config, JwtAlg, StorageMode};
        let cfg = Config {
            runtime: Runtime::Remote,
            env: OpenomEnv::Production,
            stack: Some("prod-eu".into()),
            storage: StorageMode::Cloud,
            auth: AuthMode::Jwt,
            http_addr: "0.0.0.0:6060".into(),
            database_url: "postgres://user:SUPERSECRETPW@host/db".into(),
            s3_endpoint: "https://s3".into(),
            s3_public_endpoint: "https://s3".into(),
            s3_bucket: "b".into(),
            s3_region: "eu".into(),
            s3_access_key: "AKIASECRETKEYID".into(),
            s3_secret_key: "S3SECRETVALUE".into(),
            jwt_alg: JwtAlg::Hs256,
            jwt_secret: Some("JWTSHARED".into()),
            jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            local_member_id: uuid::Uuid::nil(),
            otel_enabled: true,
            otlp_endpoint: "https://otel".into(),
            otlp_headers: Some("authorization=Bearer AXIOMTOKEN".into()),
            internal_gc_token: Some("GCTOKENVALUE".into()),
            web_origins: vec!["https://app.example".into()],
        };
        let dbg = format!("{cfg:?}");
        for secret in [
            "SUPERSECRETPW",
            "AKIASECRETKEYID",
            "S3SECRETVALUE",
            "JWTSHARED",
            "AXIOMTOKEN",
            "GCTOKENVALUE",
        ] {
            assert!(!dbg.contains(secret), "Debug leaked a secret: {secret}");
        }
        assert!(
            dbg.contains("<redacted>"),
            "secrets should be marked redacted"
        );
        // Non-secret fields still print — Debug stays useful for diagnostics.
        assert!(dbg.contains("Production") && dbg.contains("app.example"));
    }
}
