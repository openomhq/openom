variable "stack_name" {
  description = "Environment/stack identity — prefixes resource names + tags (staging, production). Matches OPENOM_ENV and the OTEL openom.stack label."
  type        = string
}

variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "eu-central-1"
}

variable "tf_state_bucket" {
  description = "The out-of-band Terraform state bucket (OPE-468). Named here too so the CI deploy role can be granted state access (a backend block can't be read as a variable). Keep in sync with env/<env>.s3.tfbackend."
  type        = string
}

variable "github_owner" {
  description = "GitHub org/user that owns the repo allowed to assume the CI deploy role."
  type        = string
  default     = "openomhq"
}

variable "github_repo" {
  description = "GitHub repository name (without owner) allowed to assume the CI deploy role."
  type        = string
  default     = "openom"
}

variable "github_environment" {
  description = "The GitHub Actions environment (job `environment:`) whose OIDC token may assume the deploy role."
  type        = string
  default     = "staging"
}

variable "manage_oidc_provider" {
  description = "Create the account-global GitHub OIDC provider from THIS stack. Exactly one stack per AWS account sets true (staging owns it); others set false and look it up. Prevents an EntityAlreadyExists collision across environments."
  type        = bool
  default     = true
}

variable "lambda_artifact_key" {
  description = "S3 key of the built Lambda zip in the artifacts bucket, git-SHA-keyed (e.g. openom/<sha>.zip). Empty until a build exists; the Lambda is count-gated on it, so the admin's first (IAM-only) apply runs with it empty and CI brings the function up."
  type        = string
  default     = ""
}

# --- Lambda env-specific config ---
# All supplied by CI as TF_VAR_* from the GitHub `staging` environment (GitHub stays the single source
# of truth). Every one defaults to "" so the admin's first apply — before any artifact exists, Lambda
# count 0 — needs none of them. CI sets them when it deploys the function.

# Non-secret (GitHub *variables*).
variable "otlp_endpoint" {
  description = "OTLP/HTTP base endpoint (Axiom EU edge). Non-secret."
  type        = string
  default     = ""
}
variable "s3_endpoint" {
  description = "R2 S3-compatible endpoint the server signs requests against. Non-secret."
  type        = string
  default     = ""
}
variable "s3_public_endpoint" {
  description = "R2 endpoint baked into presigned URLs handed to clients. Non-secret."
  type        = string
  default     = ""
}
variable "s3_bucket" {
  description = "R2 bucket holding encrypted tree blobs. Non-secret."
  type        = string
  default     = ""
}
variable "s3_region" {
  description = "R2 region (usually auto). Non-secret."
  type        = string
  default     = ""
}
variable "jwks_url" {
  description = "Supabase JWKS URL for ES256 verification. Non-secret (public endpoint)."
  type        = string
  default     = ""
}
variable "jwt_issuer" {
  description = "Expected JWT iss claim (Supabase). Non-secret."
  type        = string
  default     = ""
}
variable "jwt_audience" {
  description = "Expected JWT aud claim (Supabase, usually 'authenticated'). Non-secret."
  type        = string
  default     = ""
}
variable "web_origins" {
  description = "CORS allow-list for OPENOM_WEB_ORIGINS (comma-separated). Non-secret."
  type        = string
  default     = ""
}

# Secrets (GitHub *secrets*) — sensitive, redacted in plan output.
variable "database_url" {
  description = "Pooled Neon connection string (embeds the password). Secret."
  type        = string
  default     = ""
  sensitive   = true
}
variable "s3_access_key" {
  description = "R2 access key id. Secret."
  type        = string
  default     = ""
  sensitive   = true
}
variable "s3_secret_key" {
  description = "R2 secret access key. Secret."
  type        = string
  default     = ""
  sensitive   = true
}
variable "otlp_headers" {
  description = "OTLP headers carrying the Axiom token + dataset (k=v,..). Secret."
  type        = string
  default     = ""
  sensitive   = true
}
variable "internal_gc_token" {
  description = "Shared secret gating POST /internal/gc. Secret."
  type        = string
  default     = ""
  sensitive   = true
}
