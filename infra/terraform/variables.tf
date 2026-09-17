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
  description = "S3 key of the built Lambda zip in the artifacts bucket, git-SHA-keyed (e.g. openom/<sha>.zip). Empty until a build exists; consumed by OPE-17's Lambda."
  type        = string
  default     = ""
}
