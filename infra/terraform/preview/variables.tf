variable "aws_region" {
  description = "AWS region for preview Lambda functions and standing regional resources."
  type        = string
  default     = "eu-central-1"
}

variable "expected_aws_account_id" {
  description = "AWS account in which the preview platform is allowed to exist."
  type        = string
  default     = "841547768414"
}

variable "cloudflare_account_id" {
  description = "Cloudflare account that owns Pages and R2."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for openom.org."
  type        = string
}

variable "github_owner" {
  description = "GitHub organization allowed to assume the preview deployment role."
  type        = string
  default     = "openomhq"
}

variable "github_repository" {
  description = "GitHub repository allowed to assume the preview deployment role."
  type        = string
  default     = "openom"
}

variable "github_environment" {
  description = "Protected GitHub Environment used by preview deployment jobs."
  type        = string
  default     = "preview"
}

variable "pages_project_name" {
  description = "Dedicated Cloudflare Pages project for pull-request previews."
  type        = string
  default     = "openom-preview"
}

variable "pages_production_branch" {
  description = "Administrative production branch for the dedicated preview Pages project."
  type        = string
  default     = "main"
}

variable "r2_bucket_name" {
  description = "Dedicated R2 bucket for all preview object-store namespaces."
  type        = string
  default     = "openom-preview"
}

variable "artifacts_bucket_name" {
  description = "AWS S3 bucket holding short-lived preview Lambda artifacts."
  type        = string
  default     = "openom-preview-artifacts"
}

variable "terraform_state_bucket" {
  description = "Existing AWS S3 bucket that stores Terraform state."
  type        = string
}

variable "app_domain" {
  description = "Wildcard application domain served by the shared preview edge."
  type        = string
  default     = "*.app.dev.openom.org"
}

variable "api_domain" {
  description = "Wildcard API domain served by the shared preview edge."
  type        = string
  default     = "*.api.dev.openom.org"
}
