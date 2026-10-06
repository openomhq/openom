variable "stack_name" {
  description = "Environment/stack identity — names the Lambda to look up + tags + CloudFront comment (staging, production)."
  type        = string
}

variable "api_domain" {
  description = "Custom domain to put in front of the API Function URL (e.g. api.staging.openom.org)."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id for openom.org — where the ACM-validation + CNAME records are written."
  type        = string
}

variable "app_region" {
  description = "AWS region where the app Lambda runs, so its Function URL can be read as the CloudFront origin."
  type        = string
  default     = "eu-central-1"
}

variable "state_bucket_name" {
  description = "Existing S3 bucket that stores every persistent OpenTofu root's remote state."
  type        = string
  default     = ""
}

variable "manage_state_bucket" {
  description = "Whether this domain state is the single administrative owner of the shared state bucket."
  type        = bool
  default     = false
}

variable "state_bucket_region" {
  description = "AWS region containing the shared OpenTofu state bucket."
  type        = string
  default     = "eu-central-1"
}
