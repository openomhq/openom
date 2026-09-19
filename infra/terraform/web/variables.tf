variable "stack_name" {
  description = "Environment/stack identity (staging, production) — names the Pages project + Access app."
  type        = string
}

variable "cloudflare_account_id" {
  description = "Cloudflare account id that owns Pages + Zero Trust (the openom account)."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id for openom.org — where the web custom-domain CNAME lives."
  type        = string
}

variable "web_domain" {
  description = "Custom domain for the web app (e.g. app.staging.openom.org)."
  type        = string
}

variable "pages_project_name" {
  description = "Cloudflare Pages project name. CI uploads content to this same name via wrangler."
  type        = string
}

variable "production_branch" {
  description = "The Pages project's production branch."
  type        = string
  default     = "main"
}
