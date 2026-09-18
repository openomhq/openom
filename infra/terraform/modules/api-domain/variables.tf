variable "api_domain" {
  description = "FQDN to serve the API on (e.g. api.staging.openom.org, api.openom.org, pr123.api.dev.openom.org)."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id that owns api_domain's DNS records (the openom.org zone)."
  type        = string
}

variable "function_url_host" {
  description = "Lambda Function URL host — no scheme, no trailing slash (<id>.lambda-url.<region>.on.aws). CloudFront's origin."
  type        = string
}

variable "comment" {
  description = "CloudFront distribution comment (shown in the console)."
  type        = string
  default     = "openom API"
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_100 = NA + EU edges (cheapest covering our users)."
  type        = string
  default     = "PriceClass_100"
}
