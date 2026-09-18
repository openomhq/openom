locals {
  fn_name = "openom-${var.stack_name}-api"
}

# Read the app Lambda's alias Function URL directly. NOT via terraform_remote_state — that copies the
# app root's ENTIRE state (which holds plaintext DB/R2/token secrets) into this root's state. A direct
# data lookup takes only the URL, and stays correct if the app root's backend layout ever changes.
#
# This read fails with a clear "not found" if the Lambda/alias doesn't exist yet — deploy the app
# stack before applying the domain.
data "aws_lambda_function_url" "api" {
  provider      = aws.app_region
  function_name = local.fn_name
  qualifier     = "live"
}

locals {
  # CloudFront's origin: the Function URL host, no scheme, no trailing slash.
  function_url_host = trimsuffix(trimprefix(data.aws_lambda_function_url.api.function_url, "https://"), "/")
}

module "api_domain" {
  source = "../modules/api-domain"

  api_domain         = var.api_domain
  cloudflare_zone_id = var.cloudflare_zone_id
  function_url_host  = local.function_url_host
  comment            = "openom ${var.stack_name} API"
}

output "api_custom_url" {
  description = "The API's custom domain."
  value       = module.api_domain.api_custom_url
}

output "cloudfront_domain" {
  description = "The CloudFront distribution domain the API CNAME points at."
  value       = module.api_domain.cloudfront_domain
}
