output "cloudfront_distribution_id" {
  description = "Shared preview CloudFront distribution ID."
  value       = aws_cloudfront_distribution.preview.id
}

output "cloudfront_domain" {
  description = "AWS hostname behind both unproxied preview wildcard records."
  value       = aws_cloudfront_distribution.preview.domain_name
}

output "route_store_arn" {
  description = "CloudFront KeyValueStore updated by preview lifecycle workflows."
  value       = aws_cloudfront_key_value_store.routes.arn
}

output "route_store_id" {
  description = "CloudFront KeyValueStore ID updated by preview lifecycle workflows."
  value       = aws_cloudfront_key_value_store.routes.id
}

output "router_sink_function_url" {
  description = "Protected standing origin used solely to carry Lambda OAC configuration."
  value       = aws_lambda_function_url.router_sink.function_url
}

output "pages_project_name" {
  description = "Dedicated Pages project receiving preview branch deployments."
  value       = cloudflare_pages_project.preview.name
}

output "preview_artifacts_bucket" {
  description = "AWS S3 bucket receiving short-lived Lambda deployment packages."
  value       = aws_s3_bucket.artifacts.id
}

output "preview_object_store" {
  description = "Non-secret R2 endpoint and bucket consumed by preview deployment workflows."
  value = {
    bucket   = cloudflare_r2_bucket.preview.name
    endpoint = "https://${var.cloudflare_account_id}.r2.cloudflarestorage.com"
    region   = "auto"
  }
}

output "preview_api_execution_role_arn" {
  description = "Shared, boundary-capped execution role for ephemeral preview APIs."
  value       = aws_iam_role.preview_api.arn
}

output "preview_deploy_role_arn" {
  description = "GitHub OIDC role assumed by privileged preview lifecycle jobs."
  value       = aws_iam_role.preview_deploy.arn
}
