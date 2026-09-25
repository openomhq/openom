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
