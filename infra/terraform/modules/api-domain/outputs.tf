output "api_custom_url" {
  description = "The API's custom domain."
  value       = "https://${var.api_domain}/"
}

output "cloudfront_domain" {
  description = "The CloudFront distribution domain the api_domain CNAME points at."
  value       = aws_cloudfront_distribution.api.domain_name
}

output "certificate_arn" {
  description = "ARN of the validated ACM certificate."
  value       = aws_acm_certificate_validation.api.certificate_arn
}
