# Reusable: CloudFront + a DNS-validated ACM cert + Cloudflare DNS, in front of a Lambda Function URL.
# Instantiated once per (environment, domain): staging, production, and per-PR preview envs all call
# this with a different api_domain + function_url_host.

# --- ACM certificate (us-east-1 — enforced by the caller's provider — DNS-validated via Cloudflare) ---
resource "aws_acm_certificate" "api" {
  domain_name       = var.api_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_dns_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options :
    dvo.domain_name => {
      # Strip ACM's trailing dot — Cloudflare stores names/values undotted, and a doubly-qualified
      # name silently fails validation (the record ACM looks for never appears).
      name    = trimsuffix(dvo.resource_record_name, ".")
      type    = dvo.resource_record_type
      content = trimsuffix(dvo.resource_record_value, ".")
    }
  }
  zone_id = var.cloudflare_zone_id
  name    = each.value.name
  type    = each.value.type
  content = each.value.content
  ttl     = 60
  proxied = false
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn = aws_acm_certificate.api.arn
  # Derive the FQDNs from ACM directly (v5 dropped the computed `hostname`, and we don't want to
  # depend on how the provider echoes back `name`). depends_on ties this to the records' creation.
  validation_record_fqdns = [
    for dvo in aws_acm_certificate.api.domain_validation_options : trimsuffix(dvo.resource_record_name, ".")
  ]
  depends_on = [cloudflare_dns_record.cert_validation]
}

# --- CloudFront in front of the Function URL ---
# Managed policies: never cache the API, and forward all viewer headers EXCEPT Host (a Function URL
# origin needs its own Host, not the viewer's) — AWS's recommended pair for Lambda Function URLs.
data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

# OAC lets CloudFront SigV4-sign requests to the Function URL origin, so the origin can require
# AWS_IAM (locked to CloudFront) instead of being public. The matching grant to the CloudFront
# principal is created by the caller (it needs the Lambda's region + name).
resource "aws_cloudfront_origin_access_control" "api" {
  name                              = "${var.api_domain}-oac"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "api" {
  enabled         = true
  is_ipv6_enabled = true
  # Keep QUIC optionality out of the critical API path: some enterprise networks block UDP/443
  # without letting managed Chromium clients fall back cleanly from HTTP/3 to HTTP/2.
  http_version = "http2"
  aliases      = [var.api_domain]
  comment      = var.comment

  origin {
    domain_name              = var.function_url_host
    origin_id                = "function-url"
    origin_access_control_id = aws_cloudfront_origin_access_control.api.id
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "function-url"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  viewer_certificate {
    # The VALIDATED cert, so CloudFront waits for DNS validation before coming up.
    acm_certificate_arn      = aws_acm_certificate_validation.api.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  price_class = var.price_class
}

# api_domain → CloudFront (DNS-only; CloudFront terminates TLS with the ACM cert).
resource "cloudflare_dns_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = var.api_domain
  type    = "CNAME"
  content = aws_cloudfront_distribution.api.domain_name
  ttl     = 300
  proxied = false
}
