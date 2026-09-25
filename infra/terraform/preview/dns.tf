resource "cloudflare_dns_record" "preview_app" {
  zone_id = var.cloudflare_zone_id
  name    = var.app_domain
  type    = "CNAME"
  content = aws_cloudfront_distribution.preview.domain_name
  proxied = false
  ttl     = 60
}

resource "cloudflare_dns_record" "preview_api" {
  zone_id = var.cloudflare_zone_id
  name    = var.api_domain
  type    = "CNAME"
  content = aws_cloudfront_distribution.preview.domain_name
  proxied = false
  ttl     = 60
}
