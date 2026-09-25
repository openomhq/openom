resource "aws_acm_certificate" "preview" {
  provider                  = aws.us_east_1
  domain_name               = var.app_domain
  subject_alternative_names = [var.api_domain]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_dns_record" "certificate_validation" {
  for_each = {
    for option in aws_acm_certificate.preview.domain_validation_options :
    option.domain_name => {
      name  = trimsuffix(option.resource_record_name, ".")
      type  = option.resource_record_type
      value = trimsuffix(option.resource_record_value, ".")
    }
  }

  zone_id = var.cloudflare_zone_id
  name    = each.value.name
  type    = each.value.type
  content = each.value.value
  proxied = false
  ttl     = 60
}

resource "aws_acm_certificate_validation" "preview" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.preview.arn
  validation_record_fqdns = [for record in cloudflare_dns_record.certificate_validation : record.name]
}
