terraform {
  required_version = ">= 1.10.0"

  required_providers {
    # Inherited from the caller. The caller's default (or passed) aws provider MUST be in us-east-1 —
    # CloudFront viewer certs can only be issued there. CloudFront itself is global.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}
