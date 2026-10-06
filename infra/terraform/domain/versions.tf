terraform {
  # Match the OpenTofu minor used by every persistent infrastructure root.
  required_version = "~> 1.13.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # v6.22 added declarative support for preserving S3's SSE-C upload block.
      version = "~> 6.22"
    }
    # DNS for the API custom domain (ACM validation record + the CNAME to CloudFront).
    cloudflare = {
      source = "cloudflare/cloudflare"
      # Upgrade deliberately: newer releases add computed DNS metadata that otherwise churns plans.
      version = "5.25.0"
    }
  }
}
