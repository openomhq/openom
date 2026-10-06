terraform {
  # Match the OpenTofu minor used by every persistent infrastructure root.
  required_version = "~> 1.13.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # DNS for the API custom domain (ACM validation record + the CNAME to CloudFront).
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}
