terraform {
  # >= 1.10 for NATIVE S3 state locking (use_lockfile), matching the app root.
  required_version = ">= 1.10.0"

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
