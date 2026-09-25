terraform {
  required_version = ">= 1.10.0"

  backend "s3" {
    use_lockfile = true
  }

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}
