terraform {
  # >= 1.10 for NATIVE S3 state locking (use_lockfile) — no DynamoDB lock table required.
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # Used only to fetch GitHub's OIDC TLS thumbprint at plan time (see oidc.tf).
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
