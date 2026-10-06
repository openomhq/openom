terraform {
  # OpenTofu 1.13 supplies native S3 locking and client-side state encryption.
  required_version = "~> 1.13.0"

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
