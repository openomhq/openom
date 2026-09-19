terraform {
  # >= 1.10 for NATIVE S3 state locking (use_lockfile), matching the other roots.
  required_version = ">= 1.10.0"

  required_providers {
    # Cloudflare Pages (the web app host), its custom domain + DNS, and the Zero Trust Access wall.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}
