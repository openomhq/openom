terraform {
  # Match the OpenTofu minor used by every persistent infrastructure root.
  required_version = "~> 1.13.0"

  required_providers {
    # Cloudflare Pages (the web app host), its custom domain, and DNS.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}
