# CloudFront and its ACM cert are managed here. CloudFront viewer certs MUST live in us-east-1, and
# CloudFront itself is global, so this default provider covers both.
provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Project   = "openom"
      Stack     = var.stack_name
      ManagedBy = "terraform"
    }
  }
}

# The region where the app Lambda lives — used ONLY to read its Function URL (the CloudFront origin).
provider "aws" {
  alias  = "app_region"
  region = var.app_region
  default_tags {
    tags = {
      Project   = "openom"
      Stack     = var.stack_name
      ManagedBy = "terraform"
    }
  }
}

# DNS for openom.org. Reads the token from CLOUDFLARE_API_TOKEN in the environment (never committed).
provider "cloudflare" {}
