provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "preview"
      ManagedBy   = "terraform"
      Project     = "openom"
      Stack       = "preview"
    }
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "preview"
      ManagedBy   = "terraform"
      Project     = "openom"
      Stack       = "preview"
    }
  }
}

provider "cloudflare" {}
