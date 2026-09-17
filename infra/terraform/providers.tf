provider "aws" {
  region = var.aws_region

  # Tag everything with the stack, so cost + resources line up with OPENOM_ENV / the OTEL
  # `openom.stack` label. `Stack` mirrors `var.stack_name`.
  default_tags {
    tags = {
      Project   = "openom"
      Stack     = var.stack_name
      ManagedBy = "terraform"
    }
  }
}
