# S3 backend with NATIVE state locking (use_lockfile) — no DynamoDB lock table.
#
# bucket/key/region are supplied PER-ENV via `-backend-config=env/<env>.s3.tfbackend` at
# `terraform init` (partial config), so each environment keeps its own state object under the one
# shared, versioned state bucket (created out-of-band).
terraform {
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
