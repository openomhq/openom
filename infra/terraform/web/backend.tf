# S3 backend with NATIVE state locking. Own state object (web/<env>.tfstate) — this root is admin-applied
# (it needs account-scoped Cloudflare Pages + Zero Trust rights, which CI doesn't hold), separate from the
# app root (CI) and the api-domain root. bucket/key/region come per-env via -backend-config.
terraform {
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
