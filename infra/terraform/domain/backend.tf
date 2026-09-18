# S3 backend with NATIVE state locking (use_lockfile) — no DynamoDB lock table.
#
# bucket/key/region come PER-ENV via `-backend-config=env/<env>.s3.tfbackend` at init. This root keeps
# its OWN state object (…/domain.tfstate), separate from the app root's, because the two are applied by
# different principals: the app root by the narrow CI OIDC role on every deploy, this domain root by an
# admin (it needs CloudFront + ACM + Cloudflare, which CI has no rights to). Sharing one state would
# make each apply try to destroy the other's resources.
terraform {
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
