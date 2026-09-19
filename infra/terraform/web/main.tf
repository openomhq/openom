# The Cloudflare Pages project the web app is published to (CI uploads content to this name via
# wrangler; Terraform owns the project + its custom domain). The staging login gate is a Pages Function
# (apps/staging-gate) with a shared password set as a Pages secret via `wrangler pages secret put` —
# not an Access wall, and not managed here.
resource "cloudflare_pages_project" "app" {
  account_id        = var.cloudflare_account_id
  name              = var.pages_project_name
  production_branch = var.production_branch
}

# Attach the custom domain to the project, and point DNS at it (proxied → Cloudflare serves + fronts it).
resource "cloudflare_pages_domain" "app" {
  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.app.name
  name         = var.web_domain
}

resource "cloudflare_dns_record" "app" {
  zone_id = var.cloudflare_zone_id
  name    = var.web_domain
  type    = "CNAME"
  content = "${cloudflare_pages_project.app.name}.pages.dev"
  ttl     = 1 # 1 = automatic; required for a proxied record
  proxied = true
}

output "pages_project" {
  description = "The Pages project name CI deploys to."
  value       = cloudflare_pages_project.app.name
}

output "web_url" {
  description = "The web app's custom domain."
  value       = "https://${var.web_domain}/"
}
