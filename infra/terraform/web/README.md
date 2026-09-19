# Web app host (Cloudflare Pages)

The staging web app: `app.staging.openom.org` on a Cloudflare **Pages** project, pointed at the real API
(`api.staging.openom.org`), behind a lightweight shared-password **staging gate**.

## Why a separate admin root

Like `domain/`, admin-applied: Pages + DNS are account/zone-scoped Cloudflare resources needing a token
with Pages Edit + DNS Edit. Own state key `web/staging.tfstate`. It owns the Pages project + custom
domain; the workflow `staging.web.yml` uploads content (the app + the gate Function) to it.

## The staging gate (not Cloudflare Access)

A Pages Function (`apps/staging-gate/_middleware.js`, deployed into `_site/functions/`) serves a branded
"openom · staging" page with a **single shared password**, build info (commit, branch), and live
per-service health — API / DATABASE / AUTH / STORAGE, read server-side from the API's `/status`. Enter
the password → a 30-day cookie → the app loads. The app's own account login is the *real* gate behind it.

Share access by telling someone the password (works from your phone); to revoke everyone, rotate it.
This trades per-person control for zero-friction sharing — fine for a pre-release staging env with no
real data. (If that ever changes, swap in per-person Cloudflare Access.)

The password is the GitHub `staging` secret **`STAGING_APP_GATE_PASSWORD`**. The `staging.web` workflow
syncs it into the Pages project on every deploy (`wrangler pages secret put`, fed over stdin) — no local
tooling. Rotate = update the GitHub secret and re-run `staging.web`.

## Inputs

Committed in `env/staging.tfvars`: `cloudflare_account_id`, `cloudflare_zone_id`, `web_domain`,
`pages_project_name`. No secrets in the repo.

**Two tokens, don't confuse them:**
- `CLOUDFLARE_PAGES_TOKEN` — a **GitHub secret** (Pages-Edit only), read by CI (`staging.web` →
  `wrangler pages deploy`). Set once; you never need its value again.
- `CLOUDFLARE_API_TOKEN` — **not** a GitHub secret. It's the **env-var name** wrangler + the Terraform
  Cloudflare provider read when you run commands **locally** (the `terraform apply` here, and
  `wrangler pages secret put`). Fill it with the local admin token (`openom-terraform-cloudflare`,
  Pages+DNS+Access) in your shell: `export CLOUDFLARE_API_TOKEN=<that value>`.

## Apply (admin, local)

```sh
export CLOUDFLARE_API_TOKEN=…        # Pages + DNS edit
cd infra/terraform/web
terraform init  -backend-config=env/staging.s3.tfbackend
terraform apply -var-file=env/staging.tfvars
```

Then, for the content deploy (`staging.web.yml`), set these on the GitHub `staging` environment:
`CLOUDFLARE_PAGES_TOKEN` secret (a Pages-Edit-only token), `STAGING_APP_GATE_PASSWORD` secret (the shared
gate password), the `CLOUDFLARE_ACCOUNT_ID` variable, and `https://app.staging.openom.org` in the
`OPENOM_WEB_ORIGINS` variable (server CORS). Then dispatch the workflow.

## Notes

- **Cutover from the Access wall:** this apply removes the previously-applied Zero Trust Access
  application + policy. Fine — the Pages project has no content deployed yet, so there's nothing exposed
  in the gap until the first `staging.web` deploy brings up the gate Function.
- **CSP ships Report-Only first** (in the workflow's `_headers`) — verify in a browser, then enforce.
  The gate page sets its own CSP (to allow its inline `<style>`); the app gets the `_headers` CSP.
- **API stays gate-free** (CloudFront OAC + app JWT) — never put a wall on it (it would block the SPA's
  XHR).
- **Prod later**: `env/production.tfvars` (`app.openom.org` or `play.openom.org`) + a backend file.
