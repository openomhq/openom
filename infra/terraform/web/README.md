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
the password → a 30-day cookie → the app loads. The form is served as a normal `200` HTML response rather
than an HTTP-auth `401`, so all supported browsers render it consistently. The app's own account login is
the *real* gate behind it.

Share access by telling someone the password (works from your phone); to revoke everyone, rotate it.
This trades per-person control for zero-friction sharing — fine for a pre-release staging env with no
real data. (If that ever changes, swap in per-person Cloudflare Access.)

The password is managed in Infisical and synchronized to the GitHub `staging` environment as
**`STAGING_APP_GATE_PASSWORD`**. The `staging.web` workflow copies that delivery value into the Pages
project on every deploy (`wrangler pages secret put`, fed over stdin). Rotate it in Infisical, wait for
the GitHub sync, then re-run `staging.web`.

## Inputs

Committed in `env/staging.tfvars`: `cloudflare_account_id`, `cloudflare_zone_id`, `web_domain`,
`pages_project_name`. No secrets in the repo.

**Two tokens, don't confuse them:**
- `CLOUDFLARE_PAGES_TOKEN` — a Pages-Edit-only token managed in Infisical and synchronized to the
  GitHub `staging` environment for `staging.web`.
- `CLOUDFLARE_API_TOKEN` — an unsynchronized local operator credential from `prod:/admin`. The
  Terraform Cloudflare provider reads it when an administrator runs this root.

## Apply (admin, local)

```sh
export CLOUDFLARE_API_TOKEN=…        # Pages + DNS edit
cd infra/terraform/web
terraform init  -backend-config=env/staging.s3.tfbackend
terraform apply -var-file=env/staging.tfvars
```

For content deployment, Infisical delivers `CLOUDFLARE_PAGES_TOKEN` and
`STAGING_APP_GATE_PASSWORD` to the GitHub `staging` environment. Keep `CLOUDFLARE_ACCOUNT_ID` and
`OPENOM_WEB_ORIGINS` as GitHub variables, then dispatch `staging.web`.

## Notes

- **CSP ships Report-Only first** (in the workflow's `_headers`) — verify in a browser, then enforce.
  The gate page sets its own CSP (to allow its inline `<style>`); the app gets the `_headers` CSP.
- **API stays gate-free** (CloudFront OAC + app JWT) — never put a wall on it (it would block the SPA's
  XHR).
- **Prod later**: `env/production.tfvars` (`app.openom.org` or `play.openom.org`) + a backend file.
