# Administrative AWS and domain controls

Puts `api.<stack>.openom.org` in front of the Lambda **Function URL** via CloudFront + a DNS-validated
ACM cert, with Cloudflare DNS. For staging, this root also owns the existing shared OpenTofu state
bucket's protective configuration. The domain resources live in the reusable `../modules/api-domain`
module; this root wires those resources and the account-level administrative controls together.

## Why this is a separate OpenTofu root

The server root (`infra/terraform/`) is applied by the **CI OIDC role on every deploy**, and that role is
deliberately narrow (Lambda + logs + its own state). CloudFront, ACM, and Cloudflare are **not** in its
rights and there is no `CLOUDFLARE_API_TOKEN` in CI. This root is therefore **admin-applied**, keeps its
**own state object** (`domain/staging.tfstate` — outside the `staging/*` prefix the CI role can reach, so
CI can't read or corrupt it), and reads the app Lambda's Function URL with a direct
`aws_lambda_function_url` data lookup.

The shared state bucket also belongs here because this root is admin-applied and outside the CI role's
state prefix. `manage_state_bucket` is true only for staging: exactly one persistent state may own the
account-level bucket, even after production domain configuration is added. Keeping that ownership in an
existing root avoids a fifth state object, a fifth passphrase, and a circular bootstrap root.

Deploy the app stack first: if the `openom-<stack>-api` Lambda / `live` alias doesn't exist, the read
fails with a clear "not found" and nothing is created.

## Apply (admin, local)

```sh
# 1. AWS admin creds for the workload account (CloudFront/ACM are global/us-east-1).
aws sso login --profile openom-admin
export AWS_PROFILE=openom-admin

# 2. Fill cloudflare_zone_id in env/staging.tfvars (the openom.org zone id — not a secret).

cd infra/terraform/domain
infisical run --env=prod --path=/admin --command \
  'export TF_VAR_state_passphrase="$TOFU_STATE_PASSPHRASE_DOMAIN"; tofu init -backend-config=env/staging.s3.tfbackend && tofu apply -var-file=env/staging.tfvars'
```

The apply creates the ACM validation records, waits for the cert to issue, brings up CloudFront, then
points `api.staging.openom.org` at it (a DNS-only CNAME).

## Remote-state bucket

`state-storage.tf` manages `openom-tfstate-841547768414` in place. The staging domain state is its
single owner and preserves these controls:

- versioning enabled;
- SSE-S3 (`AES256`) default encryption with SSE-C uploads blocked;
- every S3 public-access block enabled;
- bucket-owner-enforced object ownership;
- deletion blocked by `prevent_destroy`; and
- obsolete versions of state and lock objects expired after 30 days, with no expiration rule for
  current object versions.

The root is intentionally self-hosted: `domain/staging.tfstate` lives in the bucket it describes. This
does not block normal recovery because the bucket already exists before backend initialization. If the
current domain state object is damaged or deleted, restore a prior S3 object version first, then run
`tofu init -reconfigure -backend-config=env/staging.s3.tfbackend` and a read-only `tofu plan`. Do not
create a replacement bucket. If no state version is recoverable, initialize an empty domain state and
import every existing domain and bucket resource before any apply; the state-bucket addresses are:

```text
aws_s3_bucket.state[0]
aws_s3_bucket_versioning.state[0]
aws_s3_bucket_server_side_encryption_configuration.state[0]
aws_s3_bucket_public_access_block.state[0]
aws_s3_bucket_ownership_controls.state[0]
aws_s3_bucket_lifecycle_configuration.state[0]
```

Each uses the bucket name as its import ID. Review the resulting plan and require zero replacement or
destruction before proceeding.

## After applying — verify

1. **Cert issued**: the apply blocks on `aws_acm_certificate_validation`; if it hangs, check the
   validation CNAME resolved in Cloudflare (a doubly-qualified name is the classic failure — the module
   strips ACM's trailing dot to avoid it).
2. **Authenticated request end to end**: `curl` an authenticated **GET** through the custom domain and
   confirm it matches the raw Function URL (CloudFront must forward the `Authorization` header — the
   managed policy pair does, but verify once).

## Reuse for production / preview

Resource logic is in `../modules/api-domain`, so new environments add only thin per-env config:

- **production** (`api.openom.org`): add `env/production.tfvars` (api_domain, the same openom.org zone
  id) + `env/production.s3.tfbackend` (`key = "domain/production.tfstate"`). Same commands with
  `production` in place of `staging`; leave `manage_state_bucket = false` so staging remains the only
  owner of the shared bucket.
- **preview** (`<pr>.api.dev.openom.org`): does **not** drop in cleanly here — per-PR domains would need
  a workflow holding CloudFront/Cloudflare rights (which this split exists to avoid), and a
  cert+distribution per PR is slow and quota-heavy. When preview lands, the likely shape is a single
  admin-minted `*.api.dev.openom.org` wildcard cert + one CloudFront distribution routing by `Host`
  (a small module extension), or previews simply using the raw Function URL. Not built here.

## Notes

- `PriceClass_100` (NA + EU edges) — cheapest tier covering our users. IPv6 + HTTP/2 on; HTTP/3 is
  deliberately disabled for enterprise-network compatibility.
- Managed **CachingDisabled** + **AllViewerExceptHostHeader** policies: the API is never cached, and
  every viewer header except `Host` is forwarded (a Function URL origin must present its own `Host` for
  TLS/SNI).
- DNS records are **DNS-only** (`proxied = false`): CloudFront terminates TLS with the ACM cert, so it
  must receive the request directly.
- **Origin lock (OAC)**: this root also creates a CloudFront **Origin Access Control** on the origin
  and grants the CloudFront service principal (scoped to this distribution) invoke rights on the
  Function URL. That's additive and harmless while the server root's Function URL is still `NONE`; it
  becomes the *only* allowed caller once the server root flips `lambda_url_auth_type` to `AWS_IAM`. See
  the server root's README "Origin-lock cutover". OAC claims `Authorization`, so clients send the JWT in
  `Openom-Auth` and a body digest in `x-amz-content-sha256`.
- **Staleness**: the domain reads the Function URL live at plan time, so a re-apply always tracks the
  current URL. If the Lambda function is ever destroyed + recreated, re-apply this root to repoint the
  origin.
