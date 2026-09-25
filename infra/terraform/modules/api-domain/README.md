# module: api-domain

CloudFront + a DNS-validated ACM cert + Cloudflare DNS in front of a Lambda **Function URL**. Reusable
across environments — staging, production, and per-PR preview envs each instantiate it with a different
`api_domain` / `function_url_host`.

Viewer traffic supports HTTP/2 (with HTTP/1.1 fallback). HTTP/3 is deliberately disabled because QUIC
over UDP/443 is commonly blocked by enterprise networks, and some managed Chromium clients fail instead
of falling back cleanly. The modern `TLSv1.2_2021` security policy remains unchanged.

## Inputs

| name                 | required | notes                                                        |
| -------------------- | -------- | ------------------------------------------------------------ |
| `api_domain`         | yes      | FQDN to serve (e.g. `api.staging.openom.org`, `api.openom.org`) |
| `cloudflare_zone_id` | yes      | zone owning the DNS records (the `openom.org` zone)          |
| `function_url_host`  | yes      | Function URL host, no scheme/trailing slash (the origin)     |
| `comment`            | no       | CloudFront console comment                                   |
| `price_class`        | no       | defaults to `PriceClass_100`                                 |

## Outputs

`api_custom_url`, `cloudfront_domain`, `certificate_arn`.

## Provider requirement

The module uses the caller's `aws` provider **as-is** — that provider MUST be configured for
**us-east-1** (CloudFront viewer certs are only issuable there). A caller whose default `aws` provider is
another region should pass a us-east-1 alias:

```hcl
module "api_domain" {
  source    = "../modules/api-domain"
  providers = { aws = aws.us_east_1 }
  ...
}
```

The dedicated domain roots here set their default `aws` provider to us-east-1, so they call the module
with no explicit `providers` block.
