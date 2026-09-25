# Preview dynamic-origin security spike

## What it is — and is not

This is a temporary, reproducible proof for the load-bearing preview-router mechanism. It verifies that a
CloudFront Function can read a route from KeyValueStore, dynamically select a Lambda Function URL that is not
declared as a distribution origin, and retain Lambda origin access control inherited from a protected base
origin.

It is not the permanent preview environment. It creates no DNS records, certificates, GitHub environments,
Neon branches, R2 objects, Cloudflare Pages projects, or Supabase resources. The final preview infrastructure
must not depend on this Terraform state.

## What the runner proves

- Two `AWS_IAM` Lambda Function URLs can be selected independently through KVS.
- CloudFront signs requests to the dynamically selected Function URL.
- Direct access to either raw Function URL is rejected.
- `Openom-Auth` reaches the origin while OAC owns `Authorization`.
- `x-amz-content-sha256` reaches the origin for empty `GET`/`DELETE` payloads and validates body-bearing
  `POST`/`PUT` requests, matching AWS's Lambda-OAC contract.
- A KVS route can move between origins without a CloudFront distribution deployment.
- A stale KVS ETag is rejected.
- A controlled public probe stands in for the web/custom origin and verifies that the route can explicitly
  disable the protected base origin's OAC. The final Pages origin uses the same unsigned custom-origin path
  without the probe Lambda.

The permanent router therefore needs one standing, protected Lambda Function URL as its inert base origin.
Dynamic API routes replace only that hostname and inherit OAC; app routes replace the hostname and explicitly
disable OAC. CloudFront's JavaScript 2.0 parser also requires `catch (error)`, not optional catch binding.

The probe Lambdas never log or return the bearer value. The protected probes only report whether the expected
fixed credential arrived; the public web probe contains no secrets or application behavior.

## Run

Authenticate the existing administrator profile, then run from the repository root:

```sh
aws sso login --profile openom-admin
export AWS_PROFILE=openom-admin
node scripts/preview-spike.mjs run
```

The runner refuses any AWS account other than the configured openom account, initializes and applies this
local-state root, performs the live assertions, and destroys the stack in a `finally` block. CloudFront
deployment and deletion each take several minutes.

To inspect the Terraform plan without creating resources:

```sh
node scripts/preview-spike.mjs plan
```

If the process or machine stops before automatic cleanup completes, authenticate again and run:

```sh
node scripts/preview-spike.mjs destroy
```

Local Terraform state is intentionally gitignored. Do not delete it until `destroy` succeeds.

## Result

The live proof passed on 2026-09-25 with AWS provider 5.100.0. The runner selected two protected Lambda
origins, rejected both raw URLs, preserved app authentication and payload hashes, changed a route through KVS
without redeploying CloudFront, selected an unsigned web origin, rejected stale KVS writes, and destroyed all
22 temporary resources.
