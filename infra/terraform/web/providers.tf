# Cloudflare only (Pages + DNS + Zero Trust Access). Reads the token from CLOUDFLARE_API_TOKEN in the
# environment — this root needs a token with Pages Edit + Access (Zero Trust) Edit + DNS Edit, scoped to
# the openom account/zone (more than the DNS-only token the api-domain root uses).
provider "cloudflare" {}
