stack_name         = "staging"
api_domain         = "api.staging.openom.org"
cloudflare_zone_id = "09079b9bd72727ab61ab64db15b42f30"

# Region the staging Lambda runs in (to read its Function URL as the CloudFront origin).
app_region = "eu-central-1"

# Shared remote-state storage. Managed from this admin-only root so the CI role cannot mutate it.
manage_state_bucket = true
state_bucket_name   = "openom-tfstate-841547768414"
state_bucket_region = "eu-central-1"
