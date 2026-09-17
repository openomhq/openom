stack_name = "staging"
aws_region = "eu-central-1"

# Same bucket as env/staging.s3.tfbackend (a backend block can't be read as a variable, so the CI
# deploy role's state-access policy needs the name here too).
tf_state_bucket = "openom-tfstate-841547768414"

# github_owner / github_repo / github_environment default to openomhq / openom / staging.

# Staging owns the account-global GitHub OIDC provider; a later production stack in the same account
# must set this false (and look the provider up) to avoid an EntityAlreadyExists collision.
manage_oidc_provider = true
