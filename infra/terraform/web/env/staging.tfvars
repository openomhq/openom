stack_name         = "staging"
web_domain         = "app.staging.openom.org"
pages_project_name = "openom-staging-web"

cloudflare_zone_id    = "09079b9bd72727ab61ab64db15b42f30"
cloudflare_account_id = "79f9c0ea8f2aac18cc58389d42b32784"

# The staging login gate is a shared password (a Pages Function), NOT managed here — it's the GitHub
# secret STAGING_APP_GATE_PASSWORD, synced to the Pages project by the staging.web workflow.
