# Deployment configuration

## What it is — and is not

This component validates the repository's deployment-environment contract against GitHub workflow
jobs. It keeps required variables, secrets, privileges, and validation steps synchronized with
`contracts/deployment-environments.json`.

It does not deploy infrastructure or applications. Workflows call the validator before privileged
deployment steps, and CI checks the complete contract with:

```sh
node infra/deployment/deployment-config.mjs --check
node --test infra/deployment/deployment-config.test.mjs
```
