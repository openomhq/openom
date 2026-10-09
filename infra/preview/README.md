# Preview automation

## What it is — and is not

This component owns the trusted automation for pull-request preview deployment, routing, lifecycle
reconciliation, and cleanup. It works with the shared standing infrastructure in
`infra/terraform/preview`, but it does not provision that platform or contain application code.

The privileged workflows invoke these modules directly so their inputs and trust boundaries remain
visible in the workflow definitions. Tests stay beside the automation they protect; router and sink
tests stay with their OpenTofu root under `infra/terraform/preview/tests`.

Run the complete preview suite from the repository root:

```sh
task test:preview
```
