# Contributing to openom

Thank you for helping build openom. The project is pre-release, so prefer clean designs over compatibility
machinery for users or data that do not yet exist. Security, privacy, and local-first behavior remain hard
requirements even while interfaces are allowed to change.

## Working agreement

Substantive work follows an issue-first pull-request workflow:

1. Select or create a concrete task.
2. Branch from current `main`.
3. Implement and validate one coherent change.
4. Open a pull request against `main`.
5. Request a hosted preview only when it adds review value.
6. Merge after review and acceptance, then close the task and remove the branch.

`main` is currently the only authoritative branch. Do not target or document a `develop` branch unless the
repository adopts one later.

## Choose an issue

Maintainer work starts from a leaf YouTrack task such as `OPE-641`, not an epic or initiative. Before coding:

- Make the title imperative and the description specific enough to define completion.
- Assign the task and place it in the correct area.
- Resolve blocking dependencies or state explicitly which independent slice is being implemented.
- Move its Stage to `Develop`; leave its State unresolved while work continues.

External contributors do not need tracker administration access before starting a conversation. Open a GitHub
issue or discuss the change with a maintainer. A maintainer will create or associate the YouTrack task before a
substantive pull request is merged.

## Create the branch

Start from an up-to-date, clean `main`:

```sh
git switch main
git pull --ff-only
git switch -c feat/ope-123
```

Same-repository branches use lowercase `<kind>/ope-<task>[/<short-description>]` names. Prefer the short form
because it becomes the human-facing preview hostname. Add a short suffix only when it materially helps:

```text
feat/ope-123
feat/ope-123/user-auth
fix/ope-456/token-ttl
docs/ope-641
```

Common kinds are `feat`, `fix`, `docs`, `refactor`, `test`, and `chore`. Fork contributors may use any clear
branch name; the maintainer-owned integration branch supplies the repository convention when needed. Avoid
renaming a branch after a preview has been deployed because the normalized branch name identifies its URL and
ephemeral resources.

## Implement and validate

- Keep the change focused on its task; report unrelated findings separately.
- Follow the applicable `AGENTS.md` files and update package or app README contracts with behavioral changes.
- Prefer the repository's Task commands, then its existing runners and Docker tooling, over ad hoc host commands.
- Start with focused tests, then run the relevant broader checks before requesting review.
- Never commit credentials, generated local state, or provider output containing secrets.

Rust changes must satisfy the crate-specific tests and all-feature Clippy guidance in `AGENTS.md`. Web changes
must preserve the buildless runtime and pass the repository's JavaScript type, unit, and browser checks that
cover the changed surface.

## Commit

Use the repository's Conventional Commit format and reference the leaf task in the footer:

```text
feat(app): expose account sync status

Refs: OPE-123
```

Use the enclosing component as the scope, imperative mood, a lowercase summary, and no trailing period. Larger
changes may use multiple meaningful commits and explanatory bodies. Do not reference an epic or initiative in
place of the task that the commit implements.

## Open the pull request

Push the branch and open a pull request against `main`. A useful pull-request description contains:

- **Summary:** what changed and why.
- **Validation:** exact automated and manual checks performed.
- **Operational impact:** deployment, configuration, security, or follow-up requirements.
- **Tracker:** the leaf issue identifier, for example `Refs: OPE-123`.

Use a draft pull request while the design or implementation is incomplete. Move the task to `Review` when it is
ready for review and to `Test` while its automated and manual acceptance is being completed. Pull-request code
must never be given deployment secrets merely to make a check pass.

Every pull-request update receives the fast web, server, and relevant Linux Clippy checks. When the final
candidate is ready, add it to the `main` merge queue; the queue runs the full Windows, macOS, and Linux desktop
matrix against the candidate combined with current `main`. That matrix is not repeated after merge. A later
commit invalidates the candidate and requires fresh queue acceptance.

## Request a preview

Hosted previews are explicit review tools, not an automatic consequence of opening or updating a pull request.
For an open same-repository pull request:

1. A maintainer adds the `preview` label.
2. A maintainer manually runs the `preview.deploy` workflow from `main` with the pull-request number.
3. The workflow verifies the triggering maintainer, pins the current pull-request SHA, and builds it without
   credentials.
4. The workflow summary and GitHub deployment record expose the branch-derived app URL.

Later commits do not redeploy automatically; dispatch the workflow again when the new head is ready. Fork pull
requests receive ordinary unprivileged CI but no hosted preview by default. Web previews are local-first and
their API URL remains unprovisioned until the separately approved full-stack preview path is implemented.
Preview cleanup is currently tracked by OPE-638.

## Merge and finish

Merge only through the `main` merge queue after required CI is green, review findings are resolved, and
task-specific acceptance passes. For changes requiring staging verification, move the task to `Staging` after
merge and complete that verification before resolution. Otherwise resolve the task when the merged behavior is
accepted. Move completed work to `Done`, set its State to `Fixed`, and delete the merged branch.

If a pull request is abandoned, close it, remove any preview approval, and update the task instead of leaving
its status ambiguous.
