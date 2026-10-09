# Repository automation tests

Repository-wide policy tests live in `tests/repository/`. Component tests remain with their owners, including
deployment tests in `infra/deployment/` and preview tests in `infra/preview/`.

`tests/run-automation-tests.mjs` reads the tracked `*.test.mjs` files and requires each file to belong to exactly
one suite declared in `tests/automation-suites.mjs`. Run every suite with `task test:automation`, or use the
suite-specific Task commands listed by `task --list`.
