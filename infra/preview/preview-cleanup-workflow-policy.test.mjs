import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from '../deployment/deployment-config.mjs';

const cleanupSource = readFileSync(
  new URL('../../.github/workflows/preview.cleanup.yml', import.meta.url),
  'utf8',
);
const lifecycleSource = readFileSync(
  new URL('../../.github/workflows/preview.lifecycle.yml', import.meta.url),
  'utf8',
);
const jobs = workflowJobSources(cleanupSource);
const lifecycleJobs = workflowJobSources(lifecycleSource);

test('untrusted pull-request lifecycle signals carry no identity, code, or credentials', () => {
  assert.match(lifecycleSource, /^  pull_request:\s*$/m);
  assert.doesNotMatch(lifecycleSource, /^  pull_request_target:\s*$/m);
  assert.doesNotMatch(lifecycleSource, /^  workflow_dispatch:\s*$/m);
  assert.match(lifecycleSource, /^      - closed\s*$/m);
  assert.match(lifecycleSource, /^      - labeled\s*$/m);
  assert.match(lifecycleSource, /^      - unlabeled\s*$/m);
  assert.match(lifecycleSource, /^run-name: preview lifecycle signal\s*$/m);
  assert.match(lifecycleSource, /^permissions: \{\}\s*$/m);
  assert.doesNotMatch(lifecycleJobs.signal, /actions\/checkout|secrets\.|vars\.|id-token:/);
  assert.doesNotMatch(lifecycleJobs.signal, /\$\{\{/);
});

test('privileged cleanup runs only from trusted workflow-run, schedule, or manual events', () => {
  assert.match(cleanupSource, /^  workflow_run:\s*$/m);
  assert.match(cleanupSource, /^  schedule:\s*$/m);
  assert.match(cleanupSource, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(cleanupSource, /^  pull_request(?:_target)?:/m);
  assert.doesNotMatch(cleanupSource, /display_title/);
  assert.match(jobs.resolve, /^          ref: main\s*$/m);
  assert.match(jobs.cleanup, /^          ref: main\s*$/m);
  assert.doesNotMatch(jobs.resolve, /environment:|id-token: write|deployments: write/);
});

test('cleanup serializes with the matching preview and scopes privilege to deletion', () => {
  assert.match(
    jobs.cleanup,
    /^      group: preview-\$\{\{ needs\.resolve\.outputs\.pull_request_number \|\| 'janitor' \}\}\s*$/m,
  );
  assert.match(jobs.cleanup, /^      name: preview\s*$/m);
  assert.match(jobs.cleanup, /^      deployment: false\s*$/m);
  assert.match(jobs.cleanup, /^      id-token: write\s*$/m);
  assert.match(jobs.cleanup, /^      deployments: write\s*$/m);
  assert.doesNotMatch(jobs.resolve, /pull-requests: write|issues: write/);
  assert.match(jobs.cleanup, /node infra\/preview\/preview-cleanup\.mjs cleanup/);
  assert.match(jobs.cleanup, /node infra\/preview\/preview-cleanup\.mjs reconcile/);
  assert.match(jobs.cleanup, /node infra\/preview\/preview-cleanup\.mjs janitor/);
  const cleanupStep = jobs.cleanup
    .split(/(?=^      - )/m)
    .find((step) => step.includes('--branch "$PREVIEW_SOURCE_BRANCH"')) ?? '';
  assert.match(
    cleanupStep,
    /PREVIEW_SOURCE_BRANCH: \$\{\{ needs\.resolve\.outputs\.source_branch \}\}/,
  );
  assert.match(cleanupStep, /--branch "\$PREVIEW_SOURCE_BRANCH"/);
  assert.doesNotMatch(
    cleanupSource,
    /--branch\s+["']?\$\{\{\s*needs\.resolve\.outputs\.source_branch/,
  );
  assert.doesNotMatch(jobs.cleanup, /issues: write|preview-cleanup-comment/);
});

test('cleanup comments run separately with only pull-request-write privilege', () => {
  assert.match(
    jobs.comment,
    /^    if: needs\.cleanup\.result == 'success' && needs\.cleanup\.outputs\.comments != '\[\]'\s*$/m,
  );
  assert.match(jobs.comment, /^      contents: read\s*$/m);
  assert.match(jobs.comment, /^      pull-requests: write\s*$/m);
  assert.doesNotMatch(jobs.comment, /issues: write/);
  assert.doesNotMatch(jobs.comment, /environment:|id-token: write|deployments: write|secrets\.|vars\./);
  assert.match(jobs.comment, /^          ref: main\s*$/m);
  assert.match(jobs.comment, /PREVIEW_CLEANUPS: \$\{\{ needs\.cleanup\.outputs\.comments \}\}/);
  assert.match(jobs.comment, /node infra\/preview\/preview-cleanup-comment\.mjs/);
});

test('deployment instructions run separately with only pull-request-write privilege', () => {
  assert.match(
    jobs.instructions,
    /^    if: needs\.resolve\.outputs\.mode == 'reconcile' && needs\.resolve\.outputs\.desired_mode != 'none'\s*$/m,
  );
  assert.match(jobs.instructions, /^      pull-requests: write\s*$/m);
  assert.doesNotMatch(jobs.instructions, /environment:|id-token: write|deployments: write|secrets\.|vars\./);
  assert.match(jobs.instructions, /^          ref: main\s*$/m);
  assert.match(jobs.instructions, /node infra\/preview\/preview-instructions\.mjs/);
});
