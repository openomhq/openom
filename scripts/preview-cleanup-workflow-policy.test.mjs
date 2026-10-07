import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from './deployment-config.mjs';

const cleanupSource = readFileSync(
  new URL('../.github/workflows/preview.cleanup.yml', import.meta.url),
  'utf8',
);
const lifecycleSource = readFileSync(
  new URL('../.github/workflows/preview.lifecycle.yml', import.meta.url),
  'utf8',
);
const jobs = workflowJobSources(cleanupSource);

test('unprivileged pull-request lifecycle events carry no code or credentials', () => {
  assert.match(lifecycleSource, /^  pull_request:\s*$/m);
  assert.match(lifecycleSource, /^  workflow_dispatch:\s*$/m);
  assert.match(
    lifecycleSource,
    /^run-name: 'preview lifecycle for PR #\$\{\{ github\.event\.pull_request\.number \|\| inputs\.pull_request \}\}'\s*$/m,
  );
  assert.match(lifecycleSource, /^permissions: \{\}\s*$/m);
  assert.doesNotMatch(lifecycleSource, /actions\/checkout|secrets\.|vars\.|id-token:/);
});

test('privileged cleanup runs only from trusted workflow-run, schedule, or manual events', () => {
  assert.match(cleanupSource, /^  workflow_run:\s*$/m);
  assert.match(cleanupSource, /^  schedule:\s*$/m);
  assert.match(cleanupSource, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(cleanupSource, /^  pull_request(?:_target)?:/m);
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
  assert.match(jobs.cleanup, /node scripts\/preview-cleanup\.mjs cleanup/);
  assert.match(jobs.cleanup, /node scripts\/preview-cleanup\.mjs janitor/);
  assert.doesNotMatch(jobs.cleanup, /issues: write|preview-cleanup-comment/);
});

test('cleanup comments run separately with only pull-request-write privilege', () => {
  assert.match(
    jobs.comment,
    /^    if: needs\.resolve\.outputs\.mode == 'cleanup' && needs\.cleanup\.result == 'success'\s*$/m,
  );
  assert.match(jobs.comment, /^      contents: read\s*$/m);
  assert.match(jobs.comment, /^      pull-requests: write\s*$/m);
  assert.doesNotMatch(jobs.comment, /issues: write/);
  assert.doesNotMatch(jobs.comment, /environment:|id-token: write|deployments: write|secrets\.|vars\./);
  assert.match(jobs.comment, /^          ref: main\s*$/m);
  assert.match(jobs.comment, /node scripts\/preview-cleanup-comment\.mjs/);
});
