import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from './deployment-config.mjs';

const source = readFileSync(
  new URL('../.github/workflows/preview.instructions.yml', import.meta.url),
  'utf8',
);
const jobs = workflowJobSources(source);

test('preview instructions use trusted label and manual triggers', () => {
  assert.match(source, /^  pull_request_target:\s*$/m);
  assert.match(source, /^    types: \[labeled\]\s*$/m);
  assert.match(source, /^    branches: \[main\]\s*$/m);
  assert.match(source, /^  workflow_dispatch:\s*$/m);
  assert.match(jobs.comment, /github\.event\.label\.name == 'preview'/);
  assert.match(jobs.comment, /github\.event\.label\.name == 'full-preview'/);
  assert.match(
    jobs.comment,
    /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/,
  );
  assert.match(jobs.comment, /github\.ref == 'refs\/heads\/main'/);
});

test('privileged comment automation executes only trusted main code', () => {
  assert.match(source, /^permissions: \{\}\s*$/m);
  assert.match(jobs.comment, /^      pull-requests: write\s*$/m);
  assert.doesNotMatch(jobs.comment, /^      issues: write\s*$/m);
  assert.match(jobs.comment, /^          ref: main\s*$/m);
  assert.match(jobs.comment, /persist-credentials: false/);
  assert.doesNotMatch(
    jobs.comment,
    /ref:\s*\$\{\{[^\n]*pull_request\.head|repository:\s*\$\{\{[^\n]*pull_request\.head|secrets\.|vars\.|id-token:|deployments: write/,
  );
  assert.match(jobs.comment, /node scripts\/preview-instructions\.mjs/);
});

test('manual and label runs share one serialized pull-request identity', () => {
  assert.match(
    source,
    /^  group: preview-instructions-\$\{\{ github\.event\.pull_request\.number \|\| inputs\.pull_request \}\}\s*$/m,
  );
  assert.match(
    jobs.comment,
    /PULL_REQUEST_NUMBER: \$\{\{ github\.event\.pull_request\.number \|\| inputs\.pull_request \}\}/,
  );
});
