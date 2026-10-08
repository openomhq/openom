import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
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

test('preview instructions are folded into the trusted cleanup chain', () => {
  assert.equal(
    existsSync(new URL('../.github/workflows/preview.instructions.yml', import.meta.url)),
    false,
  );
  assert.match(lifecycleSource, /^  pull_request:\s*$/m);
  assert.match(lifecycleSource, /^      - labeled\s*$/m);
  assert.doesNotMatch(lifecycleSource, /pull_request_target/);
  assert.match(jobs.instructions, /needs\.resolve\.outputs\.desired_mode != 'none'/);
  assert.match(
    jobs.instructions,
    /PREVIEW_PULL_REQUEST: \$\{\{ needs\.resolve\.outputs\.pull_request_number \}\}/,
  );
});

test('privileged instruction comments execute only trusted main code', () => {
  assert.match(jobs.instructions, /^      pull-requests: write\s*$/m);
  assert.doesNotMatch(jobs.instructions, /^      issues: write\s*$/m);
  assert.match(jobs.instructions, /^          ref: main\s*$/m);
  assert.match(jobs.instructions, /persist-credentials: false/);
  assert.doesNotMatch(
    jobs.instructions,
    /pull_request\.head|secrets\.|vars\.|id-token:|deployments: write/,
  );
  assert.match(jobs.instructions, /node scripts\/preview-instructions\.mjs/);
});

test('instruction comments serialize on the server-resolved pull request', () => {
  assert.match(
    jobs.instructions,
    /^      group: preview-instructions-\$\{\{ needs\.resolve\.outputs\.pull_request_number \}\}\s*$/m,
  );
});
