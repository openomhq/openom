import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from './deployment-config.mjs';

const readWorkflow = (name) => readFileSync(
  new URL(`../.github/workflows/${name}`, import.meta.url),
  'utf8',
);

test('staging component workflows remain independently runnable and become reusable', () => {
  for (const workflow of ['staging.server.yml', 'staging.web.yml', 'staging.smoke.yml']) {
    const source = readWorkflow(workflow);
    assert.match(source, /^  workflow_call:\s*$/m, workflow);
    assert.match(source, /^  workflow_dispatch:\s*$/m, workflow);
  }
  assert.match(readWorkflow('staging.smoke.yml'), /^  schedule:\s*$/m);
});

test('staging deployment orchestrates explicit component modes without deployment logic', () => {
  const source = readWorkflow('staging.deploy.yml');
  const jobs = workflowJobSources(source);

  assert.match(source, /^name: staging\.deploy$/m);
  assert.match(source, /^  workflow_dispatch:\s*$/m);
  assert.match(source, /default: full/);
  assert.match(source, /options:\s*\n\s+- full\s*\n\s+- server\s*\n\s+- web/);
  assert.doesNotMatch(source, /runs-on:|steps:|environment:/);

  assert.match(jobs.server, /uses: \.\/\.github\/workflows\/staging\.server\.yml/);
  assert.match(jobs.server, /id-token: write/);
  assert.match(jobs.server, /secrets: inherit/);

  assert.match(jobs.web, /needs: server/);
  assert.match(jobs.web, /needs\.server\.result == 'success'/);
  assert.match(jobs.web, /uses: \.\/\.github\/workflows\/staging\.web\.yml/);
  assert.doesNotMatch(jobs.web, /id-token: write/);
  assert.match(jobs.web, /secrets: inherit/);

  assert.match(jobs.smoke, /needs: \[server, web\]/);
  assert.match(jobs.smoke, /needs\.server\.result == 'success'/);
  assert.match(jobs.smoke, /needs\.web\.result == 'success'/);
  assert.match(jobs.smoke, /uses: \.\/\.github\/workflows\/staging\.smoke\.yml/);
  assert.match(jobs.smoke, /id-token: write/);
  assert.match(jobs.smoke, /secrets: inherit/);
});
