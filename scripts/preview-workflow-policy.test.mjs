import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from './deployment-config.mjs';

const source = readFileSync(new URL('../.github/workflows/preview.deploy.yml', import.meta.url), 'utf8');
const jobs = workflowJobSources(source);

test('preview deployment is manual and cannot run from pull request events', () => {
  assert.match(source, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(source, /^  pull_request(?:_target)?:/m);
  assert.match(source, /^  group: preview-\$\{\{ inputs\.pull_request \}\}\s*$/m);
  assert.match(source, /^      mode:\s*$/m);
  assert.match(jobs.authorize, /--mode "\$\{\{ inputs\.mode \}\}"/);
});

test('authorization and deployment automation are pinned to main', () => {
  assert.match(jobs.authorize, /^          ref: main\s*$/m);
  assert.match(jobs.authorize, /node scripts\/preview-request\.mjs/);
  assert.match(jobs.authorize, /GITHUB_TRIGGERING_ACTOR: \$\{\{ github\.triggering_actor \}\}/);
  assert.match(jobs.deploy, /^          ref: main\s*$/m);
  assert.match(jobs.deploy, /^      name: preview\s*$/m);
  assert.match(jobs.deploy, /^      deployment: false\s*$/m);
});

test('pull request code runs only in the unprivileged build job', () => {
  assert.match(jobs.build, /ref: \$\{\{ needs\.authorize\.outputs\.commit_sha \}\}/);
  assert.doesNotMatch(jobs.build, /environment:/);
  assert.doesNotMatch(jobs.build, /id-token: write/);
  assert.doesNotMatch(jobs.build, /\$\{\{\s*(?:secrets|vars)\./);
  assert.doesNotMatch(jobs.deploy, /ref: \$\{\{ needs\.authorize\.outputs\.commit_sha \}\}/);
  assert.doesNotMatch(jobs.deploy, /(?:node|bash|sh)\s+_site/);
  assert.doesNotMatch(jobs.deploy, /working-directory:\s*_site/);
  assert.match(jobs.build, /find _site -mindepth 1 ! -type f ! -type d/);
  assert.match(jobs.deploy, /find _site -mindepth 1 ! -type f ! -type d/);
});

test('only the trusted deploy job receives OIDC and deployment write access', () => {
  assert.doesNotMatch(source.slice(0, source.indexOf('\njobs:')), /id-token: write/);
  assert.doesNotMatch(jobs.authorize, /id-token: write|deployments: write/);
  assert.doesNotMatch(jobs.build, /id-token: write|deployments: write/);
  assert.match(jobs.deploy, /^      id-token: write\s*$/m);
  assert.match(jobs.deploy, /^      deployments: write\s*$/m);
  assert.doesNotMatch(source, /pull-requests: write|issues: write/);
});
