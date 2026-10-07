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
  for (const jobName of ['database', 'deploy-web', 'deploy-full']) {
    assert.match(jobs[jobName], /^          ref: main\s*$/m);
    assert.match(jobs[jobName], /^      name: preview\s*$/m);
    assert.match(jobs[jobName], /^      deployment: false\s*$/m);
  }
});

test('pull request code runs only in the unprivileged build job', () => {
  assert.match(jobs.build, /ref: \$\{\{ needs\.authorize\.outputs\.commit_sha \}\}/);
  assert.doesNotMatch(jobs.build, /environment:/);
  assert.doesNotMatch(jobs.build, /id-token: write/);
  assert.doesNotMatch(jobs.build, /\$\{\{\s*(?:secrets|vars)\./);
  for (const jobName of ['database', 'deploy-web', 'deploy-full']) {
    assert.doesNotMatch(jobs[jobName], /ref: \$\{\{ needs\.authorize\.outputs\.commit_sha \}\}/);
    assert.doesNotMatch(jobs[jobName], /(?:node|bash|sh)\s+_site/);
    assert.doesNotMatch(jobs[jobName], /working-directory:\s*_site/);
  }
  assert.match(jobs.build, /find _site -mindepth 1 ! -type f ! -type d/);
  assert.match(jobs['deploy-web'], /find _site -mindepth 1 ! -type f ! -type d/);
  assert.match(jobs['deploy-full'], /find _site -mindepth 1 ! -type f ! -type d/);
  assert.match(jobs.database, /Apply pull-request migrations with database-only credentials/);
  assert.doesNotMatch(
    jobs.database.match(/- name: Apply pull-request migrations[\s\S]*?(?=\n\s{6}- |$)/)?.[0] ?? '',
    /NEON_API_KEY|SUPABASE_TEST_PASSWORD|id-token/,
  );
});

test('only trusted deploy jobs receive OIDC and deployment write access', () => {
  assert.doesNotMatch(source.slice(0, source.indexOf('\njobs:')), /id-token: write/);
  assert.doesNotMatch(jobs.authorize, /id-token: write|deployments: write/);
  assert.doesNotMatch(jobs.build, /id-token: write|deployments: write/);
  assert.doesNotMatch(jobs.database, /id-token: write|deployments: write/);
  for (const jobName of ['deploy-web', 'deploy-full']) {
    assert.match(jobs[jobName], /^      id-token: write\s*$/m);
    assert.match(jobs[jobName], /^      deployments: write\s*$/m);
  }
  assert.doesNotMatch(source, /pull-requests: write|issues: write/);
});

test('deployment inventory records the canonical source branch', () => {
  for (const jobName of ['deploy-web', 'deploy-full']) {
    const publish = jobs[jobName].match(
      /node scripts\/preview-deployment\.mjs[\s\S]*?(?=\n\s{6}- name:|$)/,
    )?.[0] ?? '';
    assert.match(publish, /--source-branch "\$\{\{ needs\.authorize\.outputs\.source_branch \}\}"/);
  }
});

test('full acceptance drops AWS credentials before deployed pull-request code runs', () => {
  assert.match(jobs['deploy-full'], /OPENOM_DEPLOYED_AUTH_ACCEPTANCE: '1'/);
  assert.match(jobs['deploy-full'], /AWS_ACCESS_KEY_ID: ''/);
  assert.match(jobs['deploy-full'], /AWS_SECRET_ACCESS_KEY: ''/);
  assert.match(jobs['deploy-full'], /AWS_SESSION_TOKEN: ''/);
});
