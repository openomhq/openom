import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from '../deployment/deployment-config.mjs';

const source = readFileSync(new URL('../../.github/workflows/preview.deploy.yml', import.meta.url), 'utf8');
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
  assert.match(jobs.authorize, /node infra\/preview\/preview-request\.mjs/);
  assert.match(jobs.authorize, /GITHUB_TRIGGERING_ACTOR: \$\{\{ github\.triggering_actor \}\}/);
  for (const jobName of ['database', 'deploy-web', 'deploy-full']) {
    assert.match(jobs[jobName], /^          ref: main\s*$/m);
    assert.match(jobs[jobName], /^      name: preview\s*$/m);
    assert.match(jobs[jobName], /^      deployment: false\s*$/m);
  }
});

test('web deployment refuses an implicit full-stack downgrade before publishing Pages', () => {
  const guard = jobs['deploy-web'].indexOf('name: Refuse an implicit full-stack downgrade');
  const pages = jobs['deploy-web'].indexOf('name: Deploy the immutable Pages artifact');
  assert.ok(guard !== -1 && guard < pages);
  assert.match(jobs['deploy-web'], /node infra\/preview\/preview-route\.mjs assert-web/);
});

test('pull request code runs only in the unprivileged build job', () => {
  assert.match(jobs.build, /ref: \$\{\{ needs\.authorize\.outputs\.commit_sha \}\}/);
  assert.doesNotMatch(jobs.build, /environment:/);
  assert.doesNotMatch(jobs.build, /id-token: write/);
  assert.doesNotMatch(jobs.build, /\$\{\{\s*(?:secrets|vars)\./);
  const rustCache = jobs.build.match(
    /uses: Swatinem\/rust-cache@[\s\S]*?(?=\n\s{6}- |$)/,
  )?.[0] ?? '';
  assert.match(rustCache, /^          save-if: false\s*$/m);
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
      /node infra\/preview\/preview-deployment\.mjs[\s\S]*?(?=\n\s{6}- name:|$)/,
    )?.[0] ?? '';
    assert.match(
      jobs[jobName],
      /PREVIEW_SOURCE_BRANCH: \$\{\{ needs\.authorize\.outputs\.source_branch \}\}/,
    );
    assert.match(publish, /--source-branch "\$PREVIEW_SOURCE_BRANCH"/);
  }
});

test('validated branch names enter privileged shells only through environment variables', () => {
  assert.doesNotMatch(
    source,
    /--(?:branch|source-branch)\s+["']?\$\{\{\s*needs\.authorize\.outputs\.source_branch/,
  );
  for (const jobName of ['database', 'deploy-web', 'deploy-full']) {
    const branchSteps = jobs[jobName]
      .split(/(?=^      - )/m)
      .filter((step) => step.includes('$PREVIEW_SOURCE_BRANCH'));
    assert.notEqual(branchSteps.length, 0);
    for (const step of branchSteps) {
      assert.match(
        step,
        /PREVIEW_SOURCE_BRANCH: \$\{\{ needs\.authorize\.outputs\.source_branch \}\}/,
      );
    }
  }
});

test('full acceptance drops AWS credentials before deployed pull-request code runs', () => {
  const storageCheck = jobs['deploy-full'].indexOf('name: Verify preview object-store access');
  const lambdaReconcile = jobs['deploy-full'].indexOf('name: Reconcile the protected Lambda');
  assert.ok(storageCheck !== -1 && storageCheck < lambdaReconcile);
  assert.match(jobs['deploy-full'], /key="previews\/\$\{PREVIEW_SLUG\}\/acceptance\/storage-\$\{GITHUB_RUN_ID\}\.txt"/);
  assert.match(jobs['deploy-full'], /s3api put-object/);
  assert.match(jobs['deploy-full'], /s3api get-object/);
  assert.match(jobs['deploy-full'], /s3api delete-object/);
  assert.match(jobs['deploy-full'], /OPENOM_DEPLOYED_AUTH_ACCEPTANCE: '1'/);
  assert.match(jobs['deploy-full'], /AWS_ACCESS_KEY_ID: ''/);
  assert.match(jobs['deploy-full'], /AWS_SECRET_ACCESS_KEY: ''/);
  assert.match(jobs['deploy-full'], /AWS_SESSION_TOKEN: ''/);
});
