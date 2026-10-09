import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from '../../infra/deployment/deployment-config.mjs';

const readWorkflow = (name) => readFileSync(
  new URL(`../../.github/workflows/${name}`, import.meta.url),
  'utf8',
);

const workflowNames = readdirSync(new URL('../../.github/workflows/', import.meta.url))
  .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
  .sort();

test('third-party actions use immutable commit SHAs', () => {
  const violations = [];

  for (const workflowName of workflowNames) {
    const source = readWorkflow(workflowName);
    for (const match of source.matchAll(/^\s*(?:-\s*)?uses:\s*["']?([^\s#"']+)["']?/gm)) {
      const action = match[1];
      const line = source.slice(0, match.index).split('\n').length;
      const isLocalAction = action.startsWith('./');
      const isCommitPinned = /@[0-9a-f]{40}$/.test(action);
      const isDigestPinnedContainer = /^docker:\/\/[^\s]+@sha256:[0-9a-f]{64}$/.test(action);

      if (!isLocalAction && !isCommitPinned && !isDigestPinnedContainer) {
        violations.push(`${workflowName}:${line}: ${action}`);
      }
    }
  }

  assert.deepEqual(
    violations,
    [],
    `third-party actions must use full commit SHAs:\n${violations.join('\n')}`,
  );
});

for (const workflow of ['ci.desktop.yml', 'ci.server.yml', 'ci.web.yml']) {
  test(`${workflow} validates pull requests and merge groups without repeating on main`, () => {
    const source = readWorkflow(workflow);
    assert.match(source, /^  pull_request:\s*$/m);
    assert.match(source, /^  merge_group:\s*$/m);
    assert.match(source, /^    types: \[checks_requested\]\s*$/m);
    assert.match(source, /^    branches: \[main\]\s*$/m);
    assert.match(source, /^  workflow_dispatch:\s*$/m);
    assert.doesNotMatch(source, /^  push:\s*$/m);
  });
}


test('main workflow runs quick checks only for administrator bypass pushes', () => {
  const source = readWorkflow('ci.main.yml');
  const jobs = workflowJobSources(source);

  assert.match(source, /^  push:\s*\n\s+branches: \[main\]\s*$/m);
  assert.doesNotMatch(source, /^  pull_request:\s*$/m);
  assert.doesNotMatch(source, /^  merge_group:\s*$/m);
  assert.match(jobs.detect, /commits\/\$\{GITHUB_SHA\}\/pulls/);
  assert.match(jobs.detect, /select\(\.merged_at != null and \.base\.ref == "main"\)/);
  assert.match(jobs.detect, /node scripts\/ci\/ci-main-scope\.mjs --github-output/);
  assert.match(jobs.quick, /needs\.detect\.outputs\.bypass_push == 'true'/);
  assert.match(jobs.quick, /needs\.detect\.outputs\.quick_required == 'true'/);
  assert.match(jobs.quick, /go-task\/setup-task@[0-9a-f]{40}/);
  assert.ok(
    jobs.quick.indexOf('go-task/setup-task@') < jobs.quick.indexOf('task --list'),
    'quick must install Task before invoking it',
  );
  assert.doesNotMatch(jobs.detect, /go-task\/setup-task@/);
  assert.match(jobs.rust, /needs\.detect\.outputs\.bypass_push == 'true'/);
  assert.match(jobs.rust, /needs\.detect\.outputs\.rust_required == 'true'/);
  assert.match(jobs.rust, /cargo fmt --all --check/);
  assert.match(jobs.rust, /cargo check --workspace --exclude openom-tauri --all-features --locked/);
  assert.doesNotMatch(source, /cargo clippy|cargo test|tauri build|docker compose/);
});

test('desktop workflow keeps a stable required gate and reserves the matrix for final acceptance', () => {
  const source = readWorkflow('ci.desktop.yml');
  const jobs = workflowJobSources(source);

  assert.match(jobs.classify, /node scripts\/ci\/ci-scope\.mjs --github-output/);
  assert.match(jobs.clippy, /needs: classify/);
  assert.match(jobs.clippy, /needs\.classify\.outputs\.desktop_required == 'true'/);
  assert.match(jobs.build, /github\.event_name != 'pull_request'/);
  assert.match(jobs.build, /matrix:\s*\n\s+os: \[windows-latest, macos-latest, ubuntu-latest\]/);
  assert.match(jobs['desktop-gate'], /^    name: desktop-gate\s*$/m);
  assert.match(jobs['desktop-gate'], /needs: \[classify, clippy, build\]/);
  assert.match(jobs['desktop-gate'], /if: always\(\)/);
  assert.match(jobs['desktop-gate'], /CLIPPY_RESULT: \$\{\{ needs\.clippy\.result \}\}/);
  assert.match(jobs['desktop-gate'], /BUILD_RESULT: \$\{\{ needs\.build\.result \}\}/);
});
