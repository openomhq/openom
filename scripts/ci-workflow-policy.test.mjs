import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { workflowJobSources } from './deployment-config.mjs';

const readWorkflow = (name) => readFileSync(
  new URL(`../.github/workflows/${name}`, import.meta.url),
  'utf8',
);

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

test('desktop workflow keeps a stable required gate and reserves the matrix for final acceptance', () => {
  const source = readWorkflow('ci.desktop.yml');
  const jobs = workflowJobSources(source);

  assert.match(jobs.classify, /node scripts\/ci-scope\.mjs --github-output/);
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
