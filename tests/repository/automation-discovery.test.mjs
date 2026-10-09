import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { automationSuites, classifyAutomationTests } from '../automation-suites.mjs';

const taskfile = fs.readFileSync(new URL('../../Taskfile.yml', import.meta.url), 'utf8');

test('automation tests belong to exactly one suite', () => {
  const classification = classifyAutomationTests([
    'tests/repository/example.test.mjs',
    'infra/deployment/example.test.mjs',
    'infra/preview/example.test.mjs',
    'infra/terraform/preview/tests/example.test.mjs',
    'infra/terraform/tests/example.test.mjs',
  ]);

  assert.deepEqual(classification.unassigned, []);
  assert.deepEqual(classification.duplicated, []);
  assert.deepEqual(
    Object.fromEntries(classification.assigned),
    {
      repository: ['tests/repository/example.test.mjs'],
      deployment: ['infra/deployment/example.test.mjs'],
      preview: [
        'infra/preview/example.test.mjs',
        'infra/terraform/preview/tests/example.test.mjs',
      ],
      terraform: ['infra/terraform/tests/example.test.mjs'],
    },
  );
});

test('automation discovery rejects missing and overlapping suite ownership', () => {
  const classification = classifyAutomationTests(
    ['unknown/example.test.mjs', 'owned/example.test.mjs'],
    [
      { name: 'first', roots: ['owned/'] },
      { name: 'second', roots: ['owned/example.'] },
    ],
  );

  assert.deepEqual(classification.unassigned, ['unknown/example.test.mjs']);
  assert.deepEqual(classification.duplicated, [
    { file: 'owned/example.test.mjs', suites: ['first', 'second'] },
  ]);
});

test('Taskfile exposes every declared suite and the aggregate suite', () => {
  for (const { name } of automationSuites) {
    assert.match(taskfile, new RegExp(`^  test:${name}:`, 'mu'));
    assert.match(taskfile, new RegExp(`node tests/run-automation-tests\\.mjs ${name}`, 'u'));
  }
  assert.match(taskfile, /^  test:automation:/mu);
  assert.match(taskfile, /node tests\/run-automation-tests\.mjs\s*$/mu);
});
