import assert from 'node:assert/strict';
import test from 'node:test';

import { isDocumentationPath, requiresDesktopValidation } from './ci-scope.mjs';

test('documentation paths do not require desktop validation', () => {
  for (const file of [
    'README.md',
    'CONTRIBUTING.md',
    'docs/operations/preview.md',
    'plan/infra.preview.md',
    '.github/ISSUE_TEMPLATE/bug.md',
  ]) {
    assert.equal(isDocumentationPath(file), true, file);
  }
  assert.equal(requiresDesktopValidation(['README.md', 'docs/architecture.md']), false);
});

test('code, configuration, and workflow changes require desktop validation', () => {
  for (const file of [
    'Cargo.toml',
    'apps/src-tauri/src/lib.rs',
    'packages/openom-app-core/src/lib.rs',
    '.github/workflows/ci.desktop.yml',
    'scripts/cargo.mjs',
  ]) {
    assert.equal(isDocumentationPath(file), false, file);
    assert.equal(requiresDesktopValidation([file]), true, file);
  }
});

test('empty or mixed changes fail closed', () => {
  assert.equal(requiresDesktopValidation([]), true);
  assert.equal(requiresDesktopValidation(['README.md', 'openom/src/lib.rs']), true);
});
