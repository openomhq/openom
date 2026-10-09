import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyMainValidation, isRustBuildPath } from './ci-main-scope.mjs';

test('documentation-only pushes need no implementation checks', () => {
  assert.deepEqual(
    classifyMainValidation(['README.md', 'docs/operations/preview.md']),
    { quickRequired: false, rustRequired: false },
  );
});

test('JavaScript and automation changes need only quick repository checks', () => {
  for (const file of [
    'apps/app/src/main.js',
    'infra/preview/preview-cleanup.mjs',
    '.github/workflows/preview.cleanup.yml',
    'contracts/deployment-environments.json',
  ]) {
    assert.deepEqual(
      classifyMainValidation([file]),
      { quickRequired: true, rustRequired: false },
      file,
    );
  }
});

test('Rust sources and build inputs also need a compile check', () => {
  for (const file of [
    'openom/src/lib.rs',
    'packages/tree/Cargo.toml',
    'Cargo.lock',
    '.cargo/config.toml',
    'rust-toolchain.toml',
    'rustfmt.toml',
  ]) {
    assert.equal(isRustBuildPath(file), true, file);
    assert.deepEqual(
      classifyMainValidation([file]),
      { quickRequired: true, rustRequired: true },
      file,
    );
  }
});

test('mixed changes run the union of applicable checks', () => {
  assert.deepEqual(
    classifyMainValidation(['docs/architecture.md', 'apps/app/src/main.js', 'openom/src/lib.rs']),
    { quickRequired: true, rustRequired: true },
  );
});

test('an unavailable diff fails closed', () => {
  assert.deepEqual(
    classifyMainValidation([]),
    { quickRequired: true, rustRequired: true },
  );
});
