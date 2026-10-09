import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const scriptsDirectory = path.join(repositoryRoot, 'scripts');
const categories = ['build', 'check', 'ci', 'dev', 'rust', 'test'];

test('repository scripts are executable-only and categorized by responsibility', () => {
  const rootEntries = fs.readdirSync(scriptsDirectory, { withFileTypes: true });
  const rootFiles = rootEntries.filter((entry) => entry.isFile()).map((entry) => entry.name);
  const rootDirectories = rootEntries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();

  assert.deepEqual(rootFiles, []);
  assert.deepEqual(rootDirectories, categories);

  const testSources = fs
    .readdirSync(scriptsDirectory, { withFileTypes: true, recursive: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.test.mjs'))
    .map((entry) => entry.name);
  assert.deepEqual(testSources, []);
});
