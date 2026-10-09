import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const previewDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(previewDirectory, '..', '..');
const testDirectories = [
  previewDirectory,
  path.join(repositoryRoot, 'infra', 'terraform', 'preview', 'tests'),
];

const testFiles = testDirectories
  .flatMap((directory) =>
    fs
      .readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.test.mjs'))
      .map((entry) => path.join(directory, entry.name)),
  )
  .sort();

if (testFiles.length === 0) {
  throw new Error('preview test discovery found no tests');
}

const result = spawnSync(process.execPath, ['--test', ...testFiles], {
  cwd: repositoryRoot,
  stdio: 'inherit',
});

if (result.error) {
  throw result.error;
}

process.exitCode = result.status ?? 1;
