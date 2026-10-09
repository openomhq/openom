#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { automationSuites, classifyAutomationTests } from './automation-suites.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requestedSuite = process.argv[2];
const suiteNames = new Set(automationSuites.map(({ name }) => name));

if (requestedSuite && !suiteNames.has(requestedSuite)) {
  throw new Error(`unknown automation test suite: ${requestedSuite}`);
}

const trackedTests = execFileSync(
  'git',
  ['ls-files', '--cached', '--others', '--exclude-standard', '--', '*.test.mjs'],
  {
    cwd: repositoryRoot,
    encoding: 'utf8',
  },
)
  .split(/\r?\n/u)
  .filter((file) => file && fs.existsSync(path.join(repositoryRoot, file)));

const { assigned, duplicated, unassigned } = classifyAutomationTests(trackedTests);
if (unassigned.length > 0 || duplicated.length > 0) {
  const problems = [
    ...unassigned.map((file) => `${file}: no declared Task suite`),
    ...duplicated.map(({ file, suites }) => `${file}: multiple Task suites (${suites.join(', ')})`),
  ];
  throw new Error(`automation test discovery is incomplete:\n${problems.join('\n')}`);
}

const selectedTests = requestedSuite
  ? assigned.get(requestedSuite)
  : automationSuites.flatMap(({ name }) => assigned.get(name));

if (selectedTests.length === 0) {
  throw new Error(`automation test discovery found no tests${requestedSuite ? ` for ${requestedSuite}` : ''}`);
}

const result = spawnSync(process.execPath, ['--test', ...selectedTests], {
  cwd: repositoryRoot,
  stdio: 'inherit',
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
