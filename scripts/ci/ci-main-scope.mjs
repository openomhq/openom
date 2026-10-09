#!/usr/bin/env node
// Classify direct pushes to main for the lightweight bypass safety net.
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { isDocumentationPath } from './ci-scope.mjs';

export function isRustBuildPath(file) {
  const normalized = String(file).replaceAll('\\', '/');
  const basename = normalized.split('/').at(-1);
  return normalized.endsWith('.rs')
    || normalized.startsWith('.cargo/')
    || basename === 'Cargo.toml'
    || basename === 'Cargo.lock'
    || basename === 'rust-toolchain'
    || basename === 'rust-toolchain.toml'
    || basename === 'rustfmt.toml'
    || basename === 'clippy.toml';
}

export function classifyMainValidation(files) {
  const paths = [...files].filter(Boolean);
  if (paths.length === 0) return { quickRequired: true, rustRequired: true };

  const implementationPaths = paths.filter((file) => !isDocumentationPath(file));
  return {
    quickRequired: implementationPaths.length > 0,
    rustRequired: implementationPaths.some(isRustBuildPath),
  };
}

async function main() {
  const outputIndex = process.argv.indexOf('--github-output');
  const outputPath = outputIndex === -1 ? null : process.argv[outputIndex + 1];
  if (outputIndex !== -1 && !outputPath) throw new Error('--github-output requires a path');

  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const files = Buffer.concat(chunks).toString('utf8').split(/\r?\n/).filter(Boolean);
  const classification = classifyMainValidation(files);
  const assignments = [
    `quick_required=${classification.quickRequired}`,
    `rust_required=${classification.rustRequired}`,
  ].join('\n') + '\n';

  if (outputPath) appendFileSync(outputPath, assignments);
  else process.stdout.write(assignments);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
