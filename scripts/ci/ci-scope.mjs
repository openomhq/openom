#!/usr/bin/env node
// Classify changed paths for the desktop validation gate.
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const DOCUMENTATION_PREFIXES = [
  'docs/',
  'plan/',
  '.github/ISSUE_TEMPLATE/',
];

export function isDocumentationPath(file) {
  const normalized = String(file).replaceAll('\\', '/');
  return normalized.endsWith('.md')
    || DOCUMENTATION_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

export function requiresDesktopValidation(files) {
  const paths = [...files].filter(Boolean);
  return paths.length === 0 || paths.some((file) => !isDocumentationPath(file));
}

async function main() {
  const outputIndex = process.argv.indexOf('--github-output');
  const outputPath = outputIndex === -1 ? null : process.argv[outputIndex + 1];
  if (outputIndex !== -1 && !outputPath) throw new Error('--github-output requires a path');

  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const files = Buffer.concat(chunks).toString('utf8').split(/\r?\n/).filter(Boolean);
  const assignment = `desktop_required=${requiresDesktopValidation(files)}\n`;
  if (outputPath) appendFileSync(outputPath, assignment);
  else process.stdout.write(assignment);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
