#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const LAMBDA_NAME_LIMIT = 64;
export const LAMBDA_NAME_PREFIX = 'openom-preview-';
export const LAMBDA_NAME_SUFFIX = '-api';
export const MAX_PREVIEW_SLUG_LENGTH =
  LAMBDA_NAME_LIMIT - LAMBDA_NAME_PREFIX.length - LAMBDA_NAME_SUFFIX.length;
const SAFE_SOURCE_BRANCH = /^[A-Za-z0-9._/-]+$/;

export class PreviewNameError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewNameError';
    this.code = code;
  }
}

export function normalizePreviewSlug(branchName) {
  if (typeof branchName !== 'string') {
    throw new PreviewNameError('invalid_branch_name', 'branch name must be a string');
  }

  const slug = branchName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  if (!slug) {
    throw new PreviewNameError(
      'empty_preview_slug',
      'branch name must contain at least one ASCII letter or digit',
    );
  }
  if (slug.length > MAX_PREVIEW_SLUG_LENGTH) {
    throw new PreviewNameError(
      'preview_slug_too_long',
      `preview slug is ${slug.length} characters; maximum is ${MAX_PREVIEW_SLUG_LENGTH}`,
    );
  }
  return slug;
}

export function assertPreviewSourceBranch(branchName) {
  if (typeof branchName !== 'string' || !SAFE_SOURCE_BRANCH.test(branchName)) {
    throw new PreviewNameError(
      'invalid_source_branch',
      'preview source branch may contain only ASCII letters, digits, dots, underscores, slashes, and dashes',
    );
  }
  return branchName;
}

function parsePullRequestNumber(value) {
  if (value === undefined || value === null) return null;
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new PreviewNameError(
      'invalid_pull_request_number',
      'pull request number must be a positive integer',
    );
  }
  return number;
}

export function previewIdentity(branchName, pullRequestNumber) {
  const sourceBranch = assertPreviewSourceBranch(branchName);
  const slug = normalizePreviewSlug(sourceBranch);
  return Object.freeze({
    slug,
    sourceBranch,
    pullRequestNumber: parsePullRequestNumber(pullRequestNumber),
    appUrl: `https://${slug}.app.dev.openom.org`,
    apiUrl: `https://${slug}.api.dev.openom.org`,
    lambdaName: `${LAMBDA_NAME_PREFIX}${slug}${LAMBDA_NAME_SUFFIX}`,
    neonBranch: `preview/${slug}`,
    objectStoreKeyPrefix: `previews/${slug}/`,
    pagesBranch: slug,
  });
}

function livePreviewRecord(value, index) {
  if (
    !value
    || typeof value !== 'object'
    || typeof value.slug !== 'string'
    || typeof value.sourceBranch !== 'string'
  ) {
    throw new PreviewNameError(
      'invalid_live_preview_record',
      `live preview record ${index} must contain string slug and sourceBranch fields`,
    );
  }
  const pullRequestNumber = parsePullRequestNumber(value.pullRequestNumber);
  if (pullRequestNumber === null) {
    throw new PreviewNameError(
      'invalid_live_preview_record',
      `live preview record ${index} must contain a pullRequestNumber`,
    );
  }
  return {
    slug: value.slug,
    sourceBranch: value.sourceBranch,
    pullRequestNumber,
  };
}

export function assertPreviewSlugAvailable(identity, livePreviews) {
  if (!Array.isArray(livePreviews)) {
    throw new PreviewNameError('invalid_live_previews', 'live previews must be an array');
  }
  if (identity.pullRequestNumber === null) {
    throw new PreviewNameError(
      'missing_pull_request_number',
      'collision checks require a pull request number',
    );
  }

  for (const [index, value] of livePreviews.entries()) {
    const live = livePreviewRecord(value, index);
    if (live.slug !== identity.slug) continue;

    const sameBranch = live.sourceBranch === identity.sourceBranch;
    const samePullRequest = live.pullRequestNumber === identity.pullRequestNumber;
    if (!sameBranch || !samePullRequest) {
      throw new PreviewNameError(
        'preview_slug_collision',
        `preview slug ${identity.slug} is already owned by ${live.sourceBranch}`,
      );
    }
  }

  return identity;
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewNameError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

function githubOutputs(identity) {
  return {
    slug: identity.slug,
    source_branch: identity.sourceBranch,
    pull_request_number: identity.pullRequestNumber ?? '',
    app_url: identity.appUrl,
    api_url: identity.apiUrl,
    lambda_name: identity.lambdaName,
    neon_branch: identity.neonBranch,
    object_store_key_prefix: identity.objectStoreKeyPrefix,
    pages_branch: identity.pagesBranch,
  };
}

export function runPreviewNameCli(args) {
  const branchName = argumentValue(args, '--branch');
  if (branchName === undefined) {
    throw new PreviewNameError('missing_branch', 'usage: preview-name.mjs --branch <name> [options]');
  }

  const identity = previewIdentity(branchName, argumentValue(args, '--pr-number'));
  const livePreviewsPath = argumentValue(args, '--live-previews');
  if (livePreviewsPath !== undefined) {
    const livePreviews = JSON.parse(readFileSync(livePreviewsPath, 'utf8'));
    assertPreviewSlugAvailable(identity, livePreviews);
  }

  const githubOutputPath = argumentValue(args, '--github-output');
  if (githubOutputPath !== undefined) {
    const lines = Object.entries(githubOutputs(identity))
      .map(([name, value]) => `${name}=${value}`)
      .join('\n');
    appendFileSync(githubOutputPath, `${lines}\n`, 'utf8');
  } else {
    process.stdout.write(`${JSON.stringify(identity, null, 2)}\n`);
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runPreviewNameCli(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
