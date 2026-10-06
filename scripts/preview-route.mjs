#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

import { assertPreviewSlugAvailable, previewIdentity } from './preview-name.mjs';

const KVS_REGION = 'us-east-1';
const DEFAULT_ATTEMPTS = 5;

export class PreviewRouteError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewRouteError';
    this.code = code;
  }
}

function command(commandName, args) {
  return spawnSync(commandName, args, { encoding: 'utf8', stdio: 'pipe' });
}

function parseJson(output, operation) {
  try {
    return JSON.parse(output);
  } catch {
    throw new PreviewRouteError('invalid_aws_response', `${operation} returned malformed JSON`);
  }
}

function awsArguments(operation, values) {
  return [
    'cloudfront-keyvaluestore',
    operation,
    ...values,
    '--region', KVS_REGION,
    '--output', 'json',
    '--no-cli-pager',
  ];
}

function successful(result, operation) {
  if (result.error) {
    throw new PreviewRouteError('aws_command_failed', `${operation} failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new PreviewRouteError(
      'aws_command_failed',
      `${operation} failed: ${(result.stderr || result.stdout).trim()}`,
    );
  }
  return parseJson(result.stdout, operation);
}

function routeRecord(identity, commitSha, pagesProject, mode, apiOrigin) {
  if (!/^[a-f0-9]{40}$/.test(commitSha)) {
    throw new PreviewRouteError('invalid_preview_sha', 'preview commit SHA is invalid');
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(pagesProject)) {
    throw new PreviewRouteError('invalid_pages_project', 'Pages project name is invalid');
  }
  if (mode !== 'web' && mode !== 'full') {
    throw new PreviewRouteError('invalid_preview_mode', 'preview mode must be web or full');
  }
  if (mode === 'full' && !/^[a-z0-9.-]+\.lambda-url\.[a-z0-9-]+\.on\.aws$/.test(apiOrigin ?? '')) {
    throw new PreviewRouteError('invalid_api_origin', 'full preview API origin is invalid');
  }
  return {
    version: 1,
    slug: identity.slug,
    sourceBranch: identity.sourceBranch,
    pullRequestNumber: identity.pullRequestNumber,
    commitSha,
    mode,
    webOrigin: `${identity.slug}.${pagesProject}.pages.dev`,
    ...(mode === 'full' ? { apiOrigin } : {}),
  };
}

function requiredEnvironmentValue(value, name) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewRouteError('missing_route_configuration', `${name} is required`);
}

function getExistingRoute(execute, kvsArn, slug) {
  const result = execute('aws', awsArguments('get-key', ['--kvs-arn', kvsArn, '--key', slug]));
  if (result.status === 0) {
    const response = parseJson(result.stdout, 'KVS route lookup');
    try {
      return JSON.parse(response.Value);
    } catch {
      throw new PreviewRouteError('invalid_existing_route', `KVS route ${slug} is malformed`);
    }
  }
  const detail = result.stderr || result.stdout || '';
  if (detail.includes('ResourceNotFoundException')) return null;
  successful(result, 'KVS route lookup');
  return null;
}

function currentEtag(execute, kvsArn) {
  const response = successful(execute('aws', awsArguments(
    'describe-key-value-store',
    ['--kvs-arn', kvsArn],
  )), 'KVS description');
  if (typeof response.ETag !== 'string' || response.ETag.length === 0) {
    throw new PreviewRouteError('missing_kvs_etag', 'KVS description did not include an ETag');
  }
  return response.ETag;
}

function isPreconditionFailure(result) {
  const detail = result.stderr || result.stdout || '';
  return detail.includes('PreconditionFailedException') || detail.includes('PreconditionFailed');
}

export async function putPreviewRoute({
  apiOrigin,
  attempts = DEFAULT_ATTEMPTS,
  commitSha,
  execute = command,
  identity,
  kvsArn,
  mode = 'web',
  pagesProject,
  pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new PreviewRouteError('invalid_attempt_count', 'attempt count must be a positive integer');
  }
  const record = routeRecord(identity, commitSha, pagesProject, mode, apiOrigin);
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const existing = getExistingRoute(execute, kvsArn, identity.slug);
    if (existing) assertPreviewSlugAvailable(identity, [existing]);
    const etag = currentEtag(execute, kvsArn);
    const result = execute('aws', awsArguments('put-key', [
      '--kvs-arn', kvsArn,
      '--if-match', etag,
      '--key', identity.slug,
      '--value', JSON.stringify(record),
    ]));
    if (result.status === 0) return { previous: existing, record };
    if (!isPreconditionFailure(result)) successful(result, 'KVS route update');
    if (attempt + 1 < attempts) await pause(250 * (attempt + 1));
  }
  throw new PreviewRouteError(
    'preview_route_contention',
    `KVS route ${identity.slug} could not be updated after ${attempts} attempts`,
  );
}

export async function restorePreviewRoute({
  attempts = DEFAULT_ATTEMPTS,
  execute = command,
  identity,
  installed,
  kvsArn,
  pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  previous,
}) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const current = getExistingRoute(execute, kvsArn, identity.slug);
    if (!isDeepStrictEqual(current, installed)) {
      throw new PreviewRouteError(
        'preview_route_changed',
        `KVS route ${identity.slug} changed after this deployment attempt`,
      );
    }
    const etag = currentEtag(execute, kvsArn);
    const operation = previous ? 'put-key' : 'delete-key';
    const values = [
      '--kvs-arn', kvsArn,
      '--if-match', etag,
      '--key', identity.slug,
      ...(previous ? ['--value', JSON.stringify(previous)] : []),
    ];
    const result = execute('aws', awsArguments(operation, values));
    if (result.status === 0) return;
    if (!isPreconditionFailure(result)) successful(result, 'KVS route rollback');
    if (attempt + 1 < attempts) await pause(250 * (attempt + 1));
  }
  throw new PreviewRouteError(
    'preview_route_rollback_contention',
    `KVS route ${identity.slug} could not be restored after ${attempts} attempts`,
  );
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewRouteError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export async function runPreviewRouteCli(args, environment = process.env) {
  const operation = args[0];
  const branch = argumentValue(args, '--branch');
  const pullRequest = argumentValue(args, '--pull-request');
  const identity = previewIdentity(branch, pullRequest);
  const kvsArn = requiredEnvironmentValue(
    environment.AWS_CLOUDFRONT_KVS_ARN,
    'AWS_CLOUDFRONT_KVS_ARN',
  );
  if (operation === 'rollback') {
    const rollbackFile = argumentValue(args, '--rollback-file');
    const rollback = parseJson(readFileSync(rollbackFile, 'utf8'), 'preview rollback file');
    await restorePreviewRoute({
      identity,
      installed: rollback.record,
      kvsArn,
      previous: rollback.previous,
    });
    return rollback;
  }
  if (operation !== 'put') {
    throw new PreviewRouteError(
      'missing_operation',
      'usage: preview-route.mjs put|rollback --branch <name> --pull-request <number> ...',
    );
  }
  const result = await putPreviewRoute({
    apiOrigin: argumentValue(args, '--api-origin'),
    commitSha: argumentValue(args, '--commit'),
    identity,
    kvsArn,
    mode: argumentValue(args, '--mode') ?? 'web',
    pagesProject: requiredEnvironmentValue(
      environment.CLOUDFLARE_PAGES_PROJECT,
      'CLOUDFLARE_PAGES_PROJECT',
    ),
  });
  const rollbackFile = argumentValue(args, '--rollback-file');
  if (rollbackFile) writeFileSync(rollbackFile, JSON.stringify(result));
  return result;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const record = await runPreviewRouteCli(process.argv.slice(2));
    console.log(JSON.stringify(record));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
