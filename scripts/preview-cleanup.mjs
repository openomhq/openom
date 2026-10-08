#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { listActivePreviewDeployments, retirePreviewDeployments } from './preview-deployment.mjs';
import { deletePreviewLambda, listPreviewLambdas } from './preview-lambda.mjs';
import { previewIdentity } from './preview-name.mjs';
import {
  deletePreviewDatabase,
  listPreviewDatabases,
} from './preview-neon.mjs';
import { deletePreviewRoute, listPreviewRouteRecords } from './preview-route.mjs';
import { desiredPreviewMode } from './preview-policy.mjs';

const AWS_CLI_IMAGE = 'amazon/aws-cli:2.31.22@sha256:bf253be91e12d49ba1bd6dc939a76ea9777901772032692b14639e643118e1c1';

export class PreviewCleanupError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'PreviewCleanupError';
    this.code = code;
  }
}

function command(commandName, args, options = {}) {
  return spawnSync(commandName, args, {
    encoding: 'utf8',
    stdio: 'pipe',
    ...options,
  });
}

function requiredString(value, name) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewCleanupError('missing_cleanup_configuration', `${name} is required`);
}

function successful(result, operation) {
  if (result.error) {
    throw new PreviewCleanupError('cleanup_command_failed', `${operation} failed to start`);
  }
  if (result.status !== 0) {
    throw new PreviewCleanupError(
      'cleanup_command_failed',
      `${operation} failed: ${(result.stderr || result.stdout || '').trim().slice(0, 1000)}`,
    );
  }
}

function validateBucket(value, name) {
  const bucket = requiredString(value, name);
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) {
    throw new PreviewCleanupError('invalid_cleanup_configuration', `${name} is invalid`);
  }
  return bucket;
}

export function deletePreviewObjectPrefix({
  accessKeyId,
  bucket,
  endpoint,
  execute = command,
  identity,
  secretAccessKey,
}) {
  const validatedBucket = validateBucket(bucket, 'R2_BUCKET');
  const validatedEndpoint = new URL(requiredString(endpoint, 'R2_ENDPOINT'));
  if (validatedEndpoint.protocol !== 'https:' || !validatedEndpoint.hostname.endsWith('.r2.cloudflarestorage.com')) {
    throw new PreviewCleanupError('invalid_cleanup_configuration', 'R2_ENDPOINT is invalid');
  }
  const result = execute('docker', [
    'run', '--rm',
    '-e', 'AWS_ACCESS_KEY_ID',
    '-e', 'AWS_SECRET_ACCESS_KEY',
    '-e', 'AWS_DEFAULT_REGION',
    '-e', 'AWS_EC2_METADATA_DISABLED',
    AWS_CLI_IMAGE,
    's3', 'rm', `s3://${validatedBucket}/${identity.objectStoreKeyPrefix}`,
    '--recursive',
    '--endpoint-url', validatedEndpoint.href.replace(/\/$/, ''),
    '--only-show-errors',
  ], {
    env: {
      ...process.env,
      AWS_ACCESS_KEY_ID: requiredString(accessKeyId, 'R2_ACCESS_KEY_ID'),
      AWS_SECRET_ACCESS_KEY: requiredString(secretAccessKey, 'R2_SECRET_ACCESS_KEY'),
      AWS_DEFAULT_REGION: 'auto',
      AWS_EC2_METADATA_DISABLED: 'true',
    },
  });
  successful(result, 'preview object-prefix deletion');
  return { deletedPrefix: identity.objectStoreKeyPrefix };
}

export function deletePreviewArtifactPrefix({ bucket, execute = command, identity }) {
  const validatedBucket = validateBucket(bucket, 'AWS_PREVIEW_ARTIFACTS_BUCKET');
  const prefix = `previews/${identity.slug}/`;
  const result = execute('aws', [
    's3', 'rm', `s3://${validatedBucket}/${prefix}`,
    '--recursive',
    '--only-show-errors',
  ]);
  successful(result, 'preview artifact-prefix deletion');
  return { deletedPrefix: prefix };
}

export async function waitForPreviewRouteRemoval({
  attempts = 40,
  fetchImplementation = fetch,
  identity,
  pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const responses = await Promise.all([identity.appUrl, identity.apiUrl].map(async (url) => {
      try {
        const response = await fetchImplementation(url, { redirect: 'manual' });
        const body = await response.text();
        return response.status === 404 && body.includes('preview_not_found');
      } catch {
        return false;
      }
    }));
    if (responses.every(Boolean)) return { converged: true };
    if (attempt + 1 < attempts) await pause(3_000);
  }
  throw new PreviewCleanupError(
    'preview_route_cleanup_not_converged',
    `preview route ${identity.slug} did not converge to the deterministic 404`,
  );
}

function cleanupConfiguration(environment) {
  const githubRepository = requiredString(environment.GITHUB_REPOSITORY, 'GITHUB_REPOSITORY');
  return {
    artifactBucket: requiredString(environment.AWS_PREVIEW_ARTIFACTS_BUCKET, 'AWS_PREVIEW_ARTIFACTS_BUCKET'),
    githubApiUrl: environment.GITHUB_API_URL ?? 'https://api.github.com',
    githubLogUrl: `${requiredString(environment.GITHUB_SERVER_URL, 'GITHUB_SERVER_URL')}/${githubRepository}/actions/runs/${requiredString(environment.GITHUB_RUN_ID, 'GITHUB_RUN_ID')}`,
    githubRepository,
    githubToken: requiredString(environment.GITHUB_TOKEN, 'GITHUB_TOKEN'),
    kvsArn: requiredString(environment.AWS_CLOUDFRONT_KVS_ARN, 'AWS_CLOUDFRONT_KVS_ARN'),
    neonApiKey: requiredString(environment.NEON_API_KEY, 'NEON_API_KEY'),
    neonBaseBranchId: requiredString(environment.NEON_PREVIEW_BASE_BRANCH_ID, 'NEON_PREVIEW_BASE_BRANCH_ID'),
    neonProjectId: requiredString(environment.NEON_PROJECT_ID, 'NEON_PROJECT_ID'),
    r2AccessKeyId: requiredString(environment.R2_ACCESS_KEY_ID, 'R2_ACCESS_KEY_ID'),
    r2Bucket: requiredString(environment.R2_BUCKET, 'R2_BUCKET'),
    r2Endpoint: requiredString(environment.R2_ENDPOINT, 'R2_ENDPOINT'),
    r2SecretAccessKey: requiredString(environment.R2_SECRET_ACCESS_KEY, 'R2_SECRET_ACCESS_KEY'),
  };
}

export async function cleanupPreview({
  environment = process.env,
  execute = command,
  fetchImplementation = fetch,
  identity,
  operations = {},
}) {
  const config = cleanupConfiguration(environment);
  const adapters = {
    deleteArtifactPrefix: operations.deleteArtifactPrefix ?? deletePreviewArtifactPrefix,
    deleteDatabase: operations.deleteDatabase ?? deletePreviewDatabase,
    deleteDeployment: operations.deleteDeployment ?? retirePreviewDeployments,
    deleteLambda: operations.deleteLambda ?? deletePreviewLambda,
    deleteObjectPrefix: operations.deleteObjectPrefix ?? deletePreviewObjectPrefix,
    deleteRoute: operations.deleteRoute ?? deletePreviewRoute,
    waitForRouteRemoval: operations.waitForRouteRemoval ?? waitForPreviewRouteRemoval,
  };
  const result = { identity, phases: [] };
  result.route = await adapters.deleteRoute({ execute, identity, kvsArn: config.kvsArn });
  result.phases.push('route');
  result.routeConvergence = await adapters.waitForRouteRemoval({
    fetchImplementation,
    identity,
  });
  result.phases.push('route-convergence');
  result.lambda = await adapters.deleteLambda({
    execute,
    functionName: identity.lambdaName,
    pullRequestNumber: identity.pullRequestNumber,
    slug: identity.slug,
    sourceBranch: identity.sourceBranch,
  });
  result.phases.push('lambda');
  result.database = await adapters.deleteDatabase({
    apiKey: config.neonApiKey,
    baseBranchId: config.neonBaseBranchId,
    branchName: identity.neonBranch,
    fetchImplementation,
    projectId: config.neonProjectId,
    pullRequestNumber: identity.pullRequestNumber,
    sourceBranch: identity.sourceBranch,
  });
  result.phases.push('database');
  result.objectStore = await adapters.deleteObjectPrefix({
    accessKeyId: config.r2AccessKeyId,
    bucket: config.r2Bucket,
    endpoint: config.r2Endpoint,
    execute,
    identity,
    secretAccessKey: config.r2SecretAccessKey,
  });
  result.phases.push('object-store');
  result.artifacts = await adapters.deleteArtifactPrefix({
    bucket: config.artifactBucket,
    execute,
    identity,
  });
  result.phases.push('artifacts');
  result.deployment = await adapters.deleteDeployment({
    apiUrl: config.githubApiUrl,
    fetchImplementation,
    logUrl: config.githubLogUrl,
    pullRequestNumber: identity.pullRequestNumber,
    repository: config.githubRepository,
    slug: identity.slug,
    token: config.githubToken,
  });
  result.phases.push('deployment');
  return result;
}

async function githubGet(fetchImplementation, apiUrl, token, route) {
  const response = await fetchImplementation(`${apiUrl}${route}`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'x-github-api-version': '2022-11-28',
    },
  });
  if (!response.ok) {
    throw new PreviewCleanupError(
      'github_preview_listing_failed',
      `GitHub preview listing failed with status ${response.status}`,
    );
  }
  return response.json();
}

export async function listDesiredPullRequests({
  apiUrl = 'https://api.github.com',
  fetchImplementation = fetch,
  repository,
  token,
}) {
  const identities = [];
  for (let page = 1; ; page += 1) {
    const pulls = await githubGet(
      fetchImplementation,
      apiUrl,
      token,
      `/repos/${repository}/pulls?state=open&per_page=100&page=${page}`,
    );
    if (!Array.isArray(pulls)) {
      throw new PreviewCleanupError('invalid_github_response', 'GitHub pull-request listing is malformed');
    }
    for (const pull of pulls) {
      if (pull.head?.repo?.full_name !== repository) continue;
      const mode = desiredPreviewMode(pull);
      if (mode === 'none') continue;
      identities.push({ identity: previewIdentity(pull.head.ref, pull.number), mode });
    }
    if (pulls.length < 100) break;
  }
  return identities;
}

function identityKey(identity) {
  return `${identity.pullRequestNumber}:${identity.sourceBranch}`;
}

function mergeDiscoveredIdentities(groups) {
  const records = new Map();
  for (const [source, identities] of Object.entries(groups)) {
    for (const value of identities) {
      const identity = value.identity ?? value;
      const existingSlug = [...records.values()].find((record) => (
        record.identity.slug === identity.slug && identityKey(record.identity) !== identityKey(identity)
      ));
      if (existingSlug) {
        throw new PreviewCleanupError(
          'preview_cleanup_identity_collision',
          `preview slug ${identity.slug} has conflicting ownership`,
        );
      }
      const key = identityKey(identity);
      const record = records.get(key) ?? { identity, routeMode: null, sources: new Set() };
      record.sources.add(source);
      if (source === 'route' && typeof value.mode === 'string') record.routeMode = value.mode;
      records.set(key, record);
    }
  }
  return [...records.values()];
}

export function selectOrphanedPreviews({ desired, discovered }) {
  const desiredByPullRequest = new Map(desired.map((value) => {
    const desired = value.identity ? value : { identity: value, mode: 'full' };
    return [desired.identity.pullRequestNumber, desired];
  }));
  const readyReplacements = new Set(discovered
    .filter((record) => record.sources.has('route'))
    .map((record) => identityKey(record.identity)));
  return discovered.filter((record) => {
    const expected = desiredByPullRequest.get(record.identity.pullRequestNumber);
    if (!expected) return true;
    if (identityKey(expected.identity) !== identityKey(record.identity)) {
      return readyReplacements.has(identityKey(expected.identity));
    }
    if (expected.mode === 'full') return false;
    return record.routeMode === 'full'
      || record.sources.has('database')
      || record.sources.has('lambda');
  });
}

export async function janitorPreviewResources({
  environment = process.env,
  execute = command,
  fetchImplementation = fetch,
  operations = {},
}) {
  const config = cleanupConfiguration(environment);
  const discover = operations.discover ?? (async () => ({
    database: await listPreviewDatabases({
      apiKey: config.neonApiKey,
      baseBranchId: config.neonBaseBranchId,
      fetchImplementation,
      projectId: config.neonProjectId,
    }),
    deployment: await listActivePreviewDeployments({
      apiUrl: config.githubApiUrl,
      fetchImplementation,
      repository: config.githubRepository,
      token: config.githubToken,
    }),
    lambda: listPreviewLambdas({ execute }),
    route: listPreviewRouteRecords({ execute, kvsArn: config.kvsArn }),
  }));
  const listDesired = operations.listDesired ?? listDesiredPullRequests;
  const cleanup = operations.cleanup ?? cleanupPreview;
  const [desired, groups] = await Promise.all([
    listDesired({
      apiUrl: config.githubApiUrl,
      fetchImplementation,
      repository: config.githubRepository,
      token: config.githubToken,
    }),
    discover(),
  ]);
  const discovered = mergeDiscoveredIdentities(groups);
  const orphaned = selectOrphanedPreviews({ desired, discovered });
  const cleaned = [];
  for (const record of orphaned) {
    cleaned.push(await cleanup({
      environment,
      execute,
      fetchImplementation,
      identity: record.identity,
    }));
  }
  return {
    desired: desired.length,
    cleaned,
    discovered: discovered.length,
  };
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewCleanupError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export async function runPreviewCleanupCli(args, environment = process.env) {
  if (args[0] === 'janitor') return janitorPreviewResources({ environment });
  if (args[0] !== 'cleanup') {
    throw new PreviewCleanupError(
      'missing_operation',
      'usage: preview-cleanup.mjs cleanup --branch <name> --pull-request <number> | janitor',
    );
  }
  const identity = previewIdentity(
    argumentValue(args, '--branch'),
    argumentValue(args, '--pull-request'),
  );
  return cleanupPreview({ environment, identity });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await runPreviewCleanupCli(process.argv.slice(2))));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
