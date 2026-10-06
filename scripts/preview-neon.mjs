#!/usr/bin/env node
import { chmodSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_API_URL = 'https://console.neon.tech/api/v2';
const RETRYABLE_STATUSES = new Set([423, 503]);
const OWNERSHIP_KEYS = Object.freeze({
  pullRequest: 'openom-preview-pull-request',
  sourceBranch: 'openom-preview-source-branch',
});

export class PreviewNeonError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'PreviewNeonError';
    this.code = code;
  }
}

function requiredString(value, name) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewNeonError('missing_neon_configuration', `${name} is required`);
}

function positiveInteger(value, name) {
  const parsed = Number(value);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  throw new PreviewNeonError('invalid_neon_configuration', `${name} must be a positive integer`);
}

function assertIdentifier(value, name) {
  const identifier = requiredString(value, name);
  if (/^[a-z0-9-]{1,60}$/.test(identifier)) return identifier;
  throw new PreviewNeonError('invalid_neon_configuration', `${name} has an invalid identifier shape`);
}

function assertBranchName(value) {
  const branchName = requiredString(value, 'preview branch name');
  if (/^preview\/[a-z0-9][a-z0-9-]{0,44}$/.test(branchName)) return branchName;
  throw new PreviewNeonError(
    'invalid_neon_branch_name',
    'preview branch name must use the preview/<slug> namespace',
  );
}

function responseJson(response, operation) {
  return response.json().catch(() => {
    throw new PreviewNeonError('invalid_neon_response', `${operation} returned malformed JSON`);
  });
}

async function requestJson({
  apiKey,
  apiUrl,
  body,
  fetchImplementation,
  method = 'GET',
  operation,
  pathname,
  query,
  attempts = 3,
  pause,
}) {
  const url = new URL(`${apiUrl}${pathname}`);
  for (const [name, value] of Object.entries(query ?? {})) {
    url.searchParams.set(name, String(value));
  }

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let response;
    try {
      response = await fetchImplementation(url, {
        method,
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${apiKey}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (cause) {
      if (method === 'GET' && attempt + 1 < attempts) {
        await pause(250 * (attempt + 1));
        continue;
      }
      throw new PreviewNeonError(
        method === 'GET' ? 'neon_request_failed' : 'neon_mutation_uncertain',
        `${operation} did not return a response`,
        { cause },
      );
    }

    if (response.ok) return responseJson(response, operation);
    if (RETRYABLE_STATUSES.has(response.status) && attempt + 1 < attempts) {
      await pause(250 * (attempt + 1));
      continue;
    }
    throw new PreviewNeonError(
      response.status === 409 ? 'neon_resource_conflict' : 'neon_api_failed',
      `${operation} failed with status ${response.status}`,
    );
  }
  throw new PreviewNeonError('neon_api_failed', `${operation} exhausted its retry budget`);
}

function normalizeBranchList(response) {
  if (!response || !Array.isArray(response.branches)) {
    throw new PreviewNeonError('invalid_neon_response', 'branch listing omitted branches');
  }
  if (response.branches.some((branch) => (
    !branch
    || typeof branch.id !== 'string'
    || typeof branch.name !== 'string'
  ))) {
    throw new PreviewNeonError('invalid_neon_response', 'branch listing contains an invalid branch');
  }
  return response;
}

function ownerAnnotation(response, branchId) {
  const annotation = response.annotations?.[branchId];
  return annotation?.value ?? null;
}

function expectedOwner(pullRequestNumber, sourceBranch) {
  return {
    [OWNERSHIP_KEYS.pullRequest]: String(pullRequestNumber),
    [OWNERSHIP_KEYS.sourceBranch]: sourceBranch,
  };
}

function assertOwnedBranch(branch, annotation, config) {
  if (branch.parent_id !== config.baseBranchId) {
    throw new PreviewNeonError(
      'preview_neon_parent_mismatch',
      `Neon branch ${config.branchName} does not descend from the configured preview base`,
    );
  }
  const owner = expectedOwner(config.pullRequestNumber, config.sourceBranch);
  if (
    annotation?.[OWNERSHIP_KEYS.pullRequest] !== owner[OWNERSHIP_KEYS.pullRequest]
    || annotation?.[OWNERSHIP_KEYS.sourceBranch] !== owner[OWNERSHIP_KEYS.sourceBranch]
  ) {
    throw new PreviewNeonError(
      'preview_neon_owner_mismatch',
      `Neon branch ${config.branchName} belongs to another preview`,
    );
  }
  return branch;
}

async function listBranches(client) {
  const response = await requestJson({
    ...client,
    operation: 'Neon branch listing',
    pathname: `/projects/${client.projectId}/branches`,
    query: { limit: 10000 },
  });
  return normalizeBranchList(response);
}

function selectBranch(listing, config, { allowPendingAnnotation = false } = {}) {
  if (!listing.branches.some((branch) => branch.id === config.baseBranchId)) {
    throw new PreviewNeonError(
      'preview_neon_base_missing',
      'configured preview base branch was not found in the Neon project',
    );
  }
  const matches = listing.branches.filter((branch) => branch.name === config.branchName);
  if (matches.length > 1) {
    throw new PreviewNeonError(
      'preview_neon_duplicate_branch',
      `Neon returned multiple branches named ${config.branchName}`,
    );
  }
  if (matches.length === 1) {
    const annotation = ownerAnnotation(listing, matches[0].id);
    if (allowPendingAnnotation && annotation === null) return null;
    return assertOwnedBranch(matches[0], annotation, config);
  }
  const activePreviews = listing.branches.filter((branch) => branch.name.startsWith('preview/'));
  if (activePreviews.length >= config.maxFullStacks) {
    throw new PreviewNeonError(
      'preview_capacity_reached',
      `full-preview capacity is ${config.maxFullStacks}; clean up an existing preview first`,
    );
  }
  return null;
}

async function reconcileCreatedBranch(client, config) {
  for (let attempt = 0; attempt < client.attempts; attempt += 1) {
    const listing = await listBranches(client);
    const branch = selectBranch(listing, config, { allowPendingAnnotation: true });
    if (branch) return branch;
    if (attempt + 1 < client.attempts) await client.pause(250 * (attempt + 1));
  }
  return null;
}

async function createBranch(client, config) {
  const response = await requestJson({
    ...client,
    body: {
      annotation_value: expectedOwner(config.pullRequestNumber, config.sourceBranch),
      branch: {
        name: config.branchName,
        parent_id: config.baseBranchId,
        protected: false,
      },
      endpoints: [{ type: 'read_write' }],
    },
    method: 'POST',
    operation: 'Neon branch creation',
    pathname: `/projects/${client.projectId}/branches`,
  });
  if (!response?.branch || typeof response.branch.id !== 'string') {
    throw new PreviewNeonError('invalid_neon_response', 'branch creation omitted the branch');
  }
  if (response.branch.name !== config.branchName || response.branch.parent_id !== config.baseBranchId) {
    throw new PreviewNeonError('invalid_neon_response', 'branch creation returned the wrong branch');
  }
}

async function reconcileCreate(client, config) {
  try {
    await createBranch(client, config);
  } catch (error) {
    if (!(error instanceof PreviewNeonError) || ![
      'neon_mutation_uncertain',
      'neon_resource_conflict',
      'invalid_neon_response',
    ].includes(error.code)) throw error;
    const branch = await reconcileCreatedBranch(client, config);
    if (branch) return branch;
    throw error;
  }
  const branch = await reconcileCreatedBranch(client, config);
  if (branch) return branch;
  throw new PreviewNeonError(
    'preview_neon_branch_missing',
    'Neon branch creation succeeded but the branch could not be reconciled',
  );
}

async function ensureEndpoint(client, branchId) {
  const pathname = `/projects/${client.projectId}/branches/${branchId}/endpoints`;
  const listed = await requestJson({
    ...client,
    operation: 'Neon endpoint listing',
    pathname,
  });
  if (!listed || !Array.isArray(listed.endpoints)) {
    throw new PreviewNeonError('invalid_neon_response', 'endpoint listing omitted endpoints');
  }
  const endpoints = listed.endpoints.filter((endpoint) => endpoint?.type === 'read_write');
  if (endpoints.length > 1) {
    throw new PreviewNeonError('preview_neon_endpoint_conflict', 'preview branch has multiple read-write endpoints');
  }
  if (endpoints.length === 1 && typeof endpoints[0].id === 'string') return endpoints[0];

  try {
    const created = await requestJson({
      ...client,
      body: { endpoint: { branch_id: branchId, type: 'read_write' } },
      method: 'POST',
      operation: 'Neon endpoint creation',
      pathname: `/projects/${client.projectId}/endpoints`,
    });
    if (typeof created?.endpoint?.id === 'string') return created.endpoint;
  } catch (error) {
    if (!(error instanceof PreviewNeonError) || ![
      'neon_mutation_uncertain',
      'neon_resource_conflict',
      'invalid_neon_response',
    ].includes(error.code)) throw error;
  }

  const reconciled = await requestJson({
    ...client,
    operation: 'Neon endpoint reconciliation',
    pathname,
  });
  const endpoint = reconciled?.endpoints?.find((candidate) => candidate?.type === 'read_write');
  if (typeof endpoint?.id === 'string') return endpoint;
  throw new PreviewNeonError('preview_neon_endpoint_missing', 'preview branch has no read-write endpoint');
}

async function connectionUri(client, config, branchId, endpointId, pooled) {
  const response = await requestJson({
    ...client,
    operation: pooled ? 'pooled Neon connection lookup' : 'direct Neon connection lookup',
    pathname: `/projects/${client.projectId}/connection_uri`,
    query: {
      branch_id: branchId,
      database_name: config.databaseName,
      endpoint_id: endpointId,
      pooled,
      role_name: config.roleName,
    },
  });
  if (typeof response?.uri !== 'string' || !/^postgres(?:ql)?:\/\//.test(response.uri)) {
    throw new PreviewNeonError('invalid_neon_response', 'connection lookup omitted a PostgreSQL URI');
  }
  return response.uri;
}

function validatedConfig(options) {
  return {
    apiKey: requiredString(options.apiKey, 'NEON_API_KEY'),
    apiUrl: requiredString(options.apiUrl ?? DEFAULT_API_URL, 'Neon API URL'),
    baseBranchId: assertIdentifier(options.baseBranchId, 'NEON_PREVIEW_BASE_BRANCH_ID'),
    branchName: assertBranchName(options.branchName),
    databaseName: requiredString(options.databaseName, 'NEON_DATABASE_NAME'),
    maxFullStacks: positiveInteger(options.maxFullStacks, 'PREVIEW_MAX_FULL_STACKS'),
    projectId: assertIdentifier(options.projectId, 'NEON_PROJECT_ID'),
    pullRequestNumber: positiveInteger(options.pullRequestNumber, 'pull request number'),
    roleName: requiredString(options.roleName, 'NEON_ROLE_NAME'),
    sourceBranch: requiredString(options.sourceBranch, 'source branch'),
  };
}

export async function reconcilePreviewDatabase(options) {
  const config = validatedConfig(options);
  const client = {
    apiKey: config.apiKey,
    apiUrl: config.apiUrl.replace(/\/$/, ''),
    attempts: options.attempts ?? 3,
    fetchImplementation: options.fetchImplementation ?? fetch,
    pause: options.pause ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))),
    projectId: config.projectId,
  };
  const listing = await listBranches(client);
  const branch = selectBranch(listing, config) ?? await reconcileCreate(client, config);
  const endpoint = await ensureEndpoint(client, branch.id);
  const [databaseUrl, migrationDatabaseUrl] = await Promise.all([
    connectionUri(client, config, branch.id, endpoint.id, true),
    connectionUri(client, config, branch.id, endpoint.id, false),
  ]);
  return {
    branchId: branch.id,
    branchName: branch.name,
    databaseUrl,
    endpointId: endpoint.id,
    migrationDatabaseUrl,
  };
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewNeonError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export async function runPreviewNeonCli(args, environment = process.env) {
  if (args[0] !== 'reconcile') {
    throw new PreviewNeonError(
      'missing_operation',
      'usage: preview-neon.mjs reconcile --branch <name> --source-branch <name> --pull-request <number> --output-file <path>',
    );
  }
  const outputFile = argumentValue(args, '--output-file');
  const result = await reconcilePreviewDatabase({
    apiKey: environment.NEON_API_KEY,
    baseBranchId: environment.NEON_PREVIEW_BASE_BRANCH_ID,
    branchName: argumentValue(args, '--branch'),
    databaseName: environment.NEON_DATABASE_NAME,
    maxFullStacks: environment.PREVIEW_MAX_FULL_STACKS,
    projectId: environment.NEON_PROJECT_ID,
    pullRequestNumber: argumentValue(args, '--pull-request'),
    roleName: environment.NEON_ROLE_NAME,
    sourceBranch: argumentValue(args, '--source-branch'),
  });
  requiredString(outputFile, 'output file');
  writeFileSync(outputFile, JSON.stringify(result), { encoding: 'utf8', mode: 0o600 });
  chmodSync(outputFile, 0o600);
  return { branchId: result.branchId, branchName: result.branchName, endpointId: result.endpointId };
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = await runPreviewNeonCli(process.argv.slice(2));
    console.log(JSON.stringify(result));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
