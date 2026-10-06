#!/usr/bin/env node
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ALIAS = 'live';
const URL_PERMISSION_SID = 'AllowCloudFrontInvokeFunctionUrl';
const INVOKE_PERMISSION_SID = 'AllowCloudFrontInvokeFunction';
const OWNER_TAGS = Object.freeze({
  pullRequest: 'openom-preview-pull-request',
  slug: 'openom-preview-slug',
  sourceBranch: 'openom-preview-source-branch',
});

export class PreviewLambdaError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewLambdaError';
    this.code = code;
  }
}

function command(commandName, args) {
  return spawnSync(commandName, args, { encoding: 'utf8', stdio: 'pipe' });
}

function requiredString(value, name) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewLambdaError('missing_lambda_configuration', `${name} is required`);
}

function positiveInteger(value, name) {
  const parsed = Number(value);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  throw new PreviewLambdaError('invalid_lambda_configuration', `${name} must be a positive integer`);
}

function awsArguments(service, operation, values) {
  return [service, operation, ...values, '--output', 'json', '--no-cli-pager'];
}

function detail(result) {
  return (result.stderr || result.stdout || '').trim();
}

function isMissing(result) {
  return result.status !== 0 && detail(result).includes('ResourceNotFoundException');
}

function parseJson(result, operation) {
  if (result.error) {
    throw new PreviewLambdaError('aws_command_failed', `${operation} failed to start`);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    const safeDetail = /DATABASE_URL|S3_SECRET_KEY|R2_SECRET_ACCESS_KEY/.test(stderr)
      ? ''
      : stderr.replace(/\s+/g, ' ').slice(0, 1000);
    throw new PreviewLambdaError(
      'aws_command_failed',
      `${operation} failed${safeDetail ? `: ${safeDetail}` : ''}`,
    );
  }
  try {
    return result.stdout.trim() ? JSON.parse(result.stdout) : {};
  } catch {
    throw new PreviewLambdaError('invalid_aws_response', `${operation} returned malformed JSON`);
  }
}

function runAws(execute, service, operation, values, label = `${service} ${operation}`) {
  return parseJson(execute('aws', awsArguments(service, operation, values)), label);
}

function ownerTags(config) {
  return {
    [OWNER_TAGS.pullRequest]: String(config.pullRequestNumber),
    [OWNER_TAGS.slug]: config.slug,
    [OWNER_TAGS.sourceBranch]: config.sourceBranch,
  };
}

function assertFunctionOwner(existing, config) {
  const tags = existing.Tags ?? {};
  const expected = ownerTags(config);
  for (const [name, value] of Object.entries(expected)) {
    if (tags[name] !== value) {
      throw new PreviewLambdaError(
        'preview_lambda_owner_mismatch',
        `Lambda ${config.functionName} belongs to another preview`,
      );
    }
  }
}

function validateConfig(options) {
  const functionName = requiredString(options.functionName, 'function name');
  const slug = requiredString(options.slug, 'preview slug');
  if (functionName !== `openom-preview-${slug}-api`) {
    throw new PreviewLambdaError('invalid_lambda_name', 'function name does not match the preview slug');
  }
  if (!/^[a-z0-9][a-z0-9-]{0,44}$/.test(slug)) {
    throw new PreviewLambdaError('invalid_preview_slug', 'preview slug has an invalid shape');
  }
  const commitSha = requiredString(options.commitSha, 'commit SHA');
  if (!/^[a-f0-9]{40}$/.test(commitSha)) {
    throw new PreviewLambdaError('invalid_preview_sha', 'preview commit SHA is invalid');
  }
  return {
    artifactBucket: requiredString(options.artifactBucket, 'AWS_PREVIEW_ARTIFACTS_BUCKET'),
    artifactKey: requiredString(options.artifactKey, 'artifact key'),
    commitSha,
    distributionArn: requiredString(options.distributionArn, 'CloudFront distribution ARN'),
    environmentFile: requiredString(options.environmentFile, 'Lambda environment file'),
    executionRoleArn: requiredString(options.executionRoleArn, 'AWS_PREVIEW_EXECUTION_ROLE_ARN'),
    functionName,
    pullRequestNumber: positiveInteger(options.pullRequestNumber, 'pull request number'),
    slug,
    sourceBranch: requiredString(options.sourceBranch, 'source branch'),
  };
}

function ensureLogGroup(execute, functionName) {
  const logGroup = `/aws/lambda/${functionName}`;
  const created = execute('aws', awsArguments('logs', 'create-log-group', ['--log-group-name', logGroup]));
  if (created.status !== 0 && !detail(created).includes('ResourceAlreadyExistsException')) {
    parseJson(created, 'CloudWatch log-group creation');
  }
  runAws(execute, 'logs', 'put-retention-policy', [
    '--log-group-name', logGroup,
    '--retention-in-days', '7',
  ], 'CloudWatch retention update');
}

function getFunction(execute, functionName) {
  const result = execute('aws', awsArguments('lambda', 'get-function', ['--function-name', functionName]));
  if (isMissing(result)) return null;
  return parseJson(result, 'Lambda lookup');
}

function waitForUpdate(execute, functionName) {
  runAws(execute, 'lambda', 'wait', [
    'function-updated-v2',
    '--function-name', functionName,
  ], 'Lambda update wait');
}

function waitForActive(execute, functionName) {
  runAws(execute, 'lambda', 'wait', [
    'function-active-v2',
    '--function-name', functionName,
  ], 'Lambda activation wait');
}

function createFunction(execute, config) {
  const created = runAws(execute, 'lambda', 'create-function', [
    '--function-name', config.functionName,
    '--architectures', 'arm64',
    '--runtime', 'provided.al2023',
    '--handler', 'bootstrap',
    '--role', config.executionRoleArn,
    '--code', JSON.stringify({ S3Bucket: config.artifactBucket, S3Key: config.artifactKey }),
    '--memory-size', '256',
    '--timeout', '15',
    '--environment', `file://${config.environmentFile}`,
    '--tags', JSON.stringify(ownerTags(config)),
    '--publish',
  ], 'Lambda creation');
  waitForActive(execute, config.functionName);
  return requiredString(created.Version, 'published Lambda version');
}

function updateFunction(execute, config, existing) {
  assertFunctionOwner(existing, config);
  runAws(execute, 'lambda', 'update-function-configuration', [
    '--function-name', config.functionName,
    '--runtime', 'provided.al2023',
    '--handler', 'bootstrap',
    '--role', config.executionRoleArn,
    '--memory-size', '256',
    '--timeout', '15',
    '--environment', `file://${config.environmentFile}`,
  ], 'Lambda configuration update');
  waitForUpdate(execute, config.functionName);
  const updated = runAws(execute, 'lambda', 'update-function-code', [
    '--function-name', config.functionName,
    '--s3-bucket', config.artifactBucket,
    '--s3-key', config.artifactKey,
    '--architectures', 'arm64',
    '--publish',
  ], 'Lambda code update');
  waitForUpdate(execute, config.functionName);
  return requiredString(updated.Version, 'published Lambda version');
}

function getAlias(execute, functionName) {
  const result = execute('aws', awsArguments('lambda', 'get-alias', [
    '--function-name', functionName,
    '--name', ALIAS,
  ]));
  if (isMissing(result)) return null;
  return parseJson(result, 'Lambda alias lookup');
}

function promoteAlias(execute, functionName, version, existingAlias) {
  const operation = existingAlias ? 'update-alias' : 'create-alias';
  runAws(execute, 'lambda', operation, [
    '--function-name', functionName,
    '--name', ALIAS,
    '--function-version', version,
  ], 'Lambda alias promotion');
}

function ensureFunctionUrl(execute, functionName) {
  const getArguments = ['--function-name', functionName, '--qualifier', ALIAS];
  const existing = execute('aws', awsArguments('lambda', 'get-function-url-config', getArguments));
  let response;
  if (isMissing(existing)) {
    response = runAws(execute, 'lambda', 'create-function-url-config', [
      ...getArguments,
      '--auth-type', 'AWS_IAM',
      '--invoke-mode', 'BUFFERED',
    ], 'Lambda Function URL creation');
  } else {
    const current = parseJson(existing, 'Lambda Function URL lookup');
    response = current;
    if (current.AuthType !== 'AWS_IAM' || current.InvokeMode !== 'BUFFERED') {
      response = runAws(execute, 'lambda', 'update-function-url-config', [
        ...getArguments,
        '--auth-type', 'AWS_IAM',
        '--invoke-mode', 'BUFFERED',
      ], 'Lambda Function URL update');
    }
  }
  const functionUrl = requiredString(response.FunctionUrl, 'Lambda Function URL');
  const parsed = new URL(functionUrl);
  if (!/^[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws$/.test(parsed.hostname)) {
    throw new PreviewLambdaError('invalid_function_url', 'Lambda returned an unexpected Function URL');
  }
  return { functionUrl, apiOrigin: parsed.hostname };
}

function policyStatement(policy, statementId) {
  const statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  return statements.find((statement) => statement?.Sid === statementId) ?? null;
}

function permissionMatches(statement, action, distributionArn, needsUrlAuth) {
  if (!statement || statement.Effect !== 'Allow' || statement.Action !== action) return false;
  const principal = statement.Principal?.Service ?? statement.Principal;
  if (principal !== 'cloudfront.amazonaws.com') return false;
  const sourceArn = statement.Condition?.ArnLike?.['AWS:SourceArn']
    ?? statement.Condition?.StringEquals?.['AWS:SourceArn'];
  if (sourceArn !== distributionArn) return false;
  if (!needsUrlAuth) return true;
  return statement.Condition?.StringEquals?.['lambda:FunctionUrlAuthType'] === 'AWS_IAM';
}

function readPolicy(execute, functionName) {
  const result = execute('aws', awsArguments('lambda', 'get-policy', [
    '--function-name', functionName,
    '--qualifier', ALIAS,
  ]));
  if (isMissing(result)) return { Statement: [] };
  const response = parseJson(result, 'Lambda policy lookup');
  try {
    return JSON.parse(response.Policy);
  } catch {
    throw new PreviewLambdaError('invalid_aws_response', 'Lambda policy lookup returned malformed policy');
  }
}

function ensurePermission(execute, config, policy, definition) {
  const existing = policyStatement(policy, definition.statementId);
  if (permissionMatches(existing, definition.action, config.distributionArn, definition.urlAuth)) return;
  if (existing) {
    runAws(execute, 'lambda', 'remove-permission', [
      '--function-name', config.functionName,
      '--qualifier', ALIAS,
      '--statement-id', definition.statementId,
    ], 'Lambda permission removal');
  }
  runAws(execute, 'lambda', 'add-permission', [
    '--function-name', config.functionName,
    '--qualifier', ALIAS,
    '--statement-id', definition.statementId,
    '--action', definition.action,
    '--principal', 'cloudfront.amazonaws.com',
    '--source-arn', config.distributionArn,
    ...(definition.urlAuth ? ['--function-url-auth-type', 'AWS_IAM'] : []),
  ], 'Lambda permission creation');
}

function ensureCloudFrontPermissions(execute, config) {
  const policy = readPolicy(execute, config.functionName);
  ensurePermission(execute, config, policy, {
    action: 'lambda:InvokeFunctionUrl',
    statementId: URL_PERMISSION_SID,
    urlAuth: true,
  });
  ensurePermission(execute, config, policy, {
    action: 'lambda:InvokeFunction',
    statementId: INVOKE_PERMISSION_SID,
    urlAuth: false,
  });
}

export function lambdaEnvironment(options) {
  const databaseUrl = requiredString(options.databaseUrl, 'DATABASE_URL');
  const appUrl = requiredString(options.appUrl, 'preview app URL');
  return {
    Variables: {
      AUTH: 'jwt',
      AUTH_JWKS_URL: requiredString(options.jwksUrl, 'SUPABASE_JWKS_URL'),
      AUTH_JWT_ALG: 'ES256',
      AUTH_JWT_AUD: requiredString(options.jwtAudience, 'SUPABASE_JWT_AUD'),
      AUTH_JWT_ISS: requiredString(options.jwtIssuer, 'SUPABASE_JWT_ISS'),
      DATABASE_URL: databaseUrl,
      OBJECT_STORE_KEY_PREFIX: requiredString(options.objectStoreKeyPrefix, 'object-store key prefix'),
      OPENOM_ENV: 'development',
      OPENOM_RUNTIME: 'remote',
      OPENOM_STACK: requiredString(options.slug, 'preview slug'),
      OPENOM_WEB_ORIGINS: appUrl,
      S3_ACCESS_KEY: requiredString(options.r2AccessKeyId, 'R2_ACCESS_KEY_ID'),
      S3_BUCKET: requiredString(options.r2Bucket, 'R2_BUCKET'),
      S3_ENDPOINT: requiredString(options.r2Endpoint, 'R2_ENDPOINT'),
      S3_PUBLIC_ENDPOINT: requiredString(options.r2Endpoint, 'R2_ENDPOINT'),
      S3_REGION: 'auto',
      S3_SECRET_KEY: requiredString(options.r2SecretAccessKey, 'R2_SECRET_ACCESS_KEY'),
      STORAGE: 'cloud',
    },
  };
}

export function reconcilePreviewLambda(options) {
  const config = validateConfig(options);
  const execute = options.execute ?? command;
  const existingFunction = getFunction(execute, config.functionName);
  if (existingFunction) assertFunctionOwner(existingFunction, config);
  ensureLogGroup(execute, config.functionName);
  const existingAlias = existingFunction ? getAlias(execute, config.functionName) : null;
  const previousVersion = existingAlias?.FunctionVersion ?? null;
  const installedVersion = existingFunction
    ? updateFunction(execute, config, existingFunction)
    : createFunction(execute, config);
  promoteAlias(execute, config.functionName, installedVersion, existingAlias);
  const rollback = {
    functionName: config.functionName,
    installedVersion,
    previousVersion,
  };
  options.checkpoint?.(rollback);
  const url = ensureFunctionUrl(execute, config.functionName);
  ensureCloudFrontPermissions(execute, config);

  const functionArn = existingFunction?.Configuration?.FunctionArn;
  const resolvedArn = typeof functionArn === 'string'
    ? functionArn
    : runAws(execute, 'lambda', 'get-function-configuration', [
      '--function-name', config.functionName,
    ], 'Lambda configuration lookup').FunctionArn;
  runAws(execute, 'lambda', 'tag-resource', [
    '--resource', requiredString(resolvedArn, 'Lambda function ARN'),
    '--tags', JSON.stringify({ ...ownerTags(config), 'openom-preview-commit': config.commitSha }),
  ], 'Lambda tagging');

  return {
    ...url,
    functionArn: resolvedArn,
    functionName: config.functionName,
    installedVersion,
    previousVersion,
  };
}

export function rollbackPreviewLambda({ execute = command, rollback }) {
  const functionName = requiredString(rollback?.functionName, 'rollback function name');
  const installedVersion = requiredString(rollback?.installedVersion, 'installed Lambda version');
  const alias = getAlias(execute, functionName);
  if (alias?.FunctionVersion !== installedVersion) {
    throw new PreviewLambdaError(
      'preview_lambda_changed',
      `Lambda ${functionName} changed after this deployment attempt`,
    );
  }
  if (rollback.previousVersion) {
    promoteAlias(execute, functionName, rollback.previousVersion, alias);
    return;
  }
  const functionUrlDeletion = execute('aws', awsArguments('lambda', 'delete-function-url-config', [
    '--function-name', functionName,
    '--qualifier', ALIAS,
  ]));
  if (functionUrlDeletion.status !== 0 && !isMissing(functionUrlDeletion)) {
    parseJson(functionUrlDeletion, 'Lambda Function URL rollback deletion');
  }
  const aliasDeletion = execute('aws', awsArguments('lambda', 'delete-alias', [
    '--function-name', functionName,
    '--name', ALIAS,
  ]));
  if (aliasDeletion.status !== 0 && !isMissing(aliasDeletion)) {
    parseJson(aliasDeletion, 'Lambda alias rollback deletion');
  }
  runAws(execute, 'lambda', 'delete-function', ['--function-name', functionName], 'Lambda rollback deletion');
  const logGroup = `/aws/lambda/${functionName}`;
  const deleted = execute('aws', awsArguments('logs', 'delete-log-group', ['--log-group-name', logGroup]));
  if (deleted.status !== 0 && !detail(deleted).includes('ResourceNotFoundException')) {
    parseJson(deleted, 'CloudWatch rollback deletion');
  }
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewLambdaError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export function runPreviewLambdaCli(args, environment = process.env) {
  if (args[0] === 'rollback') {
    const rollbackFile = argumentValue(args, '--rollback-file');
    rollbackPreviewLambda({ rollback: JSON.parse(readFileSync(rollbackFile, 'utf8')) });
    return { rolledBack: true };
  }
  if (args[0] !== 'reconcile') {
    throw new PreviewLambdaError('missing_operation', 'usage: preview-lambda.mjs reconcile|rollback ...');
  }

  const database = JSON.parse(readFileSync(argumentValue(args, '--database-config'), 'utf8'));
  const outputFile = requiredString(argumentValue(args, '--output-file'), 'output file');
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), 'openom-preview-lambda-'));
  const environmentFile = path.join(temporaryDirectory, 'environment.json');
  try {
    writeFileSync(environmentFile, JSON.stringify(lambdaEnvironment({
      appUrl: argumentValue(args, '--app-url'),
      databaseUrl: database.databaseUrl,
      jwksUrl: environment.SUPABASE_JWKS_URL,
      jwtAudience: environment.SUPABASE_JWT_AUD,
      jwtIssuer: environment.SUPABASE_JWT_ISS,
      objectStoreKeyPrefix: argumentValue(args, '--object-store-key-prefix'),
      r2AccessKeyId: environment.R2_ACCESS_KEY_ID,
      r2Bucket: environment.R2_BUCKET,
      r2Endpoint: environment.R2_ENDPOINT,
      r2SecretAccessKey: environment.R2_SECRET_ACCESS_KEY,
      slug: argumentValue(args, '--slug'),
    })), { encoding: 'utf8', mode: 0o600 });

    const executionRoleArn = requiredString(
      environment.AWS_PREVIEW_EXECUTION_ROLE_ARN,
      'AWS_PREVIEW_EXECUTION_ROLE_ARN',
    );
    const accountId = /^arn:aws:iam::([0-9]{12}):role\//.exec(executionRoleArn)?.[1];
    if (!accountId) {
      throw new PreviewLambdaError(
        'invalid_lambda_configuration',
        'AWS_PREVIEW_EXECUTION_ROLE_ARN has an invalid role ARN shape',
      );
    }
    const result = reconcilePreviewLambda({
      artifactBucket: environment.AWS_PREVIEW_ARTIFACTS_BUCKET,
      artifactKey: argumentValue(args, '--artifact-key'),
      commitSha: argumentValue(args, '--commit'),
      distributionArn: `arn:aws:cloudfront::${accountId}:distribution/${requiredString(environment.AWS_CLOUDFRONT_DISTRIBUTION_ID, 'AWS_CLOUDFRONT_DISTRIBUTION_ID')}`,
      environmentFile,
      executionRoleArn,
      functionName: argumentValue(args, '--function-name'),
      pullRequestNumber: argumentValue(args, '--pull-request'),
      slug: argumentValue(args, '--slug'),
      sourceBranch: argumentValue(args, '--source-branch'),
      checkpoint: (rollback) => {
        writeFileSync(outputFile, JSON.stringify(rollback), { encoding: 'utf8', mode: 0o600 });
      },
    });
    writeFileSync(outputFile, JSON.stringify(result), { encoding: 'utf8', mode: 0o600 });
    return result;
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = runPreviewLambdaCli(process.argv.slice(2));
    console.log(JSON.stringify({
      apiOrigin: result.apiOrigin,
      functionName: result.functionName,
      installedVersion: result.installedVersion,
      rolledBack: result.rolledBack,
    }));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
