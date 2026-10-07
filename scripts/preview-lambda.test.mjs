import assert from 'node:assert/strict';
import test from 'node:test';

import {
  deletePreviewLambda,
  lambdaEnvironment,
  listPreviewLambdas,
  PreviewLambdaError,
  reconcilePreviewLambda,
  rollbackPreviewLambda,
} from './preview-lambda.mjs';
import { previewIdentity } from './preview-name.mjs';

const FUNCTION_NAME = 'openom-preview-feat-ope-637-api';
const FUNCTION_ARN = `arn:aws:lambda:eu-central-1:841547768414:function:${FUNCTION_NAME}`;
const DISTRIBUTION_ARN = 'arn:aws:cloudfront::841547768414:distribution/E123456789';
const FUNCTION_URL = 'https://abc123.lambda-url.eu-central-1.on.aws/';
const CONFIG = Object.freeze({
  artifactBucket: 'openom-preview-artifacts',
  artifactKey: 'previews/feat-ope-637/0123456789abcdef0123456789abcdef01234567.zip',
  commitSha: '0123456789abcdef0123456789abcdef01234567',
  distributionArn: DISTRIBUTION_ARN,
  environmentFile: '/tmp/environment.json',
  executionRoleArn: 'arn:aws:iam::841547768414:role/openom-preview-api-exec',
  functionName: FUNCTION_NAME,
  pullRequestNumber: 42,
  slug: 'feat-ope-637',
  sourceBranch: 'feat/ope-637',
});

const OWNER_TAGS = Object.freeze({
  'openom-preview-pull-request': '42',
  'openom-preview-slug': 'feat-ope-637',
  'openom-preview-source-branch': 'feat/ope-637',
});

function result(status = 0, body = {}, stderr = '') {
  return { status, stderr, stdout: JSON.stringify(body) };
}

function operation(args) {
  return `${args[0]} ${args[1]}`;
}

function argument(args, name) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

function missing() {
  return result(254, {}, 'ResourceNotFoundException');
}

function matchingPolicy() {
  return {
    Statement: [
      {
        Action: 'lambda:InvokeFunctionUrl',
        Condition: {
          ArnLike: { 'AWS:SourceArn': DISTRIBUTION_ARN },
          StringEquals: { 'lambda:FunctionUrlAuthType': 'AWS_IAM' },
        },
        Effect: 'Allow',
        Principal: { Service: 'cloudfront.amazonaws.com' },
        Sid: 'AllowCloudFrontInvokeFunctionUrl',
      },
      {
        Action: 'lambda:InvokeFunction',
        Condition: { ArnLike: { 'AWS:SourceArn': DISTRIBUTION_ARN } },
        Effect: 'Allow',
        Principal: { Service: 'cloudfront.amazonaws.com' },
        Sid: 'AllowCloudFrontInvokeFunction',
      },
    ],
  };
}

test('creates a protected aliased function and both CloudFront grants', () => {
  const calls = [];
  const execute = (binary, args) => {
    assert.equal(binary, 'aws');
    calls.push(args);
    switch (operation(args)) {
      case 'lambda get-function': return missing();
      case 'logs create-log-group':
      case 'logs put-retention-policy':
      case 'lambda wait':
      case 'lambda create-alias':
      case 'lambda add-permission':
      case 'lambda tag-resource': return result();
      case 'lambda create-function': return result(0, { Version: '1' });
      case 'lambda get-function-url-config': return missing();
      case 'lambda create-function-url-config': return result(0, {
        AuthType: 'AWS_IAM',
        FunctionUrl: FUNCTION_URL,
        InvokeMode: 'BUFFERED',
      });
      case 'lambda get-policy': return missing();
      case 'lambda get-function-configuration': return result(0, { FunctionArn: FUNCTION_ARN });
      default: throw new Error(`unexpected command: ${operation(args)}`);
    }
  };

  const deployed = reconcilePreviewLambda({ ...CONFIG, execute });
  assert.deepEqual(deployed, {
    apiOrigin: 'abc123.lambda-url.eu-central-1.on.aws',
    functionArn: FUNCTION_ARN,
    functionName: FUNCTION_NAME,
    functionUrl: FUNCTION_URL,
    installedVersion: '1',
    previousVersion: null,
  });

  const create = calls.find((args) => operation(args) === 'lambda create-function');
  assert.equal(argument(create, '--role'), CONFIG.executionRoleArn);
  assert.equal(argument(create, '--environment'), 'file:///tmp/environment.json');
  assert.deepEqual(JSON.parse(argument(create, '--tags')), OWNER_TAGS);
  const url = calls.find((args) => operation(args) === 'lambda create-function-url-config');
  assert.equal(argument(url, '--auth-type'), 'AWS_IAM');
  assert.equal(argument(url, '--qualifier'), 'live');

  const permissions = calls.filter((args) => operation(args) === 'lambda add-permission');
  assert.equal(permissions.length, 2);
  assert.ok(permissions.every((args) => argument(args, '--source-arn') === DISTRIBUTION_ARN));
  assert.ok(permissions.every((args) => argument(args, '--principal') === 'cloudfront.amazonaws.com'));
  assert.equal(argument(permissions[0], '--function-url-auth-type'), 'AWS_IAM');
  assert.equal(argument(permissions[1], '--function-url-auth-type'), undefined);
});

test('updates configuration before code and atomically promotes the live alias', () => {
  const operations = [];
  const calls = [];
  const checkpoints = [];
  const execute = (binary, args) => {
    calls.push(args);
    operations.push(operation(args));
    switch (operation(args)) {
      case 'lambda get-function': return result(0, {
        Configuration: { FunctionArn: FUNCTION_ARN },
        Tags: OWNER_TAGS,
      });
      case 'lambda get-alias': return result(0, { FunctionVersion: '7' });
      case 'logs create-log-group': return result(254, {}, 'ResourceAlreadyExistsException');
      case 'logs put-retention-policy':
      case 'lambda update-function-configuration':
      case 'lambda wait':
      case 'lambda update-alias':
      case 'lambda tag-resource': return result();
      case 'lambda update-function-code': return result(0, { Version: '8' });
      case 'lambda get-function-url-config': return result(0, {
        AuthType: 'AWS_IAM',
        FunctionUrl: FUNCTION_URL,
        InvokeMode: 'BUFFERED',
      });
      case 'lambda get-policy': return result(0, { Policy: JSON.stringify(matchingPolicy()) });
      default: throw new Error(`unexpected command: ${operation(args)}`);
    }
  };

  const deployed = reconcilePreviewLambda({
    ...CONFIG,
    checkpoint: (rollback) => {
      operations.push('checkpoint');
      checkpoints.push(rollback);
    },
    execute,
  });
  assert.equal(deployed.previousVersion, '7');
  assert.equal(deployed.installedVersion, '8');
  assert.deepEqual(checkpoints, [{
    functionName: FUNCTION_NAME,
    installedVersion: '8',
    previousVersion: '7',
  }]);
  assert.ok(
    operations.indexOf('lambda update-function-configuration')
      < operations.indexOf('lambda update-function-code'),
  );
  assert.ok(
    operations.indexOf('lambda update-function-code') < operations.indexOf('lambda update-alias'),
  );
  assert.ok(operations.indexOf('lambda update-alias') < operations.indexOf('checkpoint'));
  assert.ok(operations.indexOf('checkpoint') < operations.indexOf('lambda get-function-url-config'));
  assert.equal(operations.filter((value) => value === 'lambda add-permission').length, 0);
  const configuration = calls.find((args) => operation(args) === 'lambda update-function-configuration');
  const code = calls.find((args) => operation(args) === 'lambda update-function-code');
  assert.equal(argument(configuration, '--architectures'), undefined);
  assert.equal(argument(code, '--architectures'), 'arm64');
});

test('reports safe AWS CLI diagnostics when an update command is rejected locally', () => {
  const execute = (binary, args) => {
    switch (operation(args)) {
      case 'lambda get-function': return result(0, {
        Configuration: { FunctionArn: FUNCTION_ARN },
        Tags: OWNER_TAGS,
      });
      case 'lambda get-alias': return result(0, { FunctionVersion: '7' });
      case 'logs create-log-group': return result(254, {}, 'ResourceAlreadyExistsException');
      case 'logs put-retention-policy': return result();
      case 'lambda update-function-configuration': return result(
        252,
        {},
        'Unknown options: arm64, --architectures',
      );
      default: throw new Error(`unexpected command: ${operation(args)}`);
    }
  };

  assert.throws(
    () => reconcilePreviewLambda({ ...CONFIG, execute }),
    (error) => error instanceof PreviewLambdaError
      && error.code === 'aws_command_failed'
      && error.message === 'Lambda configuration update failed: Unknown options: arm64, --architectures',
  );
});

test('rejects a same-named function with different ownership before any mutation', () => {
  const operations = [];
  const execute = (binary, args) => {
    operations.push(operation(args));
    if (operation(args) === 'lambda get-function') {
      return result(0, {
        Configuration: { FunctionArn: FUNCTION_ARN },
        Tags: { ...OWNER_TAGS, 'openom-preview-pull-request': '99' },
      });
    }
    throw new Error('ownership rejection must stop mutation');
  };
  assert.throws(
    () => reconcilePreviewLambda({ ...CONFIG, execute }),
    (error) => error instanceof PreviewLambdaError && error.code === 'preview_lambda_owner_mismatch',
  );
  assert.deepEqual(operations, ['lambda get-function']);
});

test('repairs a stale CloudFront permission rather than accepting its statement id', () => {
  const operations = [];
  const stalePolicy = matchingPolicy();
  stalePolicy.Statement[0].Condition.ArnLike['AWS:SourceArn'] = 'arn:aws:cloudfront::841547768414:distribution/OLD';
  const execute = (binary, args) => {
    operations.push([operation(args), args]);
    switch (operation(args)) {
      case 'lambda get-function': return result(0, {
        Configuration: { FunctionArn: FUNCTION_ARN },
        Tags: OWNER_TAGS,
      });
      case 'lambda get-alias': return result(0, { FunctionVersion: '7' });
      case 'logs create-log-group':
      case 'logs put-retention-policy':
      case 'lambda update-function-configuration':
      case 'lambda wait':
      case 'lambda update-alias':
      case 'lambda remove-permission':
      case 'lambda add-permission':
      case 'lambda tag-resource': return result();
      case 'lambda update-function-code': return result(0, { Version: '8' });
      case 'lambda get-function-url-config': return result(0, {
        AuthType: 'AWS_IAM', FunctionUrl: FUNCTION_URL, InvokeMode: 'BUFFERED',
      });
      case 'lambda get-policy': return result(0, { Policy: JSON.stringify(stalePolicy) });
      default: throw new Error(`unexpected command: ${operation(args)}`);
    }
  };
  reconcilePreviewLambda({ ...CONFIG, execute });
  assert.equal(operations.filter(([name]) => name === 'lambda remove-permission').length, 1);
  assert.equal(operations.filter(([name]) => name === 'lambda add-permission').length, 1);
});

test('rolls an update back only while the installed alias version is still current', () => {
  const operations = [];
  const execute = (binary, args) => {
    operations.push(operation(args));
    if (operation(args) === 'lambda get-alias') return result(0, { FunctionVersion: '8' });
    if (operation(args) === 'lambda update-alias') return result();
    throw new Error(`unexpected command: ${operation(args)}`);
  };
  rollbackPreviewLambda({
    execute,
    rollback: { functionName: FUNCTION_NAME, installedVersion: '8', previousVersion: '7' },
  });
  assert.deepEqual(operations, ['lambda get-alias', 'lambda update-alias']);

  assert.throws(
    () => rollbackPreviewLambda({
      execute: () => result(0, { FunctionVersion: '9' }),
      rollback: { functionName: FUNCTION_NAME, installedVersion: '8', previousVersion: '7' },
    }),
    (error) => error instanceof PreviewLambdaError && error.code === 'preview_lambda_changed',
  );
});

test('deletes a newly created function and log group on rollback', () => {
  const operations = [];
  const execute = (binary, args) => {
    operations.push(operation(args));
    if (operation(args) === 'lambda get-alias') return result(0, { FunctionVersion: '1' });
    return result();
  };
  rollbackPreviewLambda({
    execute,
    rollback: { functionName: FUNCTION_NAME, installedVersion: '1', previousVersion: null },
  });
  assert.deepEqual(operations, [
    'lambda get-alias',
    'lambda delete-function-url-config',
    'lambda delete-alias',
    'lambda delete-function',
    'logs delete-log-group',
  ]);
});

test('builds a remote JWT environment without enabling dev auth or telemetry', () => {
  const environment = lambdaEnvironment({
    appUrl: 'https://feat-ope-637.app.dev.openom.org',
    databaseUrl: 'postgresql://owner:password@example.test/neondb',
    jwksUrl: 'https://auth.example.test/.well-known/jwks.json',
    jwtAudience: 'authenticated',
    jwtIssuer: 'https://auth.example.test/auth/v1',
    objectStoreKeyPrefix: 'previews/feat-ope-637/',
    r2AccessKeyId: 'access',
    r2Bucket: 'openom-preview',
    r2Endpoint: 'https://account.r2.cloudflarestorage.com',
    r2SecretAccessKey: 'secret',
    slug: 'feat-ope-637',
  });
  assert.equal(environment.Variables.AUTH_JWT_ALG, 'ES256');
  assert.equal(environment.Variables.OPENOM_RUNTIME, 'remote');
  assert.equal(environment.Variables.OBJECT_STORE_KEY_PREFIX, 'previews/feat-ope-637/');
  assert.equal(environment.Variables.OPENOM_WEB_ORIGINS, 'https://feat-ope-637.app.dev.openom.org');
  assert.equal(environment.Variables.AUTH, 'jwt');
  assert.equal(environment.Variables.STORAGE, 'cloud');
  assert.equal(environment.Variables.OPENOM_OTEL, undefined);
});

test('deletes only an owned preview function and its log group', () => {
  const operations = [];
  const execute = (binary, args) => {
    operations.push(operation(args));
    if (operation(args) === 'lambda get-function') {
      return result(0, { Configuration: { FunctionArn: FUNCTION_ARN }, Tags: OWNER_TAGS });
    }
    return result();
  };
  assert.deepEqual(deletePreviewLambda({
    execute,
    functionName: FUNCTION_NAME,
    pullRequestNumber: 42,
    slug: 'feat-ope-637',
    sourceBranch: 'feat/ope-637',
  }), { deleted: true });
  assert.deepEqual(operations, [
    'lambda get-function',
    'lambda delete-function',
    'logs delete-log-group',
  ]);
});

test('refuses to delete a preview function owned by another pull request', () => {
  assert.throws(
    () => deletePreviewLambda({
      execute: () => result(0, {
        Configuration: { FunctionArn: FUNCTION_ARN },
        Tags: { ...OWNER_TAGS, 'openom-preview-pull-request': '99' },
      }),
      functionName: FUNCTION_NAME,
      pullRequestNumber: 42,
      slug: 'feat-ope-637',
      sourceBranch: 'feat/ope-637',
    }),
    (error) => error instanceof PreviewLambdaError && error.code === 'preview_lambda_owner_mismatch',
  );
});

test('discovers only owned ephemeral preview API functions', () => {
  const operations = [];
  const execute = (binary, args) => {
    operations.push([operation(args), argument(args, '--function-name')]);
    if (operation(args) === 'lambda list-functions') {
      return result(0, {
        Functions: [
          { FunctionName: 'openom-preview-sink' },
          { FunctionName: 'openom-preview-feat-ope-637-worker' },
          { FunctionName: FUNCTION_NAME },
        ],
      });
    }
    if (operation(args) === 'lambda get-function') {
      return result(0, { Configuration: { FunctionArn: FUNCTION_ARN }, Tags: OWNER_TAGS });
    }
    throw new Error(`unexpected command: ${operation(args)}`);
  };

  assert.deepEqual(listPreviewLambdas({ execute }), [previewIdentity('feat/ope-637', 42)]);
  assert.deepEqual(operations, [
    ['lambda list-functions', undefined],
    ['lambda get-function', FUNCTION_NAME],
  ]);
});
