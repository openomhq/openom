import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DeploymentConfigError,
  checkDeploymentContract,
  loadDeploymentContract,
  runDeploymentConfigCli,
  validateDeploymentEnvironment,
  validateWorkflowEnvironment,
  workflowReferences,
} from './deployment-config.mjs';

const validValues = {
  'account-passphrase': 'eight-or-more',
  'aws-arn': 'arn:aws:cloudfront::841547768414:key-value-store/example',
  'aws-region': 'eu-central-1',
  'aws-role-arn': 'arn:aws:iam::841547768414:role/openom-staging-ci-deploy',
  'bucket-name': 'openom-staging',
  'cloudflare-account-id': '0123456789abcdef0123456789abcdef',
  email: 'staging@example.com',
  'https-origin-list': 'https://app.staging.openom.org',
  'https-url': 'https://example.com/path',
  nonempty: 'configured',
  'positive-integer': '5',
  'postgres-url': 'postgresql://user:password@example.com/openom',
};

function environmentFor(contract, workflowName) {
  const workflow = contract.workflows[workflowName];
  return Object.fromEntries(
    [...workflow.secrets, ...workflow.variables].map((name) => [
      name,
      validValues[contract.values[name].validator],
    ]),
  );
}

function valuesForEnvironment(contract, environmentName) {
  const environment = contract.environments[environmentName];
  return Object.fromEntries(
    [...environment.secrets, ...environment.variables].map((name) => [
      name,
      validValues[contract.values[name].validator],
    ]),
  );
}

test('repository workflow references match the deployment contract', () => {
  checkDeploymentContract(loadDeploymentContract());
});

test('extracts unique reference candidates without reading their values', () => {
  const source = '${{ secrets.ONE }} ${{ secrets.TWO }} ${{ secrets.ONE }}';
  assert.deepEqual(workflowReferences(source, 'secrets'), ['ONE', 'TWO', 'ONE']);
});

test('accepts every workflow with shape-valid configuration', () => {
  const contract = loadDeploymentContract();
  for (const workflowName of Object.keys(contract.workflows)) {
    assert.doesNotThrow(() => {
      validateWorkflowEnvironment(contract, workflowName, environmentFor(contract, workflowName));
    });
  }
});

test('accepts every deployment environment with shape-valid configuration', () => {
  const contract = loadDeploymentContract();
  for (const environmentName of Object.keys(contract.environments)) {
    assert.doesNotThrow(() => {
      validateDeploymentEnvironment(
        contract,
        environmentName,
        valuesForEnvironment(contract, environmentName),
      );
    });
  }
});

test('lists only values delivered to the requested environment', () => {
  const output = [];
  runDeploymentConfigCli(['--list', 'preview'], {}, (line) => output.push(line));
  assert.match(output.join('\n'), /NEON_API_KEY/);
  assert.doesNotMatch(output.join('\n'), /DATABASE_URL/);

  output.length = 0;
  runDeploymentConfigCli(['--list', 'staging'], {}, (line) => output.push(line));
  assert.match(output.join('\n'), /DATABASE_URL/);
  assert.doesNotMatch(output.join('\n'), /NEON_API_KEY/);
});

test('reports missing names without exposing configured values', () => {
  const contract = loadDeploymentContract();
  const environment = environmentFor(contract, 'staging.server');
  const privateValue = environment.DATABASE_URL;
  delete environment.DATABASE_URL;

  assert.throws(
    () => validateWorkflowEnvironment(contract, 'staging.server', environment),
    (error) => error instanceof DeploymentConfigError
      && error.code === 'missing_deployment_values'
      && error.message.includes('DATABASE_URL')
      && !error.message.includes(privateValue),
  );
});

test('rejects malformed values without echoing them', () => {
  const contract = loadDeploymentContract();
  const environment = environmentFor(contract, 'staging.web');
  const privateValue = 'not-a-real-secret-value';
  environment.SUPABASE_TEST_EMAIL = privateValue;

  assert.throws(
    () => validateWorkflowEnvironment(contract, 'staging.web', environment),
    (error) => error instanceof DeploymentConfigError
      && error.code === 'invalid_deployment_value'
      && error.message.includes('SUPABASE_TEST_EMAIL')
      && !error.message.includes(privateValue),
  );
});

test('permits an absent optional internal GC token', () => {
  const contract = loadDeploymentContract();
  const environment = environmentFor(contract, 'staging.server');
  delete environment.OPENOM_INTERNAL_GC_TOKEN;
  assert.doesNotThrow(() => {
    validateWorkflowEnvironment(contract, 'staging.server', environment);
  });
});
