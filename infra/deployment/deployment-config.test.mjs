import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertPinnedActions,
  assertJobPrivileges,
  assertValidationStepConfiguration,
  DeploymentConfigError,
  checkDeploymentContract,
  loadDeploymentContract,
  runDeploymentConfigCli,
  validateDeploymentEnvironment,
  validateWorkflowEnvironment,
  validateWorkflowJobEnvironment,
  workflowJobSources,
  workflowReferences,
  workflowValidationStepSources,
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

test('extracts workflow jobs without merging their configuration', () => {
  const jobs = workflowJobSources(`name: example\njobs:\n  build:\n    env:\n      VALUE: \${{ vars.BUILD }}\n  deploy:\n    env:\n      VALUE: \${{ secrets.DEPLOY }}\n`);
  assert.deepEqual(Object.keys(jobs), ['build', 'deploy']);
  assert.match(jobs.build, /vars\.BUILD/);
  assert.doesNotMatch(jobs.build, /secrets\.DEPLOY/);
});

test('requires validation steps to expose every job value under its contract name', () => {
  const workflow = {
    jobs: {
      deploy: {
        secrets: ['TOKEN'],
        variables: ['ENDPOINT'],
      },
    },
  };
  const source = `jobs:
  deploy:
    steps:
      - name: Verify deployment configuration
        env:
          ENDPOINT: \${{ vars.ENDPOINT }}
        run: node infra/deployment/deployment-config.mjs --validate-job example.deploy
`;
  const validationSources = workflowValidationStepSources(source);
  assert.throws(
    () => assertValidationStepConfiguration('example', workflow, validationSources),
    (error) => error instanceof DeploymentConfigError
      && error.code === 'workflow_validation_step_configuration'
      && error.message.includes('TOKEN'),
  );

  validationSources['example.deploy'] = validationSources['example.deploy'].replace(
    'env:\n',
    'env:\n          TOKEN: ${{ secrets.TOKEN }}\n',
  );
  assert.doesNotThrow(() => {
    assertValidationStepConfiguration('example', workflow, validationSources);
  });
});

test('requires external actions to be pinned to immutable commits', () => {
  assert.doesNotThrow(() => assertPinnedActions('example', '- uses: ./local\n- uses: owner/action@0123456789012345678901234567890123456789'));
  assert.throws(
    () => assertPinnedActions('example', '- uses: owner/action@v1'),
    (error) => error instanceof DeploymentConfigError
      && error.code === 'unpinned_workflow_action'
      && error.message.includes('owner/action@v1'),
  );
});

test('rejects workflow-level OIDC before checking job privileges', () => {
  const source = 'name: example\npermissions:\n  id-token: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n';
  const workflow = { jobs: { build: { environment: false, oidc: false } } };
  assert.throws(
    () => assertJobPrivileges('example', workflow, source, workflowJobSources(source)),
    (error) => error instanceof DeploymentConfigError
      && error.code === 'workflow_level_privilege',
  );
});

test('accepts every workflow with shape-valid configuration', () => {
  const contract = loadDeploymentContract();
  for (const workflowName of Object.keys(contract.workflows)) {
    assert.doesNotThrow(() => {
      validateWorkflowEnvironment(contract, workflowName, environmentFor(contract, workflowName));
    });
  }
});

test('accepts every workflow job with only its declared configuration', () => {
  const contract = loadDeploymentContract();
  for (const [workflowName, workflow] of Object.entries(contract.workflows)) {
    const values = environmentFor(contract, workflowName);
    for (const jobName of Object.keys(workflow.jobs)) {
      assert.doesNotThrow(() => {
        validateWorkflowJobEnvironment(contract, `${workflowName}.${jobName}`, values);
      });
    }
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
