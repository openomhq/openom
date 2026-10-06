#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT_PATH = path.join(ROOT, 'contracts', 'deployment-environments.json');

export class DeploymentConfigError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DeploymentConfigError';
    this.code = code;
  }
}

export function loadDeploymentContract(contractPath = CONTRACT_PATH) {
  return JSON.parse(readFileSync(contractPath, 'utf8'));
}

export function workflowReferences(source, namespace) {
  const pattern = new RegExp(`\\$\\{\\{\\s*${namespace}\\.([A-Z][A-Z0-9_]*)\\s*\\}\\}`, 'g');
  return [...source.matchAll(pattern)].map((match) => match[1]);
}

export function workflowJobSources(source) {
  const lines = source.split(/\r?\n/);
  const jobs = {};
  let inJobs = false;
  let jobName;

  for (const line of lines) {
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    if (/^[^\s#]/.test(line)) break;

    const jobMatch = line.match(/^  ([A-Za-z0-9_-]+):\s*$/);
    if (jobMatch) {
      jobName = jobMatch[1];
      jobs[jobName] = `${line}\n`;
    } else if (jobName) {
      jobs[jobName] += `${line}\n`;
    }
  }

  return jobs;
}

export function workflowValidationStepSources(source) {
  const lines = source.split(/\r?\n/);
  const steps = {};
  let stepSource = '';

  const collect = () => {
    const match = stepSource.match(/--validate-job\s+([A-Za-z0-9_.-]+)/);
    if (match) steps[match[1]] = stepSource;
  };

  for (const line of lines) {
    if (/^      - /.test(line)) {
      collect();
      stepSource = `${line}\n`;
    } else if (stepSource) {
      stepSource += `${line}\n`;
    }
  }
  collect();
  return steps;
}

function validationEnvironmentReferences(source) {
  return Object.fromEntries([...source.matchAll(
    /^          ([A-Z][A-Z0-9_]*):\s*\$\{\{\s*(secrets|vars)\.([A-Z][A-Z0-9_]*)\s*\}\}\s*$/gm,
  )].map((match) => [match[1], `${match[2]}.${match[3]}`]));
}

export function assertPinnedActions(workflowName, source) {
  const unpinned = [...source.matchAll(/^\s*-?\s*uses:\s*([^\s#]+).*$/gm)]
    .map((match) => match[1])
    .filter((reference) => !reference.startsWith('./'))
    .filter((reference) => !/@[a-f0-9]{40}$/.test(reference));
  if (unpinned.length === 0) return;
  throw new DeploymentConfigError(
    'unpinned_workflow_action',
    `${workflowName} contains actions that are not pinned to a commit: ${uniqueSorted(unpinned).join(', ')}`,
  );
}

export function assertJobPrivileges(workflowName, workflow, source, jobSources) {
  const preamble = source.slice(0, source.indexOf('\njobs:'));
  if (/\$\{\{\s*(?:secrets|vars)\./.test(preamble) || /^\s+id-token:\s*write\s*$/m.test(preamble)) {
    throw new DeploymentConfigError(
      'workflow_level_privilege',
      `${workflowName} must grant environment configuration and OIDC only to individual jobs`,
    );
  }

  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    const jobSource = jobSources[jobName];
    const hasEnvironment = /^    environment:(?:\s*\S+)?\s*$/m.test(jobSource);
    const hasOidc = /^      id-token:\s*write\s*$/m.test(jobSource);
    if (hasEnvironment !== job.environment || hasOidc !== job.oidc) {
      throw new DeploymentConfigError(
        'workflow_job_privilege_drift',
        `${workflowName}.${jobName} privilege boundary drifted (environment=${hasEnvironment}, oidc=${hasOidc})`,
      );
    }
  }
}

export function assertValidationStepConfiguration(workflowName, workflow, validationSources) {
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    const expected = [
      ...job.secrets.map((name) => [name, `secrets.${name}`]),
      ...job.variables.map((name) => [name, `vars.${name}`]),
    ];
    if (expected.length === 0) continue;

    const workflowJobName = `${workflowName}.${jobName}`;
    const source = validationSources[workflowJobName];
    if (!source) {
      throw new DeploymentConfigError(
        'workflow_validation_step_missing',
        `${workflowJobName} must validate its deployment configuration`,
      );
    }
    const actual = validationEnvironmentReferences(source);
    const invalid = expected.filter(([name, reference]) => actual[name] !== reference);
    if (invalid.length > 0) {
      throw new DeploymentConfigError(
        'workflow_validation_step_configuration',
        `${workflowJobName} validation step must expose: ${invalid.map(([name]) => name).join(', ')}`,
      );
    }
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function assertSameNames(workflowName, namespace, expected, actual) {
  const expectedNames = uniqueSorted(expected);
  const actualNames = uniqueSorted(actual);
  if (JSON.stringify(expectedNames) === JSON.stringify(actualNames)) return;

  const expectedSet = new Set(expectedNames);
  const actualSet = new Set(actualNames);
  const missing = expectedNames.filter((name) => !actualSet.has(name));
  const undeclared = actualNames.filter((name) => !expectedSet.has(name));
  const details = [
    missing.length > 0 ? `missing from workflow: ${missing.join(', ')}` : '',
    undeclared.length > 0 ? `undeclared in contract: ${undeclared.join(', ')}` : '',
  ].filter(Boolean).join('; ');
  throw new DeploymentConfigError(
    'workflow_contract_drift',
    `${workflowName} ${namespace} references drifted (${details})`,
  );
}

export function checkDeploymentContract(contract, root = ROOT) {
  for (const [environmentName, environment] of Object.entries(contract.environments)) {
    for (const namespace of ['secrets', 'variables', 'adminSecrets']) {
      for (const name of environment[namespace]) {
        if (!contract.values[name]) {
          throw new DeploymentConfigError(
            'unknown_environment_value',
            `${environmentName} ${namespace} contains undeclared value ${name}`,
          );
        }
      }
    }
  }

  for (const [workflowName, workflow] of Object.entries(contract.workflows)) {
    const environment = contract.environments[workflow.environment];
    if (!environment) {
      throw new DeploymentConfigError(
        'unknown_workflow_environment',
        `${workflowName} uses unknown environment ${workflow.environment}`,
      );
    }
    const source = readFileSync(path.join(root, workflow.file), 'utf8');
    assertPinnedActions(workflowName, source);
    assertSameNames(
      workflowName,
      'secrets',
      workflow.secrets,
      workflowReferences(source, 'secrets'),
    );
    assertSameNames(
      workflowName,
      'vars',
      workflow.variables,
      workflowReferences(source, 'vars'),
    );

    const jobSources = workflowJobSources(source);
    assertSameNames(workflowName, 'jobs', Object.keys(workflow.jobs), Object.keys(jobSources));
    assertJobPrivileges(workflowName, workflow, source, jobSources);
    assertValidationStepConfiguration(
      workflowName,
      workflow,
      workflowValidationStepSources(source),
    );
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      assertSameNames(
        `${workflowName}.${jobName}`,
        'secrets',
        job.secrets,
        workflowReferences(jobSources[jobName], 'secrets'),
      );
      assertSameNames(
        `${workflowName}.${jobName}`,
        'vars',
        job.variables,
        workflowReferences(jobSources[jobName], 'vars'),
      );
    }

    for (const name of workflow.secrets) {
      if (!environment.secrets.includes(name)) {
        throw new DeploymentConfigError(
          'invalid_secret_contract',
          `${name} must be declared as a ${workflow.environment} GitHub-delivered secret`,
        );
      }
    }
    for (const name of workflow.variables) {
      if (!environment.variables.includes(name)) {
        throw new DeploymentConfigError(
          'invalid_variable_contract',
          `${name} must be declared as a ${workflow.environment} GitHub environment variable`,
        );
      }
    }
  }
}

function parsedUrl(name, value) {
  try {
    return new URL(value);
  } catch {
    throw new DeploymentConfigError('invalid_deployment_value', `${name} has an invalid URL shape`);
  }
}

function validateValue(name, value, validator) {
  if (value.length === 0) {
    throw new DeploymentConfigError('missing_deployment_value', `${name} is empty`);
  }
  if (validator === 'nonempty') return;
  if (validator === 'postgres-url') {
    const protocol = parsedUrl(name, value).protocol;
    if (protocol === 'postgres:' || protocol === 'postgresql:') return;
  } else if (validator === 'https-url') {
    if (parsedUrl(name, value).protocol === 'https:') return;
  } else if (validator === 'https-origin-list') {
    const origins = value.split(',').map((origin) => origin.trim()).filter(Boolean);
    if (origins.length > 0 && origins.every((origin) => {
      const url = parsedUrl(name, origin);
      return url.protocol === 'https:' && url.origin === origin;
    })) return;
  } else if (validator === 'aws-role-arn') {
    if (/^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(value)) return;
  } else if (validator === 'aws-arn') {
    if (/^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+$/.test(value)) return;
  } else if (validator === 'aws-region') {
    if (/^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/.test(value)) return;
  } else if (validator === 'email') {
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return;
  } else if (validator === 'account-passphrase') {
    if (value.length >= 8) return;
  } else if (validator === 'bucket-name') {
    if (/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)) return;
  } else if (validator === 'cloudflare-account-id') {
    if (/^[a-f0-9]{32}$/i.test(value)) return;
  } else if (validator === 'positive-integer') {
    if (/^[1-9][0-9]*$/.test(value)) return;
  } else {
    throw new DeploymentConfigError(
      'unknown_deployment_validator',
      `${name} uses unknown validator ${validator}`,
    );
  }
  throw new DeploymentConfigError(
    'invalid_deployment_value',
    `${name} does not match its required ${validator} shape`,
  );
}

export function validateWorkflowEnvironment(contract, workflowName, environment) {
  const workflow = contract.workflows[workflowName];
  if (!workflow) {
    throw new DeploymentConfigError('unknown_workflow', `unknown workflow ${workflowName}`);
  }

  validateNames(contract, [...workflow.secrets, ...workflow.variables], environment);
}

function validateNames(contract, configuredNames, environment) {
  const names = uniqueSorted(configuredNames);
  const missing = names.filter((name) => {
    const definition = contract.values[name];
    return definition.required && (!environment[name] || environment[name].length === 0);
  });
  if (missing.length > 0) {
    throw new DeploymentConfigError(
      'missing_deployment_values',
      `missing deployment configuration: ${missing.join(', ')}`,
    );
  }

  for (const name of names) {
    const value = environment[name];
    if (!value) continue;
    validateValue(name, value, contract.values[name].validator);
  }
}

export function validateWorkflowJobEnvironment(contract, workflowJobName, environment) {
  const separator = workflowJobName.lastIndexOf('.');
  const workflowName = workflowJobName.slice(0, separator);
  const jobName = workflowJobName.slice(separator + 1);
  const workflow = contract.workflows[workflowName];
  const job = workflow?.jobs[jobName];
  if (!workflow || !job) {
    throw new DeploymentConfigError('unknown_workflow_job', `unknown workflow job ${workflowJobName}`);
  }
  validateNames(contract, [...job.secrets, ...job.variables], environment);
}

export function validateDeploymentEnvironment(contract, environmentName, environment) {
  const definition = contract.environments[environmentName];
  if (!definition) {
    throw new DeploymentConfigError('unknown_environment', `unknown environment ${environmentName}`);
  }
  const names = uniqueSorted([...definition.secrets, ...definition.variables]);
  const missing = names.filter((name) => {
    const value = contract.values[name];
    return value.required && (!environment[name] || environment[name].length === 0);
  });
  if (missing.length > 0) {
    throw new DeploymentConfigError(
      'missing_deployment_values',
      `missing deployment configuration: ${missing.join(', ')}`,
    );
  }
  for (const name of names) {
    const value = environment[name];
    if (!value) continue;
    validateValue(name, value, contract.values[name].validator);
  }
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new DeploymentConfigError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export function runDeploymentConfigCli(args, environment = process.env, write = console.log) {
  const contract = loadDeploymentContract();
  if (args.includes('--check')) {
    checkDeploymentContract(contract);
    write('deployment configuration contract is in sync');
    return;
  }

  const workflowName = argumentValue(args, '--validate-workflow');
  if (workflowName) {
    validateWorkflowEnvironment(contract, workflowName, environment);
    write(`${workflowName} deployment configuration is valid`);
    return;
  }

  const workflowJobName = argumentValue(args, '--validate-job');
  if (workflowJobName) {
    validateWorkflowJobEnvironment(contract, workflowJobName, environment);
    write(`${workflowJobName} deployment configuration is valid`);
    return;
  }

  const validatedEnvironmentName = argumentValue(args, '--validate-environment');
  if (validatedEnvironmentName) {
    validateDeploymentEnvironment(contract, validatedEnvironmentName, environment);
    write(`${validatedEnvironmentName} deployment configuration is valid`);
    return;
  }

  const environmentName = argumentValue(args, '--list');
  if (environmentName) {
    if (!contract.environments[environmentName]) {
      throw new DeploymentConfigError('unknown_environment', `unknown environment ${environmentName}`);
    }
    const definition = contract.environments[environmentName];
    for (const [label, namespace] of [
      ['secret', 'secrets'],
      ['variable', 'variables'],
      ['admin-secret', 'adminSecrets'],
    ]) {
      write(`${label}: ${[...definition[namespace]].sort().join(', ')}`);
    }
    return;
  }

  throw new DeploymentConfigError(
    'missing_command',
    'usage: deployment-config.mjs --check | --validate-workflow <name> | --validate-job <workflow.job> | --validate-environment <name> | --list <environment>',
  );
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runDeploymentConfigCli(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Deploy] ${message}`);
    process.exitCode = 1;
  }
}
