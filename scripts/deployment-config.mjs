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

  const names = uniqueSorted([...workflow.secrets, ...workflow.variables]);
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
    'usage: deployment-config.mjs --check | --validate-workflow <name> | --validate-environment <name> | --list <environment>',
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
