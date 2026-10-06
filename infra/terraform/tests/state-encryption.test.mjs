import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const TOFU = process.env.OPENOM_TOFU_BIN || 'tofu';
const FIXTURE_VALUE = 'openom-state-encryption-proof';
const OLD_PASSPHRASE = 'old-proof-passphrase-0123456789abcdef';
const NEW_PASSPHRASE = 'new-proof-passphrase-fedcba9876543210';

function runTofu(root, args, variables = {}, expectSuccess = true) {
  const result = spawnSync(TOFU, [`-chdir=${root}`, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
      TF_IN_AUTOMATION: '1',
      TF_INPUT: '0',
      ...variables,
    },
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`;

  assert.equal(result.error, undefined, `could not run ${TOFU}: ${result.error?.message}`);
  if (expectSuccess) {
    assert.equal(result.status, 0, output);
  } else {
    assert.notEqual(result.status, 0, 'OpenTofu unexpectedly accepted invalid state custody');
  }
  assert.doesNotMatch(output, new RegExp(OLD_PASSPHRASE));
  assert.doesNotMatch(output, new RegExp(NEW_PASSPHRASE));
  return output;
}

function baseConfiguration(encryption = '') {
  return `${encryption}
resource "terraform_data" "proof" {
  input = "${FIXTURE_VALUE}"
}

output "proof" {
  value = terraform_data.proof.output
}
`;
}

function passphraseVariable(name) {
  return `variable "${name}" {
  type      = string
  sensitive = true
  ephemeral = true
}
`;
}

function encryptedConfiguration({ fallback = '', passphrase = 'state_passphrase', provider = 'current', alias = 'openom_state' } = {}) {
  return baseConfiguration(`${passphraseVariable(passphrase)}${fallback.variables || ''}
terraform {
  required_version = ">= 1.13.0"

  encryption {
    ${fallback.method || ''}
    key_provider "pbkdf2" "${provider}" {
      passphrase               = var.${passphrase}
      encrypted_metadata_alias = "${alias}"
    }

    method "aes_gcm" "${provider}" {
      keys = key_provider.pbkdf2.${provider}
    }

    state {
      method   = method.aes_gcm.${provider}
      enforced = ${fallback.enforced ?? true}
      ${fallback.block || ''}
    }
  }
}
`);
}

function migrationConfiguration() {
  return encryptedConfiguration({
    fallback: {
      method: 'method "unencrypted" "migration" {}',
      block: 'fallback { method = method.unencrypted.migration }',
      enforced: false,
    },
  });
}

function rolloverConfiguration() {
  return encryptedConfiguration({
    passphrase: 'new_state_passphrase',
    provider: 'next',
    alias: 'openom_state_next',
    fallback: {
      variables: passphraseVariable('old_state_passphrase'),
      method: `key_provider "pbkdf2" "current" {
      passphrase               = var.old_state_passphrase
      encrypted_metadata_alias = "openom_state"
    }

    method "aes_gcm" "current" {
      keys = key_provider.pbkdf2.current
    }`,
      block: 'fallback { method = method.aes_gcm.current }',
      enforced: true,
    },
  });
}

function assertEncrypted(state, metadataAlias) {
  const envelope = JSON.parse(state);
  assert.deepEqual(Object.keys(envelope).sort(), ['encrypted_data', 'encryption_version', 'lineage', 'meta', 'serial']);
  assert.equal(typeof envelope.encrypted_data, 'string');
  assert.equal(typeof envelope.meta[metadataAlias], 'string');
  assert.doesNotMatch(state, new RegExp(FIXTURE_VALUE));
  assert.doesNotMatch(state, new RegExp(OLD_PASSPHRASE));
  assert.doesNotMatch(state, new RegExp(NEW_PASSPHRASE));
}

test('OpenTofu migrates, enforces, and rotates passphrase-encrypted state', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'openom-tofu-state-encryption-'));
  const configuration = path.join(root, 'main.tf');
  const statePath = path.join(root, 'terraform.tfstate');
  const oldEnvironment = { TF_VAR_state_passphrase: OLD_PASSPHRASE };
  const newEnvironment = { TF_VAR_state_passphrase: NEW_PASSPHRASE };

  try {
    writeFileSync(configuration, baseConfiguration('terraform { required_version = ">= 1.13.0" }\n'));
    runTofu(root, ['init', '-backend=false', '-input=false']);
    runTofu(root, ['apply', '-auto-approve', '-input=false']);
    const plaintextState = readFileSync(statePath, 'utf8');
    assert.match(plaintextState, new RegExp(FIXTURE_VALUE));

    writeFileSync(configuration, migrationConfiguration());
    runTofu(root, ['apply', '-auto-approve', '-input=false'], oldEnvironment);
    const oldEncryptedState = readFileSync(statePath, 'utf8');
    assertEncrypted(oldEncryptedState, 'openom_state');

    writeFileSync(configuration, encryptedConfiguration());
    runTofu(root, ['plan', '-input=false'], oldEnvironment);
    runTofu(root, ['plan', '-input=false'], {}, false);
    runTofu(root, ['plan', '-input=false'], newEnvironment, false);

    writeFileSync(statePath, plaintextState);
    runTofu(root, ['plan', '-input=false'], oldEnvironment, false);
    writeFileSync(statePath, oldEncryptedState);

    writeFileSync(configuration, rolloverConfiguration());
    runTofu(root, ['apply', '-auto-approve', '-input=false'], {
      TF_VAR_old_state_passphrase: OLD_PASSPHRASE,
      TF_VAR_new_state_passphrase: NEW_PASSPHRASE,
    });
    const newEncryptedState = readFileSync(statePath, 'utf8');
    assertEncrypted(newEncryptedState, 'openom_state_next');

    writeFileSync(configuration, encryptedConfiguration({ alias: 'openom_state_next' }));
    runTofu(root, ['plan', '-input=false'], newEnvironment);
    runTofu(root, ['plan', '-input=false'], oldEnvironment, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
