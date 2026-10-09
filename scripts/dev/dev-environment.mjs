#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ENV_FILE = path.join(REPO, '.env');
const ENV_EXAMPLE = path.join(REPO, '.env.example');
const TASK_DIR = path.join(REPO, '.task');
const DEV_STATE_DIR = path.join(REPO, 'tmp', 'dev');
const RESTART_MARKER = path.join(DEV_STATE_DIR, 'server.rs');

function parseEnv(text) {
  const values = new Map();
  for (const raw of text.split(/\r?\n/u)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    values.set(key, value);
  }
  return values;
}

function replaceEnvValue(text, key, value) {
  const replacement = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, 'mu');
  if (pattern.test(text)) return text.replace(pattern, replacement);
  return `${text.trimEnd()}${os.EOL}${replacement}${os.EOL}`;
}

function commandResult(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: REPO,
    encoding: 'utf8',
    ...options,
  });
}

function dockerAvailable() {
  const result = commandResult('docker', ['version', '--format', '{{.Server.Version}}']);
  return result.status === 0 && result.stdout.trim().length > 0;
}

function localDevelopmentAvailable() {
  const watcher = commandResult('watchexec', ['--version']);
  if (watcher.status !== 0) return { ok: false, reason: 'Watchexec is unavailable' };

  fs.mkdirSync(TASK_DIR, { recursive: true });
  const source = path.join(TASK_DIR, 'runner-probe.rs');
  const executable = path.join(TASK_DIR, process.platform === 'win32' ? 'runner-probe.exe' : 'runner-probe');
  fs.writeFileSync(source, 'fn main() {}\n');

  const compiled = commandResult('rustc', [source, '-o', executable]);
  if (compiled.status !== 0) return { ok: false, reason: 'Rust could not compile a local probe' };

  const executed = commandResult(executable, []);
  try {
    fs.rmSync(source, { force: true });
    fs.rmSync(executable, { force: true });
  } catch {
    // A policy scanner may retain the denied executable briefly; .task is disposable.
  }
  if (executed.status !== 0) {
    const reason = executed.error?.code || executed.error?.message || `exit ${executed.status}`;
    return { ok: false, reason: `fresh local executables cannot run (${reason})` };
  }
  return { ok: true };
}

function ensureEnvironment() {
  let created = false;
  if (!fs.existsSync(ENV_FILE)) {
    fs.copyFileSync(ENV_EXAMPLE, ENV_FILE);
    created = true;
    console.log('[dev] created .env from .env.example');
  }

  let text = fs.readFileSync(ENV_FILE, 'utf8');
  const fileRunner = parseEnv(text).get('OPENOM_RUNNER') || 'auto';
  const inheritedRunner = process.env.OPENOM_RUNNER;
  const shellOverride = inheritedRunner && inheritedRunner !== fileRunner ? inheritedRunner : undefined;
  const requested = (shellOverride || fileRunner).toLowerCase();

  if (requested === 'local' || requested === 'docker') {
    return { runner: requested, created, persisted: !shellOverride };
  }
  if (requested !== 'auto') {
    console.error(`OPENOM_RUNNER must be auto, local, or docker; received ${requested}`);
    process.exit(2);
  }

  const local = localDevelopmentAvailable();
  let selected;
  if (local.ok) {
    selected = 'local';
  } else if (dockerAvailable()) {
    selected = 'docker';
    console.log(`[dev] selecting Docker: ${local.reason}`);
  } else {
    console.error(`[dev] local development is unavailable: ${local.reason}`);
    console.error('[dev] install Watchexec and the Rust toolchain, or start Docker, then rerun task setup');
    process.exit(1);
  }

  text = replaceEnvValue(text, 'OPENOM_RUNNER', selected);
  fs.writeFileSync(ENV_FILE, text);
  console.log(`[dev] persisted OPENOM_RUNNER=${selected} in .env`);
  return { runner: selected, created, persisted: true };
}

function prepareRestartMarker() {
  fs.mkdirSync(DEV_STATE_DIR, { recursive: true });
  if (!fs.existsSync(RESTART_MARKER)) fs.writeFileSync(RESTART_MARKER, 'ready\n');
}

function signalServerRestart() {
  prepareRestartMarker();
  fs.writeFileSync(RESTART_MARKER, `${new Date().toISOString()}\n`);
  console.log('[dev] signalled any native development server to restart and rerun migrations');

  const runningContainer = commandResult(
    'docker',
    ['compose', 'ps', '--status', 'running', '--quiet', 'server'],
  );
  if (runningContainer.status !== 0 || runningContainer.stdout.trim().length === 0) return;

  console.log('[dev] restarting the Docker development server to rerun migrations');
  const restarted = spawnSync('docker', ['compose', 'restart', 'server'], {
    cwd: REPO,
    stdio: 'inherit',
  });
  if (restarted.error || restarted.status !== 0) {
    console.error(restarted.error?.message || 'Docker development server restart failed');
    process.exit(restarted.status ?? 1);
  }
}

function runSelectedTask(taskName) {
  const allowed = new Set(['dev', 'dev:desktop', 'dev:server']);
  if (!allowed.has(taskName)) {
    console.error(`unsupported development task: ${taskName}`);
    process.exit(2);
  }
  const { runner } = ensureEnvironment();
  const result = spawnSync('task', [`${taskName}:${runner}`], {
    cwd: REPO,
    env: { ...process.env, OPENOM_RUNNER: runner },
    stdio: 'inherit',
  });
  if (result.error) console.error(result.error.message);
  process.exit(result.status ?? 1);
}

const [command, argument] = process.argv.slice(2);
switch (command) {
  case 'configure': {
    const { runner } = ensureEnvironment();
    prepareRestartMarker();
    console.log(`[dev] runner=${runner}`);
    break;
  }
  case 'prepare':
    prepareRestartMarker();
    break;
  case 'restart-server':
    signalServerRestart();
    break;
  case 'run':
    runSelectedTask(argument);
    break;
  default:
    console.error('usage: node scripts/dev/dev-environment.mjs configure|prepare|restart-server|run <task>');
    process.exit(2);
}
