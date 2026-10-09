import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const taskfile = fs.readFileSync(new URL('../Taskfile.yml', import.meta.url), 'utf8');
const compose = fs.readFileSync(new URL('../docker-compose.yml', import.meta.url), 'utf8');
const desktopCompose = fs.readFileSync(new URL('../compose.desktop.yml', import.meta.url), 'utf8');
const devEnvironment = fs.readFileSync(new URL('./dev-environment.mjs', import.meta.url), 'utf8');
const desktopEntrypoint = fs.readFileSync(new URL('../apps/src-tauri/dev-container.sh', import.meta.url), 'utf8');
const serverImage = fs.readFileSync(new URL('../openom/Dockerfile', import.meta.url), 'utf8');
const tauriImage = fs.readFileSync(new URL('../apps/src-tauri/tauri.Dockerfile', import.meta.url), 'utf8');
const tauriConfig = JSON.parse(fs.readFileSync(new URL('../apps/src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
const mainWorkflow = fs.readFileSync(new URL('../.github/workflows/ci.main.yml', import.meta.url), 'utf8');
const webWorkflow = fs.readFileSync(new URL('../.github/workflows/ci.web.yml', import.meta.url), 'utf8');

function taskSection(task) {
  const start = taskfile.indexOf(`  ${task}:`);
  assert.notEqual(start, -1, `Taskfile must define ${task}`);
  const remainder = taskfile.slice(start);
  const headerEnd = remainder.indexOf('\n') + 1;
  const next = remainder.slice(headerEnd).search(/\n  \S[^\n]*:\r?\n/u);
  return remainder.slice(0, next < 0 ? undefined : headerEnd + next);
}

test('Taskfile exposes one setup and development entry point with explicit specializations', () => {
  for (const task of ['setup', 'dev', 'dev:web', 'dev:desktop', 'dev:server']) {
    assert.match(taskfile, new RegExp(`^  ${task}:`, 'mu'));
  }
  assert.match(taskfile, /dev-environment\.mjs run dev/u);
  assert.match(taskfile, /dev-environment\.mjs run dev:desktop/u);
  assert.match(taskfile, /dev-environment\.mjs run dev:server/u);
});

test('development runner can invoke every selected task specialization', () => {
  for (const task of ['dev', 'dev:desktop', 'dev:server']) {
    assert.ok(devEnvironment.includes(`'${task}'`), `runner must allow ${task}`);
    for (const runner of ['local', 'docker']) {
      assert.doesNotMatch(taskSection(`${task}:${runner}`), /\n\s+internal:\s+true\b/u);
    }
  }
});

test('routine reset tasks preserve build caches and require confirmation', () => {
  assert.doesNotMatch(taskfile, /docker compose down -v/u);
  for (const task of ['reset:database', 'reset:objects', 'reset:server']) {
    assert.match(taskSection(task), /prompt:/u);
  }
});

test('native and Docker API development use maintained Watchexec reloads', () => {
  assert.match(taskfile, /watchexec --restart --no-vcs-ignore/u);
  assert.match(compose, /"watchexec", "--restart", "--no-vcs-ignore"/u);
  assert.match(taskfile, /--ignore '\*\*\/target\*\/\*\*' --ignore '\*\*\/tools\/\*\*'/u);
  assert.match(compose, /"--ignore", "\*\*\/target\*\/\*\*", "--ignore", "\*\*\/tools\/\*\*"/u);
  assert.match(taskfile, /--watch tmp\/dev/u);
  assert.match(compose, /"--watch", "tmp\/dev"/u);
  assert.match(serverImage, /cargo install watchexec-cli --version 2\.8\.0 --locked/u);
  assert.doesNotMatch(`${taskfile}\n${compose}\n${serverImage}`, /cargo[- ]watch/u);
});

test('desktop development selects native or browser-visible Docker execution', () => {
  const start = taskfile.indexOf('  dev:desktop:');
  const remainder = taskfile.slice(start);
  const next = remainder.indexOf('\n  dev:server:');
  const section = remainder.slice(0, next);

  assert.match(section, /dev-environment\.mjs run dev:desktop/u);
  assert.match(section, /pnpm dev/u);
  assert.match(
    section,
    /docker compose -f docker-compose\.yml -f compose\.desktop\.yml up --build --watch desktop/u,
  );
  assert.match(compose, /127\.0\.0\.1:\$\{OPENOM_DESKTOP_PORT:-6080\}:6080/u);
  assert.doesNotMatch(compose, /^\s+develop:\s*$/mu);
  assert.match(desktopCompose, /^\s+develop:\s*$/mu);
  assert.match(desktopCompose, /action: sync[\s\S]*initial_sync: true/u);
  assert.match(desktopEntrypoint, /no workspace synced; start this container with 'task dev:desktop'/u);
  assert.match(tauriImage, /novnc websockify/u);
  assert.equal(tauriConfig.build.frontendDist, '../app');
  assert.equal(tauriConfig.build.devUrl, undefined);
});

test('local service configuration has one environment-backed source', () => {
  for (const key of [
    'OPENOM_DEV_DATABASE_USER',
    'OPENOM_DEV_DATABASE_PASSWORD',
    'OPENOM_DEV_DATABASE_NAME',
    'OPENOM_DEV_OBJECT_STORE_ACCESS_KEY',
    'OPENOM_DEV_OBJECT_STORE_SECRET_KEY',
    'OPENOM_DEV_OBJECT_STORE_BUCKET',
  ]) {
    assert.match(taskfile, new RegExp(key, 'u'));
    assert.match(compose, new RegExp(key, 'u'));
  }
});

test('stop includes every optional long-running development profile', () => {
  assert.match(taskfile, /--profile desktop --profile supabase-auth --profile observability stop/u);
  assert.match(compose, /^\s+desktop:\s*$/mu);
});

test('preview tests have one discoverable Task entry point', () => {
  assert.match(taskSection('test:preview'), /node infra\/preview\/run-tests\.mjs/u);
  assert.match(mainWorkflow, /task test:preview/u);
  assert.match(webWorkflow, /task test:preview/u);
});
