import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const taskfile = fs.readFileSync(new URL('../Taskfile.yml', import.meta.url), 'utf8');
const compose = fs.readFileSync(new URL('../docker-compose.yml', import.meta.url), 'utf8');
const serverImage = fs.readFileSync(new URL('../openom/Dockerfile', import.meta.url), 'utf8');

test('Taskfile exposes one setup and development entry point with explicit specializations', () => {
  for (const task of ['setup', 'dev', 'dev:web', 'dev:desktop', 'dev:server']) {
    assert.match(taskfile, new RegExp(`^  ${task}:`, 'mu'));
  }
  assert.match(taskfile, /DEV_RUNNER:.*RUNNER.*docker.*docker.*local/u);
});

test('routine reset tasks preserve build caches and require confirmation', () => {
  assert.doesNotMatch(taskfile, /docker compose down -v/u);
  for (const task of ['reset:database', 'reset:objects', 'reset:server']) {
    const start = taskfile.indexOf(`  ${task}:`);
    const remainder = taskfile.slice(start);
    const headerEnd = remainder.indexOf('\n') + 1;
    const next = remainder.slice(headerEnd).search(/\n  \S[^\n]*:\r?\n/u);
    const section = remainder.slice(0, next < 0 ? undefined : headerEnd + next);
    assert.match(section, /prompt:/u);
  }
});

test('native and Docker API development use maintained Watchexec reloads', () => {
  assert.match(taskfile, /watchexec --restart/u);
  assert.match(compose, /"watchexec", "--restart"/u);
  assert.match(serverImage, /cargo install watchexec-cli --version 2\.8\.0 --locked/u);
  assert.doesNotMatch(`${taskfile}\n${compose}\n${serverImage}`, /cargo[- ]watch/u);
});
