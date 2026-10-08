import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const attributes = fs.readFileSync(path.join(root, '.gitattributes'), 'utf8');
const migrationsDirectory = path.join(root, 'openom', 'migrations');

test('SQLx migrations have stable cross-platform bytes', () => {
  assert.match(attributes, /^openom\/migrations\/\*\.sql text eol=lf$/mu);

  for (const name of fs.readdirSync(migrationsDirectory)) {
    if (!name.endsWith('.sql')) continue;

    const migration = fs.readFileSync(path.join(migrationsDirectory, name));
    assert.equal(migration.includes(13), false, `${name} contains a carriage return`);
  }
});
