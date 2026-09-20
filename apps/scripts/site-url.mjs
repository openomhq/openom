// Fills %SITE_URL% into a copy of the site. Social crawlers discard relative
// paths, so og:image and og:url have to be absolute — and the origin differs
// between a Pages deploy, a fork and a local run.
//
//   SITE_URL=https://example.org/ node scripts/site-url.mjs ../_site
//   node scripts/site-url.mjs ../_site        → falls back to .env.demo
//
// Rewrites .html files in place; run it on the deploy copy, never on app/.

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** SITE_URL from the environment, else from .env.demo. Always ends in a slash. */
export async function siteUrl() {
  let value = process.env.SITE_URL;
  if (!value) {
    try {
      const env = await readFile(join(HERE, '..', '.env.demo'), 'utf8');
      value = env.match(/^\s*SITE_URL\s*=\s*(.+?)\s*$/m)?.[1];
    } catch { /* no .env.demo — fall through */ }
  }
  if (!value) throw new Error('SITE_URL is not set and .env.demo has no value');
  return value.endsWith('/') ? value : value + '/';
}

async function* htmlFiles(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* htmlFiles(path);
    else if (extname(entry.name) === '.html') yield path;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const target = process.argv[2];
  if (!target) {
    console.error('usage: node scripts/site-url.mjs <directory>');
    process.exit(1);
  }
  const url = await siteUrl();
  // The first-run LANDING mode for the deploy: 'demo' (a demo/preview deployment) or 'live' (production —
  // real onboarding). Read from OPENOM_LANDING (the env or the .env.demo fallback); anything but 'demo'
  // defaults to 'live', the safe no-demo state. ('test' is e2e-only and never a deploy value.)
  let landing = process.env.OPENOM_LANDING;
  if (landing == null) {
    try {
      const env = await readFile(join(HERE, '..', '.env.demo'), 'utf8');
      landing = env.match(/^\s*OPENOM_LANDING\s*=\s*(.+?)\s*$/m)?.[1];
    } catch { /* no .env.demo — landing stays live */ }
  }
  landing = landing === 'demo' ? 'demo' : 'live';
  // The managed sync backend URL: empty unless a deployment sets OPENOM_SERVER, so production is
  // local-only (no account wall) until a server is wired.
  const server = process.env.OPENOM_SERVER ?? '';
  let touched = 0;
  for await (const file of htmlFiles(target)) {
    const before = await readFile(file, 'utf8');
    if (!before.includes('%SITE_URL%')) continue;
    await writeFile(file, before.replaceAll('%SITE_URL%', url).replaceAll('%LANDING%', landing).replaceAll('%SERVER%', server));
    touched++;
  }
  console.log('site-url → ' + url + ' · demo=' + demo + ' · server=' + (server || '(none)') + ' (' + touched + ' file' + (touched === 1 ? '' : 's') + ')');
}
