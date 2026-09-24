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

/** Resolve and validate the public provider configuration used by both local serving and deployment assembly. */
export function authConfig(environment = process.env) {
  const provider = environment.OPENOM_AUTH_PROVIDER?.trim() || 'dev';
  if (provider !== 'dev' && provider !== 'supabase') {
    throw new Error(`OPENOM_AUTH_PROVIDER must be dev or supabase, found ${provider}`);
  }
  if (provider === 'dev') return { provider, supabaseUrl: '', publishableKey: '' };

  const supabaseUrl = environment.SUPABASE_URL?.trim() || '';
  const publishableKey = environment.SUPABASE_PUBLISHABLE_KEY?.trim() || '';
  if (!supabaseUrl || !publishableKey) {
    throw new Error('Supabase auth requires SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY');
  }
  let parsed;
  try {
    parsed = new URL(supabaseUrl);
  } catch {
    throw new Error('SUPABASE_URL must be a valid HTTP(S) origin');
  }
  if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('SUPABASE_URL must be a valid HTTP(S) origin');
  }
  return { provider, supabaseUrl: parsed.origin, publishableKey };
}

const PLACEHOLDERS = [
  '%SITE_URL%',
  '%LANDING%',
  '%SERVER%',
  '%AUTH_PROVIDER%',
  '%SUPABASE_URL%',
  '%SUPABASE_ANON_KEY%',
];

/** Substitute every app-owned HTML placeholder and refuse to return a partial deployment artifact. */
export function assembleHtml(html, { siteUrl: publicUrl, landing, server, auth }) {
  const assembled = html
    .replaceAll('%SITE_URL%', publicUrl)
    .replaceAll('%LANDING%', landing)
    .replaceAll('%SERVER%', server)
    .replaceAll('%AUTH_PROVIDER%', auth.provider)
    .replaceAll('%SUPABASE_URL%', auth.supabaseUrl)
    .replaceAll('%SUPABASE_ANON_KEY%', auth.publishableKey);
  const unresolved = PLACEHOLDERS.filter((placeholder) => assembled.includes(placeholder));
  if (unresolved.length) throw new Error(`unresolved app placeholders: ${unresolved.join(', ')}`);
  return assembled;
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
  const auth = authConfig();
  let touched = 0;
  for await (const file of htmlFiles(target)) {
    const before = await readFile(file, 'utf8');
    const after = assembleHtml(before, { siteUrl: url, landing, server, auth });
    if (after !== before) {
      await writeFile(file, after);
      touched++;
    }
  }
  console.log('site-url → ' + url + ' · landing=' + landing + ' · server=' + (server || '(none)')
    + ' · auth=' + auth.provider + ' (' + touched + ' file' + (touched === 1 ? '' : 's') + ')');
}
