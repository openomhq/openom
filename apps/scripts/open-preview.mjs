#!/usr/bin/env node
import { execFileSync, spawn } from 'node:child_process';
import { createServer, isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from '@playwright/test';

import { previewIdentity } from '../../scripts/preview-name.mjs';

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_PROFILE = 'default';
const DNS_PROVIDERS = Object.freeze([
  (hostname) => `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
  (hostname) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
]);

export class OpenPreviewError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OpenPreviewError';
    this.code = code;
  }
}

export function parseOpenPreviewArguments(args) {
  if (args.length === 0) return { profile: DEFAULT_PROFILE };
  if (args.length !== 2 || args[0] !== '--profile') {
    throw new OpenPreviewError(
      'invalid_arguments',
      'usage: pnpm --dir apps preview:open [--profile <name>]',
    );
  }
  const profile = args[1];
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$/.test(profile)) {
    throw new OpenPreviewError(
      'invalid_profile',
      'profile must be 1-32 letters, digits, underscores, or dashes',
    );
  }
  return { profile };
}

export function currentBranch(execFile = execFileSync) {
  const branch = execFile('git', ['branch', '--show-current'], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
  }).trim();
  if (!branch) {
    throw new OpenPreviewError('detached_head', 'cannot open a preview from a detached HEAD');
  }
  if (branch === 'main') {
    throw new OpenPreviewError('main_branch', 'main does not have a branch preview');
  }
  return branch;
}

function dnsAnswers(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.Answer)) return [];
  return value.Answer.filter(
    (answer) => answer && typeof answer === 'object' && answer.type === 1 && isIP(answer.data) === 4,
  ).map((answer) => answer.data);
}

export async function resolvePublicIpv4(hostname, fetchImplementation = fetch) {
  const errors = [];
  for (const providerUrl of DNS_PROVIDERS) {
    try {
      const response = await fetchImplementation(providerUrl(hostname), {
        headers: { accept: 'application/dns-json' },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const addresses = dnsAnswers(await response.json());
      if (addresses.length > 0) return addresses[0];
      throw new Error('response contained no IPv4 address');
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  throw new OpenPreviewError(
    'dns_resolution_failed',
    `encrypted DNS could not resolve ${hostname}: ${errors.join('; ')}`,
  );
}

export function previewHostResolverRules(identity, edgeAddress) {
  if (isIP(edgeAddress) !== 4) {
    throw new OpenPreviewError('invalid_edge_address', 'preview edge address must be IPv4');
  }
  const appHostname = new URL(identity.appUrl).hostname;
  const apiHostname = new URL(identity.apiUrl).hostname;
  return `MAP ${appHostname} ${edgeAddress}, MAP ${apiHostname} ${edgeAddress}`;
}

export function checkPreviewOnline(url, edgeAddress, requestImplementation = httpsRequest) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const request = requestImplementation({
      hostname: target.hostname,
      lookup: (_hostname, options, callback) => {
        if (options.all) {
          callback(null, [{ address: edgeAddress, family: 4 }]);
          return;
        }
        callback(null, edgeAddress, 4);
      },
      method: 'GET',
      path: `${target.pathname}${target.search}`,
      port: 443,
      protocol: 'https:',
      servername: target.hostname,
      timeout: 15_000,
    }, (response) => {
      response.resume();
      if (response.statusCode && response.statusCode >= 200 && response.statusCode < 400) {
        resolve(response.statusCode);
        return;
      }
      reject(new OpenPreviewError(
        'preview_offline',
        `preview returned HTTP ${response.statusCode ?? 'unknown'} at ${url}`,
      ));
    });
    request.on('timeout', () => request.destroy(new Error('request timed out')));
    request.on('error', (error) => reject(new OpenPreviewError(
      'preview_unreachable',
      `preview is not reachable at ${url}: ${error.message}`,
    )));
    request.end();
  });
}

export function findAvailablePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!address || typeof address === 'string') {
          reject(new OpenPreviewError('debug_port_failed', 'could not reserve a debug port'));
          return;
        }
        resolve(address.port);
      });
    });
  });
}

function devtoolsPage(value, appUrl) {
  if (!Array.isArray(value)) return null;
  const canonicalAppUrl = new URL(appUrl).href;
  return value.find((entry) => (
    entry
    && typeof entry === 'object'
    && entry.type === 'page'
    && typeof entry.url === 'string'
    && new URL(entry.url).href === canonicalAppUrl
    && typeof entry.devtoolsFrontendUrl === 'string'
    && entry.devtoolsFrontendUrl.startsWith('https://chrome-devtools-frontend.appspot.com/')
  )) ?? null;
}

export async function waitForDevtoolsUrl(port, appUrl, fetchImplementation = fetch) {
  let lastError = 'endpoint did not become ready';
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetchImplementation(`http://127.0.0.1:${port}/json/list`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const page = devtoolsPage(await response.json(), appUrl);
      if (page) return page.devtoolsFrontendUrl;
      lastError = 'preview page was absent from the debug target list';
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new OpenPreviewError(
    'devtools_unavailable',
    `local DevTools did not become ready: ${lastError}`,
  );
}

export function openExternal(url, spawnImplementation = spawn) {
  let child;
  if (process.platform === 'win32') {
    child = spawnImplementation('rundll32.exe', ['url.dll,FileProtocolHandler', url], {
      detached: true,
      stdio: 'ignore',
    });
  } else if (process.platform === 'darwin') {
    child = spawnImplementation('open', [url], { detached: true, stdio: 'ignore' });
  } else {
    child = spawnImplementation('xdg-open', [url], { detached: true, stdio: 'ignore' });
  }
  child.unref();
}

function waitForContextClose(context) {
  return new Promise((resolve) => context.once('close', resolve));
}

export async function launchPreviewBrowser({
  appUrl,
  browser,
  findPort = findAvailablePort,
  openUrl = openExternal,
  profilePath,
  resolverRules,
  waitForClose = waitForContextClose,
  waitForDevtools = waitForDevtoolsUrl,
}) {
  const resolverArgument = `--host-resolver-rules=${resolverRules}`;
  const port = await findPort();
  const context = await browser.launchPersistentContext(profilePath, {
    args: [
      resolverArgument,
      `--remote-debugging-port=${port}`,
      '--remote-allow-origins=https://chrome-devtools-frontend.appspot.com',
    ],
    headless: true,
  });
  try {
    const page = context.pages()[0] ?? await context.newPage();
    await page.goto(appUrl);
    const devtoolsUrl = await waitForDevtools(port, appUrl);
    openUrl(devtoolsUrl);
    process.stdout.write('[Preview] Close with Ctrl+C when testing is complete.\n');
    await waitForClose(context);
    return 'devtools';
  } catch (error) {
    await context.close();
    throw error;
  }
}

export async function openPreview({
  args = process.argv.slice(2),
  browser = chromium,
  execFile = execFileSync,
  fetchImplementation = fetch,
  requestImplementation = httpsRequest,
} = {}) {
  const { profile } = parseOpenPreviewArguments(args);
  const identity = previewIdentity(currentBranch(execFile));
  const appHostname = new URL(identity.appUrl).hostname;
  const edgeAddress = await resolvePublicIpv4(appHostname, fetchImplementation);
  await checkPreviewOnline(identity.appUrl, edgeAddress, requestImplementation);

  const profilePath = path.join(REPOSITORY_ROOT, 'tmp', 'playwright', profile);
  const resolverRules = previewHostResolverRules(identity, edgeAddress);
  process.stdout.write(`[Preview] Opening ${identity.appUrl}\n`);
  process.stdout.write(`[Preview] Profile: ${profilePath}\n`);

  await launchPreviewBrowser({
    appUrl: identity.appUrl,
    browser,
    profilePath,
    resolverRules,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  openPreview().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  });
}
