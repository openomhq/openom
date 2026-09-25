// Cloudflare Pages Function — a shared-password gate in front of the STAGING web app.
//
// It serves a branded "Staging" page (build info + a light backend health check) until the visitor
// enters the shared password (env STAGING_APP_GATE_PASSWORD); then it sets a 30-day cookie and lets
// every request through. The app's own account login is the REAL gate — this only keeps the pre-release
// private and easy to share (tell someone one password), and gives a quick "which build / is it up" view.
//
// Deployed only by the staging web workflow (copied to _site/functions/_middleware.js) — NOT part of the
// app itself, so the public demo + local dev stay ungated.

const COOKIE = 'openom_staging_gate';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days — enter the password about once a month
const API_STATUS = 'https://api.staging.openom.org/status';

async function sha256Hex(input) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > -1) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

// Server-side (no CORS, no client JS → CSP-clean): read the API's /status for per-service health.
// Functional labels (API/DATABASE/AUTH/STORAGE), not vendor names — the repo is public anyway.
async function fetchStatus() {
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 3000);
    const res = await fetch(API_STATUS, { cache: 'no-store', signal: ctl.signal });
    clearTimeout(timer);
    if (!res.ok) return { api: false };
    const j = await res.json().catch(() => ({}));
    return { api: true, database: !!j.database, auth: !!j.auth, storage: !!j.storage };
  } catch {
    return { api: false };
  }
}

// state: 'up' | 'down' | 'unknown' — a coloured dot after the label, no text.
function statLine(label, state) {
  return `<span class="${state}">${label}<span class="dot"></span></span>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const password = env.STAGING_APP_GATE_PASSWORD;
  // Fail CLOSED: with no password configured, deny rather than accidentally expose staging.
  if (!password) return new Response('staging gate not configured', { status: 503 });

  const token = await sha256Hex(password);
  const url = new URL(request.url);

  // Password submission.
  if (request.method === 'POST' && url.pathname === '/__gate') {
    const form = await request.formData().catch(() => null);
    const given = form ? String(form.get('password') ?? '') : '';
    if ((await sha256Hex(given)) === token) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: '/',
          'Set-Cookie': `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAX_AGE}`,
        },
      });
    }
    return gatePage(env, { error: true });
  }

  // Already through the gate → serve the app.
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  if (cookies[COOKIE] === token) return next();

  // Otherwise show the gate.
  return gatePage(env);
}

async function gatePage(env, { error = false } = {}) {
  const sha = (env.CF_PAGES_COMMIT_SHA || '').slice(0, 7) || 'unknown';
  const branch = env.CF_PAGES_BRANCH || 'unknown';
  const s = await fetchStatus();
  const b = (up) => (up ? 'up' : 'down');
  const statuses = s.api
    ? statLine('API', 'up') + statLine('DATABASE', b(s.database)) + statLine('AUTH', b(s.auth)) + statLine('STORAGE', b(s.storage))
    // Couldn't reach /status: API is down; the rest are genuinely unknown, not "down".
    : statLine('API', 'down') + statLine('DATABASE', 'unknown') + statLine('AUTH', 'unknown') + statLine('STORAGE', 'unknown');

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>openom · staging</title>
<style>
  :root {
    color-scheme: light;
    --accent: oklch(49.8% 0.0444 166.4);
    --accent-pressed: oklch(41.8% 0.0444 166.4);
    --canvas: oklch(98.5% 0.004 155);
    --card: #ffffff;
    --label: #1c1c1e;
    --secondary: #6e6e73;
    --hairline: rgba(16, 24, 32, 0.08);
    --mono-bg: oklch(95% 0.008 155);
    --delete: #d92d20;
    --font-ui: -apple-system, "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
    --font-name: Newsreader, Georgia, serif;
  }
  @media (prefers-color-scheme: dark) {
    :root { color-scheme: dark; --canvas:#121214; --card:#1a1a1e; --label:#f2f2f5; --secondary:#9a9aa0;
            --hairline:rgba(255,255,255,0.1); --mono-bg:#26262b; --accent:oklch(67.8% 0.054 166.4); }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center; padding:24px;
         background:var(--canvas); color:var(--label); font-family:var(--font-ui);
         font-size:16px; line-height:1.5; -webkit-font-smoothing:antialiased; }
  .card { width:100%; max-width:380px; background:var(--card); border:1px solid var(--hairline);
          border-radius:18px; padding:32px; box-shadow:0 1px 2px rgba(16,24,32,.06), 0 10px 24px -16px rgba(16,24,32,.34); }
  .wordmark { font-family:var(--font-name); font-size:28px; font-weight:500; margin:0; }
  .chip { display:inline-block; margin-left:8px; padding:2px 8px; border-radius:999px; font-size:12px;
          font-family:var(--font-ui); background:var(--mono-bg); color:var(--secondary);
          vertical-align:middle; letter-spacing:.02em; }
  p.lede { color:var(--secondary); font-size:14px; margin:12px 0 24px; }
  label { display:block; font-size:13px; color:var(--secondary); margin-bottom:6px; }
  input[type=password] { width:100%; padding:11px 12px; border:1px solid var(--hairline);
          border-radius:10px; background:var(--canvas); color:var(--label); font:inherit; }
  input:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  button { width:100%; margin-top:16px; padding:11px 12px; border:0; border-radius:10px;
           background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  button:hover { background:var(--accent-pressed); }
  .err { color:var(--delete); font-size:13px; margin:12px 0 0; }
  footer { margin-top:24px; padding-top:16px; border-top:1px solid var(--hairline);
           font-size:12.5px; color:var(--secondary); }
  footer code { font-family:ui-monospace, "SF Mono", Menlo, monospace; }
  .meta { margin-bottom:12px; }
  .services { display:flex; justify-content:space-between; gap:6px; }
  .services > span { display:inline-flex; align-items:center; }
  .dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-left:7px; }
  .up .dot { background:var(--accent); } .down .dot { background:var(--delete); } .unknown .dot { background:var(--secondary); }
</style>
</head>
<body>
  <main class="card">
    <h1 class="wordmark">openom<span class="chip">staging</span></h1>
    <p class="lede">Private staging environment. Enter the shared password to continue.</p>
    <form method="POST" action="/__gate">
      <label for="pw">Password</label>
      <input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Enter</button>
      ${error ? '<p class="err">Wrong password — try again.</p>' : ''}
    </form>
    <footer>
      <div class="meta">commit <code>${sha}</code>, branch <code>${branch}</code></div>
      <div class="services">${statuses}</div>
    </footer>
  </main>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      // The gate is its own trivial page; allow its inline <style> without loosening the app's CSP.
      'Content-Security-Policy':
        "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}
