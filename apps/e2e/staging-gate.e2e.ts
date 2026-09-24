import { expect, test } from '@playwright/test';
import { enterStagingGate } from './support/stagingGate.js';

const stagingUrl = 'http://localhost:5173/';
const password = 'correct staging password';
const token = 'a'.repeat(64);

test('staging gate admits a fresh browser through its expected deployed challenge', async ({ page }) => {
  let challenges = 0;
  await page.route(`${stagingUrl}**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'POST' && url.pathname === '/__gate') {
      const submitted = new URLSearchParams(request.postData() ?? '').get('password');
      if (submitted !== password) {
        await route.fulfill({ status: 401, contentType: 'text/html', body: gatePage('abcdef0', true) });
        return;
      }
      await route.fulfill({
        status: 303,
        headers: {
          location: '/',
          'set-cookie': `openom_staging_gate=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`,
        },
      });
      return;
    }
    if (request.headers().cookie?.includes(`openom_staging_gate=${token}`)) {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><meta name="openom:auth-provider" content="supabase"><title>openom</title>',
      });
      return;
    }
    challenges += 1;
    await route.fulfill({ status: 401, contentType: 'text/html', body: gatePage('abcdef0') });
  });

  const response = await enterStagingGate(page, {
    stagingUrl,
    password,
    expectedCommit: 'abcdef0',
    readinessTimeoutMs: 1_000,
  });

  expect(response.status()).toBe(200);
  expect(challenges).toBe(1);
});

function gatePage(commit: string, error = false) {
  return `<!doctype html>
    <main>
      <form method="POST" action="/__gate">
        <input name="password" type="password">
        <button type="submit">Enter</button>
        ${error ? '<p>Wrong password</p>' : ''}
      </form>
      <footer><div class="meta">commit <code>${commit}</code></div></footer>
    </main>`;
}
