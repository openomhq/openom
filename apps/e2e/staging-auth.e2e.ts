import { expect, test, type Browser, type BrowserContext, type Page, type Response } from '@playwright/test';

const enabled = process.env.OPENOM_STAGING_AUTH_ACCEPTANCE === '1';
const stagingUrl = process.env.OPENOM_STAGING_APP_URL ?? 'https://app.staging.openom.org/';
const credentials = {
  email: process.env.SUPABASE_TEST_EMAIL ?? '',
  password: process.env.SUPABASE_TEST_PASSWORD ?? '',
};
const accountPassphrase = process.env.SUPABASE_TEST_ACCOUNT_PASSPHRASE ?? '';
const gatePassword = process.env.STAGING_APP_GATE_PASSWORD ?? '';

interface StagingAccountResult {
  memberId: string;
  authSubject: string;
  path: 'created' | 'restored';
  state: { auth: string; account: string; binding: string; pending: string[] };
}

async function openStagingApp(page: Page): Promise<Response> {
  await page.route('**/src/main.js', (route) => route.fulfill({
    status: 200,
    contentType: 'application/javascript',
    body: 'export {};',
  }));

  const deadline = Date.now() + 120_000;
  let response: Response | null = null;
  while (Date.now() < deadline) {
    response = await page.goto(stagingUrl, { waitUntil: 'domcontentloaded' });
    if (response && response.ok()) break;
    await page.waitForTimeout(2_000);
  }
  if (!response || !response.ok()) throw new Error('staging app did not become reachable');

  const gate = page.locator('form[action="/__gate"]');
  if (await gate.isVisible()) {
    await page.locator('input[name="password"]').fill(gatePassword);
    const navigation = page.waitForNavigation({ waitUntil: 'domcontentloaded' });
    await page.locator('button[type="submit"]').click();
    response = await navigation;
  }
  if (!response || !response.ok()) throw new Error('staging gate did not admit the acceptance browser');
  await expect(page.locator('meta[name="openom:auth-provider"]')).toHaveAttribute('content', 'supabase');
  return response;
}

async function composeAccount(page: Page) {
  await page.evaluate(async () => {
    const [{ composeAccountSession }, { createAuthProvider }, { appCoreWorker }, { RemoteStore }] = await Promise.all([
      import('/src/core/accountComposition.js'),
      import('/src/core/authProvider.js'),
      import('/src/core/appCoreClient.js'),
      import('/src/core/remoteStore.js'),
    ]);
    const serverUrl = document.querySelector('meta[name="openom:server"]')?.getAttribute('content')?.trim() ?? '';
    if (!serverUrl || serverUrl.startsWith('%')) throw new Error('staging server configuration is unresolved');
    const worker = appCoreWorker();
    await worker.warm();
    const composition = await composeAccountSession(worker, {
      createAuth: (account) => createAuthProvider(account),
      createRemote: (auth) => new RemoteStore({ baseUrl: serverUrl, auth }),
    });
    window.stagingAuthAcceptance = composition;
  });
}

async function accountRoundTrip(page: Page, allowCreate: boolean): Promise<StagingAccountResult> {
  return page.evaluate(async ({ signIn, passphrase, mayCreate }) => {
    const composition = window.stagingAuthAcceptance;
    await composition.auth.signIn(signIn);
    await composition.auth.getAccessToken({ forceRefresh: true });
    const probe = await composition.account.probe();

    let memberId;
    let path: 'created' | 'restored';
    if (probe.status === 'unregistered') {
      if (!mayCreate) throw new Error('the second staging context unexpectedly found an unregistered subject');
      const created = await composition.account.createAccount(passphrase);
      await composition.account.enableSync();
      memberId = created.memberId;
      path = 'created';
    } else {
      if (probe.remote.keystore === null) {
        throw new Error('the staging test subject is bound without a recoverable account backup');
      }
      const restored = await composition.account.restore({ passphrase });
      memberId = restored.memberId;
      path = 'restored';
    }

    const state = composition.account.state();
    return {
      memberId,
      authSubject: composition.auth.subject(),
      path,
      state: {
        auth: state.auth,
        account: state.account,
        binding: state.binding,
        pending: [...state.pending],
      },
    };
  }, { signIn: credentials, passphrase: accountPassphrase, mayCreate: allowCreate });
}

async function acceptanceContext(browser: Browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  const response = await openStagingApp(page);
  const csp = response.headers()['content-security-policy'] ?? '';
  const authOrigin = await page.locator('meta[name="openom:supabase-url"]').getAttribute('content') ?? '';
  expect(authOrigin).toMatch(/^https:\/\/[^%]+$/);
  expect(csp).toContain(authOrigin);
  await composeAccount(page);
  return { context, page, errors };
}

test('deployed staging signs in, refreshes, binds, backs up, and restores in a fresh context @staging', async ({ browser }) => {
  test.skip(!enabled, 'run from the staging web workflow with environment credentials');
  expect(credentials.email).not.toBe('');
  expect(credentials.password).not.toBe('');
  expect(accountPassphrase).not.toBe('');
  expect(gatePassword).not.toBe('');

  const first = await acceptanceContext(browser);
  let second: { context: BrowserContext; page: Page; errors: string[] } | null = null;
  try {
    const source = await accountRoundTrip(first.page, true);
    expect(source.authSubject).not.toBe(source.memberId);
    expect(source.state).toEqual({ auth: 'signedIn', account: 'unlocked', binding: 'backedUp', pending: [] });

    second = await acceptanceContext(browser);
    const restored = await accountRoundTrip(second.page, false);
    expect(restored.path).toBe('restored');
    expect(restored.memberId).toBe(source.memberId);
    expect(restored.authSubject).toBe(source.authSubject);
    expect(restored.state).toEqual({ auth: 'signedIn', account: 'unlocked', binding: 'backedUp', pending: [] });
    expect(first.errors).toEqual([]);
    expect(second.errors).toEqual([]);
  } finally {
    await first.context.close();
    await second?.context.close();
  }
});

declare global {
  interface Window {
    stagingAuthAcceptance: {
      account: {
        createAccount(passphrase: string): Promise<{ memberId: string }>;
        enableSync(): Promise<unknown>;
        probe(): Promise<
          { status: 'unregistered' }
          | { status: 'registered'; remote: { keystore: unknown | null } }
        >;
        restore(credential: { passphrase: string }): Promise<{ memberId: string }>;
        state(): { auth: string; account: string; binding: string; pending: readonly string[] };
      };
      auth: {
        signIn(credentials: { email: string; password: string }): Promise<void>;
        getAccessToken(options?: { forceRefresh?: boolean }): Promise<string>;
        subject(): string | null;
      };
      dispose(): void;
    };
  }
}
