import { expect, test } from '@playwright/test';

const enabled = process.env.OPENOM_ACCOUNT_ACCEPTANCE === '1';
const serverUrl = process.env.OPENOM_ACCOUNT_SERVER_URL ?? 'http://localhost:6060';
const authProvider = process.env.OPENOM_ACCOUNT_AUTH_PROVIDER ?? 'fixed-dev';
const authUrl = process.env.OPENOM_ACCOUNT_AUTH_URL ?? '';
const publishableKey = process.env.OPENOM_ACCOUNT_PUBLISHABLE_KEY ?? '';
const createProviderAccount = process.env.OPENOM_ACCOUNT_SIGN_UP === '1';
const configuredCredentials = process.env.OPENOM_ACCOUNT_CREDENTIALS
  ? JSON.parse(process.env.OPENOM_ACCOUNT_CREDENTIALS) as Record<string, { email: string; password: string }>
  : {};
const harnessParameters = new URLSearchParams({ server: serverUrl, auth: authProvider });
if (authProvider === 'supabase') {
  harnessParameters.set('authUrl', authUrl);
  harnessParameters.set('publishableKey', publishableKey);
}
const harnessUrl = `http://localhost:5173/e2e/account-roundtrip-harness.html?${harnessParameters}`;

for (const engine of ['chain', 'dag'] as const) {
  test(`account facade: register, backup, fresh-context restore, and tree reopen (${engine}) @integration`, async ({ browser }) => {
    test.skip(!enabled, 'run through scripts/account-acceptance.mjs with the real local server');
    const firstContext = await browser.newContext();
    const secondContext = await browser.newContext();
    const firstPage = await firstContext.newPage();
    const secondPage = await secondContext.newPage();
    const firstErrors: string[] = [];
    const secondErrors: string[] = [];
    const authDiagnostics: string[] = [];
    firstPage.on('pageerror', (error) => firstErrors.push(String(error)));
    secondPage.on('pageerror', (error) => secondErrors.push(String(error)));
    for (const page of [firstPage, secondPage]) {
      page.on('requestfailed', (request) => {
        if (request.url().includes('/auth/v1/')) {
          authDiagnostics.push(`${request.method()} ${request.url()} failed: ${request.failure()?.errorText ?? 'unknown'}`);
        }
      });
      page.on('response', (response) => {
        if (response.url().includes('/auth/v1/') && response.status() >= 400) {
          authDiagnostics.push(`${response.request().method()} ${response.url()} returned ${response.status()}`);
        }
      });
    }

    try {
      await firstPage.goto(harnessUrl);
      await expect(firstPage.locator('#status')).toHaveText('ready', { timeout: 20_000 });
      const passphrase = `account acceptance ${engine} passphrase`;
      const credentials = configuredCredentials[engine];
      if (authProvider === 'supabase' && !credentials) throw new Error(`missing ${engine} Supabase credentials`);
      let created;
      try {
        created = await firstPage.evaluate(async ({
          passphrase: value,
          selectedEngine,
          credentials: authCredentials,
          createProviderAccount,
        }) => {
          try {
            return await window.accountAcceptance.createAndBackup({
              passphrase: value,
              engine: selectedEngine,
              given: selectedEngine === 'chain' ? 'Ada' : 'Grace',
              credentials: authCredentials,
              createProviderAccount,
            });
          } catch (error) {
            throw new Error(JSON.stringify(error, Object.getOwnPropertyNames(error)));
          }
        }, { passphrase, selectedEngine: engine, credentials, createProviderAccount });
      } catch (error) {
        throw new Error(`${error}\nauth network: ${authDiagnostics.join('; ') || 'no failed response observed'}`);
      }

      expect(created.accountState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });
      expect(created.providerAccountStatus).toBe('signedIn');
      if (authProvider === 'supabase') expect(created.authSubject).not.toBe(created.memberId);
      else expect(created.authSubject).toBe(created.memberId);

      await secondPage.goto(harnessUrl);
      await expect(secondPage.locator('#status')).toHaveText('ready', { timeout: 20_000 });
      const restored = await secondPage.evaluate(async ({
        created: source,
        passphrase: value,
        selectedEngine,
        credentials: authCredentials,
      }) => {
        try {
          return await window.accountAcceptance.restoreAndOpen({
            subject: source.memberId,
            passphrase: value,
            engine: selectedEngine,
            treeId: source.treeId,
            docId: source.docId,
            credentials: authCredentials,
          });
        } catch (error) {
          throw new Error(JSON.stringify(error, Object.getOwnPropertyNames(error)));
        }
      }, { created, passphrase, selectedEngine: engine, credentials });

      expect(restored.memberId).toBe(created.memberId);
      expect(restored.authSubject).toBe(created.authSubject);
      expect(restored.people).toContain(created.personName);
      expect(restored.accountState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });
      expect(firstErrors, 'no creator-context page errors').toEqual([]);
      expect(secondErrors, 'no restore-context page errors').toEqual([]);
    } finally {
      await firstContext.close();
      await secondContext.close();
    }
  });
}

declare global {
  interface Window {
    accountAcceptance: {
      createAndBackup(input: {
        passphrase: string;
        engine: 'chain' | 'dag';
        given: string;
        credentials?: { email: string; password: string };
        createProviderAccount?: boolean;
      }): Promise<any>;
      restoreAndOpen(input: {
        subject: string;
        credentials?: { email: string; password: string };
        passphrase: string;
        engine: 'chain' | 'dag';
        treeId: number[];
        docId: string;
      }): Promise<any>;
    };
  }
}
