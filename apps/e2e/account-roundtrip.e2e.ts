import { expect, test } from '@playwright/test';

const enabled = process.env.OPENOM_ACCOUNT_ACCEPTANCE === '1';
const serverUrl = process.env.OPENOM_ACCOUNT_SERVER_URL ?? 'http://localhost:6060';
const harnessUrl = `http://localhost:5173/e2e/account-roundtrip-harness.html?server=${encodeURIComponent(serverUrl)}`;

for (const engine of ['chain', 'dag'] as const) {
  test(`account facade: register, backup, fresh-context restore, and tree reopen (${engine}) @integration`, async ({ browser }) => {
    test.skip(!enabled, 'run through scripts/account-acceptance.mjs with the real local server');
    const firstContext = await browser.newContext();
    const secondContext = await browser.newContext();
    const firstPage = await firstContext.newPage();
    const secondPage = await secondContext.newPage();
    const firstErrors: string[] = [];
    const secondErrors: string[] = [];
    firstPage.on('pageerror', (error) => firstErrors.push(String(error)));
    secondPage.on('pageerror', (error) => secondErrors.push(String(error)));

    try {
      await firstPage.goto(harnessUrl);
      await expect(firstPage.locator('#status')).toHaveText('ready', { timeout: 20_000 });
      const passphrase = `account acceptance ${engine} passphrase`;
      const created = await firstPage.evaluate(async ({ passphrase: value, selectedEngine }) => {
        try {
          return await window.accountAcceptance.createAndBackup({
            passphrase: value,
            engine: selectedEngine,
            given: selectedEngine === 'chain' ? 'Ada' : 'Grace',
          });
        } catch (error) {
          throw new Error(JSON.stringify(error, Object.getOwnPropertyNames(error)));
        }
      }, { passphrase, selectedEngine: engine });

      expect(created.accountState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });

      await secondPage.goto(harnessUrl);
      await expect(secondPage.locator('#status')).toHaveText('ready', { timeout: 20_000 });
      const restored = await secondPage.evaluate(async ({ created: source, passphrase: value, selectedEngine }) => {
        try {
          return await window.accountAcceptance.restoreAndOpen({
            subject: source.memberId,
            passphrase: value,
            engine: selectedEngine,
            treeId: source.treeId,
            docId: source.docId,
          });
        } catch (error) {
          throw new Error(JSON.stringify(error, Object.getOwnPropertyNames(error)));
        }
      }, { created, passphrase, selectedEngine: engine });

      expect(restored.memberId).toBe(created.memberId);
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
      createAndBackup(input: { passphrase: string; engine: 'chain' | 'dag'; given: string }): Promise<any>;
      restoreAndOpen(input: {
        subject: string;
        passphrase: string;
        engine: 'chain' | 'dag';
        treeId: number[];
        docId: string;
      }): Promise<any>;
    };
  }
}
