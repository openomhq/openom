import { test, expect } from '@playwright/test';

interface AccountUiHarness {
  setPending(actions: string[]): void;
  setConflict(reason: string | null): void;
  show(screen: string): void;
}

declare global {
  interface Window {
    accountUiHarness: AccountUiHarness;
  }
}

test('local auth exposes account status without interactive login', async ({ page }) => {
  await page.goto('/app/index.html');

  await expect(page.getByRole('button', { name: /sign in to sync/i })).toHaveCount(0);
  await page.getByRole('button', { name: /explore a demo/i }).click();
  await expect(page.locator('body')).toContainText('Bach', { timeout: 20_000 });

  const chip = page.getByRole('button', { name: /account & sync — local/i });
  await expect(chip).toBeVisible();
  await chip.click();
  await expect(page.getByRole('dialog', { name: 'Account & sync' })).toBeVisible();
  await expect(page.getByRole('button', { name: /^sign in$/i })).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('account overlay routes forms and renders pending and conflict states safely', async ({ page }) => {
  await page.goto('/app/index.html');
  await page.evaluate(async () => {
    const { loadLocale } = await import('/app/src/core/i18n.js');
    const { accountOverlayView } = await import('/app/src/views/account.js');
    await loadLocale('en');

    const root = document.createElement('div');
    root.id = 'account-ui-harness';
    document.body.replaceChildren(root);
    const accountState = {
      auth: 'signedOut',
      account: 'unlocked',
      binding: 'unbound',
      syncDisposition: 'remote',
      pending: new Set<string>(),
      conflict: null as null | { code: string; reason: string },
      retainedIdentities: [],
      storagePersistence: 'granted',
    };
    const uiState = {
      screen: 'overview' as string | null,
      busy: null,
      error: '',
      notice: null,
      discovery: 'unknown',
    };
    const render = () => {
      const node = accountOverlayView(app);
      root.replaceChildren(...(node ? [node] : []));
    };
    const app = {
      account: { state: () => accountState },
      auth: { capabilities: () => ({ canLogin: true, canSignUp: true, sync: true }) },
      accountUiState: () => uiState,
      showAccountView: (screen = 'overview') => { uiState.screen = screen; render(); },
      closeAccountView: () => { uiState.screen = null; render(); },
      doSignUp: async () => null,
      doSignIn: async () => null,
      doSignOut: async () => null,
      doEnableSync: async () => null,
    };
    window.accountUiHarness = {
      setPending(actions) {
        accountState.auth = 'signedIn';
        accountState.pending = new Set(actions);
        uiState.screen = 'overview';
        render();
      },
      setConflict(reason) {
        accountState.conflict = reason ? { code: 'identity_conflict', reason } : null;
        uiState.screen = reason ? 'conflict' : 'overview';
        render();
      },
      show(screen) {
        uiState.screen = screen;
        render();
      },
    };
    render();
  });

  await page.getByRole('button', { name: /^sign in$/i }).click();
  await expect(page.getByRole('dialog', { name: 'Sign in to sync' })).toBeVisible();
  await expect(page.locator('#account-email')).toBeFocused();
  await page.getByRole('button', { name: /new here/i }).click();
  await expect(page.getByRole('dialog', { name: 'Sign up' })).toBeVisible();

  await page.evaluate(() => window.accountUiHarness.setPending(['register', 'restore']));
  await expect(page.getByText('Finishing account registration…')).toBeVisible();
  await expect(page.getByText('Finishing account restore…')).toBeVisible();
  await expect(page.getByRole('button', { name: /enable sync/i })).toHaveCount(0);

  await page.evaluate(() => window.accountUiHarness.setConflict('local_remote_identity_mismatch'));
  await expect(page.getByRole('dialog', { name: 'Account needs attention' })).toBeVisible();
  await expect(page.getByText('local_remote_identity_mismatch')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});
