import { test, expect } from '@playwright/test';

interface AccountUiHarness {
  setPending(actions: string[]): void;
  setConflict(reason: string | null): void;
  setTreeSync(state: 'synced' | 'offline' | 'error' | 'auth-error' | 'security' | null): void;
  show(screen: string): void;
  restoredPassphrase(): string | null;
}

declare global {
  interface Window {
    accountUiHarness: AccountUiHarness;
    accountWelcomeHarness: { setAuth(auth: 'signedOut' | 'signedIn'): void };
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
    const { accountOverlayView, accountStatusChip } = await import('/app/src/views/account.js');
    await loadLocale('en');

    const root = document.createElement('div');
    root.id = 'account-ui-harness';
    const chipRoot = document.createElement('div');
    chipRoot.id = 'account-chip-harness';
    document.body.replaceChildren(chipRoot, root);
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
    let restoredPassphrase: string | null = null;
    const render = () => {
      const chip = accountStatusChip(app);
      chipRoot.replaceChildren(...(chip ? [chip] : []));
      const node = accountOverlayView(app);
      root.replaceChildren(...(node ? [node] : []));
    };
    const app = {
      syncStatus: null as null | { state: 'synced' | 'offline' | 'error' | 'auth-error' | 'security' },
      account: { state: () => accountState },
      auth: { capabilities: () => ({ canLogin: true, canSignUp: true, sync: true }) },
      accountUiState: () => uiState,
      showAccountView: (screen = 'overview') => { uiState.screen = screen; render(); },
      closeAccountView: () => { uiState.screen = null; render(); },
      doSignUp: async () => null,
      doSignIn: async () => null,
      doSignOut: async () => null,
      doEnableSync: async () => null,
      doRestore: async (passphrase: string) => { restoredPassphrase = passphrase; return null; },
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
      setTreeSync(state) {
        accountState.auth = 'signedIn';
        accountState.binding = 'backedUp';
        accountState.pending = new Set();
        app.syncStatus = state ? { state } : null;
        uiState.screen = 'overview';
        render();
      },
      show(screen) {
        uiState.screen = screen;
        render();
      },
      restoredPassphrase: () => restoredPassphrase,
    };
    render();
  });

  await page.getByRole('button', { name: /^sign in$/i }).click();
  await expect(page.getByRole('dialog', { name: 'Sign in to sync' })).toBeVisible();
  await expect(page.locator('#account-email')).toBeFocused();
  await page.getByRole('button', { name: /new here/i }).click();
  await expect(page.getByRole('dialog', { name: 'Sign up' })).toBeVisible();

  await page.evaluate(() => window.accountUiHarness.show('restore'));
  await expect(page.getByRole('dialog', { name: 'Restore your synced account' })).toBeVisible();
  const restorePassphrase = page.locator('#account-restore-passphrase');
  await expect(restorePassphrase).toBeFocused();
  await restorePassphrase.fill('restored account passphrase');
  await page.getByRole('button', { name: 'Restore account' }).click();
  await expect.poll(() => page.evaluate(() => window.accountUiHarness.restoredPassphrase()))
    .toBe('restored account passphrase');

  await page.evaluate(() => window.accountUiHarness.setTreeSync(null));
  await expect(page.getByRole('button', { name: /account & sync — sync on/i })).toBeVisible();
  await page.evaluate(() => window.accountUiHarness.setTreeSync('synced'));
  await expect(page.getByRole('button', { name: /account & sync — synced/i })).toBeVisible();
  await page.evaluate(() => window.accountUiHarness.setTreeSync('offline'));
  await expect(page.getByRole('button', { name: /account & sync — sync unavailable/i })).toBeVisible();
  await expect(page.getByText(/latest tree changes could not be uploaded/i)).toBeVisible();

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

test('welcome keeps local-first creation without offering sign-in twice', async ({ page }) => {
  await page.goto('/app/index.html');
  await page.evaluate(async () => {
    const [{ loadLocale }, { gateView }] = await Promise.all([
      import('/app/src/core/i18n.js'),
      import('/app/src/views/gate.js'),
    ]);
    await loadLocale('en');
    const root = document.createElement('div');
    document.body.replaceChildren(root);
    const state = { auth: 'signedOut' as 'signedOut' | 'signedIn' };
    const app = {
      demoEnabled: false,
      startEnabled: true,
      gateBusy: false,
      gateError: '',
      account: { state: () => state },
      auth: { capabilities: () => ({ canLogin: true }) },
      startCreate: () => {},
      showAccountView: () => {},
    };
    const render = () => root.replaceChildren(gateView(app));
    window.accountWelcomeHarness = {
      setAuth(auth) {
        state.auth = auth;
        render();
      },
    };
    render();
  });

  await expect(page.getByRole('button', { name: 'Start your family tree' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in to sync' })).toBeVisible();
  await page.evaluate(() => window.accountWelcomeHarness.setAuth('signedIn'));
  await expect(page.getByRole('button', { name: 'Start your family tree' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in to sync' })).toHaveCount(0);
});
