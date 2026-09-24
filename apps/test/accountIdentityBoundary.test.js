import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const source = (relativePath) => readFile(new URL(`../app/src/${relativePath}`, import.meta.url), 'utf8');
const appFile = (relativePath) => readFile(new URL(`../app/${relativePath}`, import.meta.url), 'utf8');

describe('account identity composition boundary', () => {
  it('leaves account lifecycle construction and auth interpretation outside main', async () => {
    const main = await source('main.js');
    expect(main).not.toMatch(/new AccountSession\b/);
    expect(main).not.toMatch(/new SessionController\b/);
    expect(main).not.toMatch(/(?:this\.)?auth\.subject\s*\(/);
    expect(main).toContain('composeAccountSession(this.worker');
    expect(main).toContain('this.account.onChange(');
  });

  it('does not expose a bearer-subject-to-member-id conversion helper', async () => {
    const [accountSession, session, remoteStore] = await Promise.all([
      source('core/accountSession.js'),
      source('core/session.js'),
      source('core/remoteStore.js'),
    ]);
    const productionSources = `${accountSession}\n${session}\n${remoteStore}`;
    expect(productionSources).not.toMatch(/memberIdFrom(?:Sub|Subject|Bearer)/i);
  });

  it('keeps provider sign-up capability separate from durable identity binding', async () => {
    const [accountSession, session] = await Promise.all([
      source('core/accountSession.js'),
      source('core/session.js'),
    ]);
    expect(session).not.toContain('canRegister');
    expect(accountSession).not.toContain('canSignUp');
    expect(session).not.toMatch(/\bissuer\s*\(\s*\)/);
  });

  it('keeps provider bearer material out of account UI state', async () => {
    const accountUi = await source('core/accountUiActions.js');
    expect(accountUi).not.toContain('accessToken');
    expect(accountUi).not.toContain('registrationAttempt');
    expect(accountUi).toContain('discovery: probe.status');
  });

  it('mounts account presentation independently from the custody gate and tree shell', async () => {
    const [main, html] = await Promise.all([source('main.js'), appFile('index.html')]);
    expect(html).toContain('<div id="account-overlay" hidden></div>');
    expect(main).toContain('renderAccountSurface()');
    expect(main).toMatch(/render\(\)\s*{\s*this\.renderAccountSurface\(\);\s*\/\/ While a gate/);
    expect(main).toContain('accountStatusChip(this)');
    expect(main).toContain('showAccountView(screen =');
  });
});
