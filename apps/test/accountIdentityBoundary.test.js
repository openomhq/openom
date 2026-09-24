import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const source = (relativePath) => readFile(new URL(`../app/src/${relativePath}`, import.meta.url), 'utf8');

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
});
