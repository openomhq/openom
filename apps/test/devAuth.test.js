import { describe, it, expect, vi } from 'vitest';
import { DevAuth, SessionController } from '../app/src/core/session.js';

function fakeAccountSession(initial = null) {
  let memberId = initial;
  const subscribers = new Set();
  return {
    memberId: () => memberId,
    onChange(callback) {
      subscribers.add(callback);
      return () => subscribers.delete(callback);
    },
    setMemberId(next) {
      memberId = next;
      for (const callback of subscribers) callback();
    },
    subscriberCount() {
      return subscribers.size;
    },
  };
}

const mk = (memberId = null) => {
  const account = fakeAccountSession(memberId);
  return { account, auth: new DevAuth(account) };
};

describe('DevAuth — account-backed development provider', () => {
  it('rejects access while the account is locked or absent', async () => {
    const { auth } = mk();
    expect(auth.subject()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'auth_required', retriable: false });

    expect(auth.list).toBeUndefined();
    expect(auth.switchTo).toBeUndefined();
    expect(auth.createAccount).toBeUndefined();
    expect(auth.memberId).toBeUndefined();
  });

  it('uses the durable account member ID as subject and raw development bearer', async () => {
    const { auth, account } = mk('member-durable-1');
    expect(auth.subject()).toBe('member-durable-1');
    expect(await auth.getAccessToken()).toBe('member-durable-1');
    expect(await auth.getAccessToken({ forceRefresh: true })).toBe('member-durable-1');

    account.setMemberId('member-durable-2');
    expect(auth.subject()).toBe('member-durable-2');
    expect(await auth.getAccessToken()).toBe('member-durable-2');
  });

  it('advertises account-backed development capabilities', () => {
    const { auth } = mk();
    expect(auth.capabilities()).toEqual({ canRegister: false, canLogin: false, sync: true });
  });

  it('fans out account changes and stops after unsubscribe', () => {
    const { auth, account } = mk();
    const callback = vi.fn();
    const off = auth.onChange(callback);

    account.setMemberId('member-1');
    expect(callback).toHaveBeenCalledTimes(1);
    off();
    account.setMemberId(null);
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('disposes its account subscription and local subscribers', () => {
    const { auth, account } = mk('member-1');
    const callback = vi.fn();
    auth.onChange(callback);
    expect(account.subscriberCount()).toBe(1);

    auth.dispose();
    expect(account.subscriberCount()).toBe(0);
    account.setMemberId('member-2');
    expect(callback).not.toHaveBeenCalled();
  });
});

describe('SessionController — delegates the provider-auth seam', () => {
  it('forwards subject, token, capabilities, and changes without exposing account identity accessors', async () => {
    const { auth, account } = mk('member-controller');
    const controller = new SessionController(auth);
    expect(controller.subject()).toBe('member-controller');
    expect(await controller.getAccessToken()).toBe('member-controller');
    expect(controller.capabilities()).toEqual({ canRegister: false, canLogin: false, sync: true });
    expect(controller.memberId).toBeUndefined();
    expect(controller.signIn).toBeUndefined();
    expect(controller.signOut).toBeUndefined();

    const callback = vi.fn();
    const off = controller.onChange(callback);
    account.setMemberId('member-controller-2');
    expect(callback).toHaveBeenCalledTimes(1);
    off();
  });

  it('requires a backend', () => {
    expect(() => new SessionController(null)).toThrow();
    expect(() => new DevAuth(null)).toThrow('needs an AccountSession');
  });
});
