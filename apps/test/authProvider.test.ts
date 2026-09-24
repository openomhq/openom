import { describe, expect, it, vi } from 'vitest';
import { createAuthProvider, readAuthProviderConfig } from '../app/src/core/authProvider.js';
import { AuthSessionCoordinator } from '../app/src/core/authSessionStore.js';
import { DevAuth, SessionController, SupabaseAuth } from '../app/src/core/session.js';

function documentWith(values: Record<string, string>) {
  return {
    querySelector(selector: string) {
      const name = selector.match(/^meta\[name="(.+)"\]$/)?.[1];
      return name && name in values ? { content: values[name] } : null;
    },
  };
}

function account() {
  return { memberId: () => null, onChange: () => () => {} };
}

describe('auth provider configuration', () => {
  it('defaults absent and unsubstituted local metadata to DevAuth', () => {
    expect(readAuthProviderConfig(documentWith({}))).toEqual({ provider: 'dev' });
    expect(readAuthProviderConfig(documentWith({ 'openom:auth-provider': '%AUTH_PROVIDER%' })))
      .toEqual({ provider: 'dev' });
  });

  it('reads complete explicit Supabase configuration', () => {
    expect(readAuthProviderConfig(documentWith({
      'openom:auth-provider': 'supabase',
      'openom:supabase-url': 'https://project.supabase.co',
      'openom:supabase-anon-key': 'publishable-key',
    }))).toEqual({
      provider: 'supabase',
      url: 'https://project.supabase.co',
      publishableKey: 'publishable-key',
    });
  });

  it('fails closed on unsupported or incomplete explicit provider selection', () => {
    expect(() => readAuthProviderConfig(documentWith({ 'openom:auth-provider': 'other' })))
      .toThrow('unsupported auth provider');
    expect(() => readAuthProviderConfig(documentWith({
      'openom:auth-provider': 'supabase',
      'openom:supabase-url': '%SUPABASE_URL%',
      'openom:supabase-anon-key': 'key',
    }))).toThrow('requires a project URL and publishable key');
  });
});

describe('auth provider factory', () => {
  it('constructs DevAuth without adding interactive provider operations', () => {
    const provider = createAuthProvider(account(), { config: { provider: 'dev' } });
    expect(provider).toBeInstanceOf(DevAuth);
    expect(provider.capabilities()).toEqual({ canSignUp: false, canLogin: false, sync: true });
    expect(provider.signIn).toBeUndefined();
    expect(provider.signOut).toBeUndefined();
  });

  it('constructs the direct Supabase provider with interactive controller operations', async () => {
    const fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: `${btoa('{}')}.${btoa(JSON.stringify({ iss: 'https://issuer', sub: 'subject' }))}.sig`,
        refresh_token: 'refresh-token',
        expires_at: 2_000_000_000,
      }),
    }) as Response);
    const provider = createAuthProvider(account(), {
      config: {
        provider: 'supabase',
        url: 'https://project.supabase.co',
        publishableKey: 'publishable-key',
      },
      fetch,
      sessionStore: new AuthSessionCoordinator('test', {
        storage: null,
        locks: null,
        broadcastFactory: null,
      }),
    });
    expect(provider).toBeInstanceOf(SupabaseAuth);
    const controller = new SessionController(provider);
    await controller.signIn({ email: 'person@example.test', password: 'secret' });
    expect(fetch).toHaveBeenCalledTimes(1);
    await expect(controller.getAccessToken()).resolves.toContain('.');
    expect(controller.memberId).toBeUndefined();
    expect(controller.issuer).toBeUndefined();
  });
});
