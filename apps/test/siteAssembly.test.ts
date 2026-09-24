import { describe, expect, it } from 'vitest';
import { assembleHtml, authConfig } from '../scripts/site-url.mjs';

const template = `
  <meta name="openom:landing" content="%LANDING%">
  <meta name="openom:server" content="%SERVER%">
  <meta name="openom:auth-provider" content="%AUTH_PROVIDER%">
  <meta name="openom:supabase-url" content="%SUPABASE_URL%">
  <meta name="openom:supabase-anon-key" content="%SUPABASE_ANON_KEY%">
  <link href="%SITE_URL%assets/icon.svg">
`;

describe('site auth assembly', () => {
  it('assembles local/default builds with DevAuth and no unresolved auth placeholders', () => {
    const html = assembleHtml(template, {
      siteUrl: 'http://localhost:5173/',
      landing: 'demo',
      server: 'http://localhost:6060',
      auth: authConfig({}),
    });
    expect(html).toContain('name="openom:auth-provider" content="dev"');
    expect(html).toContain('name="openom:supabase-url" content=""');
    expect(html).not.toMatch(/%(?:AUTH_PROVIDER|SUPABASE_URL|SUPABASE_ANON_KEY)%/);
  });

  it('assembles explicit Supabase public configuration without logging or transforming the key', () => {
    const auth = authConfig({
      OPENOM_AUTH_PROVIDER: 'supabase',
      SUPABASE_URL: 'https://project.supabase.co',
      SUPABASE_PUBLISHABLE_KEY: 'public-key-value',
    });
    const html = assembleHtml(template, {
      siteUrl: 'https://app.example/',
      landing: 'live',
      server: 'https://api.example',
      auth,
    });
    expect(html).toContain('name="openom:auth-provider" content="supabase"');
    expect(html).toContain('name="openom:supabase-url" content="https://project.supabase.co"');
    expect(html).toContain('name="openom:supabase-anon-key" content="public-key-value"');
    expect(html).not.toMatch(/%[A-Z0-9_]+%/);
  });

  it('fails assembly configuration for unknown providers and incomplete Supabase selection', () => {
    expect(() => authConfig({ OPENOM_AUTH_PROVIDER: 'unknown' })).toThrow('must be dev or supabase');
    expect(() => authConfig({ OPENOM_AUTH_PROVIDER: 'supabase' })).toThrow(
      'requires SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY',
    );
    expect(() => authConfig({
      OPENOM_AUTH_PROVIDER: 'supabase',
      SUPABASE_URL: 'https://project.supabase.co/path',
      SUPABASE_PUBLISHABLE_KEY: 'key',
    })).toThrow('valid HTTP(S) origin');
  });

  it('refuses to return an artifact when an app placeholder survives', () => {
    expect(() => assembleHtml(`${template}%SERVER%`, {
      siteUrl: '%SITE_URL%',
      landing: 'live',
      server: '%SERVER%',
      auth: authConfig({}),
    })).toThrow('unresolved app placeholders');
  });
});
