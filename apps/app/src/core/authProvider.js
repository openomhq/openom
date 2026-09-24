// Provider selection is a composition concern. This module reads only public build-time configuration and
// constructs the provider-auth seam; it never reads or derives cryptographic account identity from auth.
import { GoTrueClient } from './gotrueClient.js';
import { DevAuth, SupabaseAuth } from './session.js';

/** @typedef {import('./types/session.js').AccountIdentitySource} AccountIdentitySource */
/** @typedef {import('./types/session.js').AuthProvider} AuthProvider */
/** @typedef {import('./types/session.js').AuthSessionCoordinatorLike} AuthSessionCoordinatorLike */
/** @typedef {{ readonly provider: 'dev' } | { readonly provider: 'supabase', readonly url: string, readonly publishableKey: string }} AuthProviderConfig */
/** @typedef {{ querySelector(selector: string): { content?: string } | null }} MetaDocument */

/** @param {MetaDocument} documentLike @param {string} name */
function metaContent(documentLike, name) {
  return documentLike.querySelector(`meta[name="${name}"]`)?.content?.trim() ?? '';
}

/** @param {string} value */
function unresolved(value) {
  return value.length === 0 || /^%[A-Z0-9_]+%$/.test(value);
}

/**
 * Read public provider configuration. Missing/unsubstituted local metadata deliberately selects DevAuth;
 * an explicit Supabase selection is strict and cannot silently fall back to development authentication.
 * @param {MetaDocument} [documentLike]
 * @returns {AuthProviderConfig}
 */
export function readAuthProviderConfig(documentLike = globalThis.document) {
  if (!documentLike?.querySelector) return { provider: 'dev' };
  const provider = metaContent(documentLike, 'openom:auth-provider');
  if (unresolved(provider) || provider === 'dev') return { provider: 'dev' };
  if (provider !== 'supabase') throw new Error(`unsupported auth provider: ${provider}`);

  const url = metaContent(documentLike, 'openom:supabase-url');
  const publishableKey = metaContent(documentLike, 'openom:supabase-anon-key');
  if (unresolved(url) || unresolved(publishableKey)) {
    throw new Error('Supabase auth requires a project URL and publishable key');
  }
  return { provider: 'supabase', url, publishableKey };
}

/**
 * @param {AccountIdentitySource} accountSession
 * @param {{
 *   config?: AuthProviderConfig,
 *   document?: MetaDocument,
 *   fetch?: typeof globalThis.fetch,
 *   sessionStore?: AuthSessionCoordinatorLike,
 * }} [options]
 * @returns {AuthProvider}
 */
export function createAuthProvider(accountSession, {
  config,
  document: documentLike,
  fetch,
  sessionStore,
} = {}) {
  const selected = config ?? readAuthProviderConfig(documentLike);
  if (selected.provider === 'dev') return new DevAuth(accountSession);

  const client = new GoTrueClient({
    url: selected.url,
    publishableKey: selected.publishableKey,
    ...(fetch ? { fetch } : {}),
  });
  return new SupabaseAuth(client, {
    scope: selected.url,
    ...(sessionStore ? { store: sessionStore } : {}),
  });
}
