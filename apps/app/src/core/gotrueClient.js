// Thin, provider-specific wire adapter for Supabase Auth's GoTrue REST API.
//
// This module knows endpoint paths, headers, and response shapes. It deliberately owns no session state,
// persistence, refresh scheduling, cross-tab coordination, or account identity. Those policies belong to
// SupabaseAuth; this adapter only turns untrusted HTTP responses into a small validated token record.
import { makeError } from './errorModel.js';

/** @typedef {(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>} FetchLike */
/** @typedef {{ readonly email: string, readonly password: string }} PasswordCredentials */
/** @typedef {{ readonly accessToken: string, readonly refreshToken: string, readonly expiresAt: number }} GoTrueTokenSet */
/** @typedef {{ readonly status: 'signedIn', readonly tokens: GoTrueTokenSet } | { readonly status: 'confirmationRequired' }} GoTrueSignUpResult */
/** @typedef {{ readonly url: string, readonly publishableKey: string, readonly fetch?: FetchLike, readonly now?: () => number }} GoTrueClientOptions */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** @param {string} value */
function projectOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError('GoTrueClient requires a valid project URL');
  }
  if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new TypeError('GoTrueClient requires an HTTP(S) project origin');
  }
  return parsed.origin;
}

/** @param {unknown} value @param {number} nowMs @returns {GoTrueTokenSet} */
function decodeTokenSet(value, nowMs) {
  if (!isRecord(value)
    || typeof value.access_token !== 'string' || value.access_token.length === 0
    || typeof value.refresh_token !== 'string' || value.refresh_token.length === 0) {
    throw makeError('request_failed', { cause: 'Supabase Auth returned an invalid token response' });
  }

  const absoluteExpiry = value.expires_at;
  /** @type {number} */
  let expiresAt;
  if (typeof absoluteExpiry === 'number' && Number.isSafeInteger(absoluteExpiry) && absoluteExpiry > 0) {
    expiresAt = absoluteExpiry;
  } else {
    const expiresIn = value.expires_in;
    if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw makeError('request_failed', { cause: 'Supabase Auth returned an invalid token expiry' });
    }
    expiresAt = Math.floor(nowMs / 1_000 + expiresIn);
  }

  return {
    accessToken: value.access_token,
    refreshToken: value.refresh_token,
    expiresAt,
  };
}

/** @param {unknown} value @param {number} nowMs @returns {GoTrueSignUpResult} */
function decodeSignUp(value, nowMs) {
  if (isRecord(value)
    && typeof value.access_token === 'string' && value.access_token.length > 0
    && typeof value.refresh_token === 'string' && value.refresh_token.length > 0) {
    return { status: 'signedIn', tokens: decodeTokenSet(value, nowMs) };
  }
  if (isRecord(value)
    && typeof value.id === 'string' && value.id.length > 0
    && typeof value.email === 'string' && value.email.length > 0) {
    return { status: 'confirmationRequired' };
  }
  throw makeError('request_failed', { cause: 'Supabase Auth returned an invalid sign-up response' });
}

/** @param {number} status @param {'signup'|'password'|'refresh'|'logout'} operation */
function responseError(status, operation) {
  if (operation === 'signup' && status >= 400 && status < 500 && status !== 429) {
    return makeError('sign_up_failed', { httpStatus: status, cause: 'Supabase Auth rejected sign-up' });
  }
  if (operation === 'password' && status >= 400 && status < 500 && status !== 429) {
    return makeError('sign_in_failed', { httpStatus: status, cause: 'Supabase Auth rejected sign-in' });
  }
  if (operation !== 'password' && (status === 400 || status === 401 || status === 403)) {
    return makeError('session_expired', { httpStatus: status, cause: 'Supabase Auth rejected the session' });
  }
  return makeError('request_failed', { httpStatus: status, cause: 'Supabase Auth request failed' });
}

export class GoTrueClient {
  /** @type {string} */
  #origin;
  /** @type {string} */
  #publishableKey;
  /** @type {FetchLike} */
  #fetch;
  /** @type {() => number} */
  #now;

  /** @param {GoTrueClientOptions} options */
  constructor({ url, publishableKey, fetch: fetchImpl, now = Date.now }) {
    if (typeof publishableKey !== 'string' || publishableKey.length === 0) {
      throw new TypeError('GoTrueClient requires a publishable key');
    }
    if (fetchImpl !== undefined && typeof fetchImpl !== 'function') {
      throw new TypeError('GoTrueClient requires a fetch function');
    }
    if (typeof now !== 'function') throw new TypeError('GoTrueClient requires a clock function');
    this.#origin = projectOrigin(url);
    this.#publishableKey = publishableKey;
    this.#fetch = fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.#now = now;
  }

  /** @param {PasswordCredentials} credentials @returns {Promise<GoTrueSignUpResult>} */
  async signUp(credentials) {
    this.#validateCredentials(credentials, 'sign_up_failed');
    const value = await this.#jsonRequest(
      '/auth/v1/signup',
      { email: credentials.email, password: credentials.password },
      'signup',
    );
    return decodeSignUp(value, this.#now());
  }

  /** @param {PasswordCredentials} credentials @returns {Promise<GoTrueTokenSet>} */
  async signInWithPassword(credentials) {
    this.#validateCredentials(credentials, 'sign_in_failed');
    const value = await this.#jsonRequest(
      '/auth/v1/token?grant_type=password',
      { email: credentials.email, password: credentials.password },
      'password',
    );
    return decodeTokenSet(value, this.#now());
  }

  /** @param {string} refreshToken @returns {Promise<GoTrueTokenSet>} */
  async refresh(refreshToken) {
    if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
      throw makeError('session_expired', { cause: 'Refresh token is unavailable' });
    }
    const value = await this.#jsonRequest(
      '/auth/v1/token?grant_type=refresh_token',
      { refresh_token: refreshToken },
      'refresh',
    );
    return decodeTokenSet(value, this.#now());
  }

  /** @param {string} accessToken @returns {Promise<void>} */
  async signOut(accessToken) {
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      throw makeError('session_expired', { cause: 'Access token is unavailable' });
    }
    const response = await this.#request('/auth/v1/logout?scope=local', {
      method: 'POST',
      headers: this.#headers(accessToken),
    });
    if (!response.ok) throw responseError(response.status, 'logout');
  }

  /**
   * @param {string} path
   * @param {Record<string, string>} body
   * @param {'signup'|'password'|'refresh'} operation
   * @returns {Promise<unknown>}
   */
  async #jsonRequest(path, body, operation) {
    const response = await this.#request(path, {
      method: 'POST',
      headers: this.#headers(),
      body: JSON.stringify(body),
    });
    if (!response.ok) throw responseError(response.status, operation);
    try {
      return await response.json();
    } catch {
      throw makeError('request_failed', {
        httpStatus: response.status,
        cause: 'Supabase Auth returned malformed JSON',
      });
    }
  }

  /** @param {PasswordCredentials} credentials @param {'sign_up_failed'|'sign_in_failed'} code */
  #validateCredentials(credentials, code) {
    if (typeof credentials?.email !== 'string' || credentials.email.length === 0
      || typeof credentials?.password !== 'string' || credentials.password.length === 0) {
      throw makeError(code, { cause: 'Email and password are required' });
    }
  }

  /** @param {string} path @param {RequestInit} init */
  async #request(path, init) {
    try {
      return await this.#fetch(`${this.#origin}${path}`, init);
    } catch {
      throw makeError('request_failed', { cause: 'Supabase Auth request failed' });
    }
  }

  /** @param {string} [accessToken] @returns {Record<string, string>} */
  #headers(accessToken) {
    return {
      accept: 'application/json',
      apikey: this.#publishableKey,
      'content-type': 'application/json',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    };
  }
}
