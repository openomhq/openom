// AuthSession — the ONE seam the app's networking depends on for provider authentication.
//
// It is the forward-compat boundary (design.local-accounts-auth §1): everything below it —
// `RemoteStore`'s bearer and provider subject talk to THIS interface and nothing else. Cryptographic
// identity belongs to AccountSession; it is never inferred from an auth token. Swapping the
// auth provider (DevAuth now; SupabaseAuth / ClerkAuth / any OIDC later) is a one-line change at
// composition; no other client code moves. The wire is identical in every mode
// (`Authorization: Bearer <token>`); only the token's provenance differs, and it is hidden here.
//
//   interface AuthSession {
//     getAccessToken({ forceRefresh } = {}): Promise<string>  // the Bearer value; refresh behind the seam
//     registrationAttempt({ forceRefresh } = {}): Promise<{ accessToken, issuer, subject }>
//     subject(): string | null                                // opaque provider subject (`sub`)
//     onChange(cb): () => void                                // cb() on identity change; returns an unsubscribe
//     capabilities(): { canRegister, canLogin, sync }
//   }
//
// Auth `sub` says who authenticated a request. AccountSession.memberId() says whose keys signed data.
// `/register` binds them; client code must never equate or derive one from the other.

/**
 * DevAuth — the singleton development auth provider. It persists no parallel account or identity:
 * availability follows the profile's AccountSession, and the dev server accepts its durable member ID
 * as a raw bearer. Production providers retain their own opaque subjects and are bound in Phase 2.
 */
import { makeError } from './errorModel.js';

/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/session.js').AccountIdentitySource} AccountIdentitySource */
/** @typedef {import('./types/session.js').AuthSession} AuthSession */
/** @typedef {import('./types/session.js').SupabaseClientLike} SupabaseClientLike */
/** @typedef {import('./types/session.js').SupabaseSessionLike} SupabaseSessionLike */

/** @param {string} accessToken @returns {{ issuer: AuthIssuer, subject: AuthSubject }} */
function jwtClaims(accessToken) {
  const payload = accessToken.split('.')[1];
  if (!payload) throw makeError('auth_required', { cause: 'auth token has no JWT payload' });
  try {
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
    /** @type {unknown} */
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) throw new Error('invalid claims');
    const claims = /** @type {Record<string, unknown>} */ (decoded);
    if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new Error('missing sub');
    return {
      issuer: /** @type {AuthIssuer} */ (typeof claims.iss === 'string' ? claims.iss : ''),
      subject: /** @type {AuthSubject} */ (claims.sub),
    };
  } catch (error) {
    throw makeError('auth_required', { cause: `auth token claims are unavailable: ${error}` });
  }
}

/** @implements {AuthSession} */
export class DevAuth {
  /** @type {AccountIdentitySource} */
  #account;
  /** @type {Set<() => void>} */
  #subs = new Set();
  /** @type {(() => void) | null} */
  #unsubscribeAccount = null;

  /** @param {AccountIdentitySource} accountSession */
  constructor(accountSession) {
    if (typeof accountSession?.memberId !== 'function' || typeof accountSession?.onChange !== 'function') {
      throw new Error('DevAuth needs an AccountSession');
    }
    this.#account = accountSession;
    this.#unsubscribeAccount = this.#account.onChange(() => this.#notify());
  }

  // ---- the AuthSession seam ----

  subject() {
    const memberId = this.#account.memberId();
    // Dev convenience only: the provider subject deliberately coincides with the durable member ID.
    return memberId === null ? null : /** @type {AuthSubject} */ (/** @type {unknown} */ (memberId));
  }

  // eslint-disable-next-line no-unused-vars -- forceRefresh is a no-op for option (A); the seam for option (B).
  async getAccessToken({ forceRefresh = false } = {}) {
    const id = this.subject();
    if (!id) throw makeError('auth_required', { cause: 'DevAuth: profile account is locked' });
    return this.#tokenFor(id, { forceRefresh });
  }

  /** @param {AuthSubject} memberId @param {{ readonly forceRefresh?: boolean }} [_opts] */
  async #tokenFor(memberId, _opts = {}) {
    return memberId;
  }

  async registrationAttempt({ forceRefresh = false } = {}) {
    const subject = this.subject();
    if (!subject) throw makeError('auth_required', { cause: 'DevAuth: profile account is locked' });
    const accessToken = await this.#tokenFor(subject, { forceRefresh });
    return { accessToken, issuer: /** @type {AuthIssuer} */ (''), subject };
  }

  /** @param {() => void} cb */
  /** @param {() => void} cb */
  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    return { canRegister: false, canLogin: false, sync: true };
  }

  #notify() {
    for (const cb of this.#subs) {
      try {
        cb();
      } catch (e) {
        console.warn('[openom] auth onChange subscriber threw', e);
      }
    }
  }

  /** Detach from account-custody changes (worker replacement / tests). */
  dispose() {
    this.#unsubscribeAccount?.();
    this.#unsubscribeAccount = null;
    this.#subs.clear();
  }
}

/**
 * SupabaseAuth — a documented stub implementing the SAME AuthSession seam over supabase-js. NOT wired
 * or imported anywhere; it exists so the production swap is one line at composition
 * (`new SessionController(new SupabaseAuth(client))`) with nothing else in the client changing.
 *
 * Shape only (uncomment + `npm i @supabase/supabase-js` when wiring):
 *   getAccessToken() → session.access_token  (supabase-js refreshes under the hood; forceRefresh → refreshSession())
 *   subject()        → session.user.id       (the token's `sub`)
 *   signIn/out       → client.auth.signInWithPassword / signOut
 *   onChange         → client.auth.onAuthStateChange
 */
/** @implements {AuthSession} */
export class SupabaseAuth {
  /** @type {SupabaseClientLike} */
  #client;
  /** @type {SupabaseSessionLike | null} */
  #session = null;
  /** @type {Set<() => void>} */
  #subs = new Set();

  /** @param {SupabaseClientLike} client */
  constructor(client) {
    this.#client = client;
    // client.auth.onAuthStateChange((_event, session) => { this.#session = session; this.#notify(); });
  }

  async getAccessToken({ forceRefresh = false } = {}) {
    if (forceRefresh) {
      // const { data } = await this.#client.auth.refreshSession();
      // this.#session = data.session;
    }
    const token = this.#session?.access_token;
    if (!token) throw makeError('auth_required', { cause: 'SupabaseAuth: no session' });
    return token;
  }

  async registrationAttempt({ forceRefresh = false } = {}) {
    const accessToken = await this.getAccessToken({ forceRefresh });
    return { accessToken, ...jwtClaims(accessToken) };
  }

  subject() {
    return this.#session?.user?.id ?? null;
  }

  /** @param {unknown} credentials */
  async signIn(credentials) {
    return this.#client.auth.signInWithPassword(credentials);
  }

  async signOut() {
    return this.#client.auth.signOut();
  }

  /** @param {() => void} cb */
  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    return { canRegister: true, canLogin: true, sync: true };
  }
}

/**
 * SessionController — the app-facing handle over a swappable `#auth` backend. It IS an AuthSession
 * (delegates the whole seam) so the rest of the app depends on one stable object and one "who's
 * logged in" truth, while the provider under it is chosen once at composition (the swap point).
 */
export class SessionController {
  /** @type {AuthSession} */
  #auth;

  /** @param {AuthSession} auth */
  constructor(auth) {
    if (!auth) throw new Error('SessionController needs an AuthSession backend');
    this.#auth = auth;
  }

  /** @param {{ readonly forceRefresh?: boolean }} [opts] */
  getAccessToken(opts) {
    return this.#auth.getAccessToken(opts);
  }
  /** @param {{ readonly forceRefresh?: boolean }} [opts] */
  registrationAttempt(opts) {
    return this.#auth.registrationAttempt(opts);
  }
  subject() {
    return this.#auth.subject();
  }
  /** @param {() => void} cb */
  /** @param {() => void} cb */
  /** @param {() => void} cb */
  /** @param {() => void} cb */
  onChange(cb) {
    return this.#auth.onChange(cb);
  }
  capabilities() {
    return this.#auth.capabilities();
  }

  dispose() {
    return this.#auth.dispose?.();
  }
}
