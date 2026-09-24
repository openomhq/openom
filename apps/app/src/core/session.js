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
//     capabilities(): { canSignUp, canLogin, sync }
//   }
//
// Auth `sub` says who authenticated a request. AccountSession.memberId() says whose keys signed data.
// `/register` binds them; client code must never equate or derive one from the other.

/**
 * DevAuth — the singleton development auth provider. It persists no parallel account or identity:
 * availability follows the profile's AccountSession, and the dev server accepts its durable member ID
 * as a raw bearer. Production providers retain their own opaque subjects and bind them through the account facade.
 */
import { AuthSessionCoordinator } from './authSessionStore.js';
import { isAppError, makeError } from './errorModel.js';

/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/session.js').AccountIdentitySource} AccountIdentitySource */
/** @typedef {import('./types/session.js').AuthSessionCoordinatorLike} AuthSessionCoordinatorLike */
/** @typedef {import('./types/session.js').AuthSessionRecord} AuthSessionRecord */
/** @typedef {import('./types/session.js').AuthSession} AuthSession */
/** @typedef {import('./types/session.js').AuthProvider} AuthProvider */
/** @typedef {import('./types/session.js').GoTrueClientLike} GoTrueClientLike */
/** @typedef {import('./types/session.js').GoTrueTokenSet} GoTrueTokenSet */
/** @typedef {import('./types/session.js').PasswordCredentials} PasswordCredentials */
/** @typedef {{ kind: 'inactive', record: AuthSessionRecord|null } | { kind: 'retry'|'expired', record: AuthSessionRecord } | { kind: 'refreshed', tokens: GoTrueTokenSet, claims: { issuer: AuthIssuer, subject: AuthSubject }, record: AuthSessionRecord }} RefreshOutcome */
/** @typedef {{ kind: 'retry'|'done', record: AuthSessionRecord|null }} LogoutOutcome */

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
    if (typeof claims.iss !== 'string' || claims.iss.length === 0) throw new Error('missing iss');
    return { issuer: /** @type {AuthIssuer} */ (claims.iss), subject: /** @type {AuthSubject} */ (claims.sub) };
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
  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    return { canSignUp: false, canLogin: false, sync: true };
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
 * SupabaseAuth — provider session policy over the direct GoTrue REST client. Access tokens stay in memory;
 * only a versioned rotating refresh record and non-secret continuity hints are persisted. Every refresh runs
 * under the project lock and commits the replacement before publishing it or returning an access token.
 */
/** @implements {AuthSession} */
export class SupabaseAuth {
  /** @type {GoTrueClientLike} */
  #client;
  /** @type {AuthSessionCoordinatorLike} */
  #store;
  /** @type {AuthSessionRecord|null} */
  #record;
  /** @type {{ accessToken: string, expiresAt: number, issuer: AuthIssuer, subject: AuthSubject } | null} */
  #session = null;
  /** @type {Set<() => void>} */
  #subs = new Set();
  /** @type {Promise<string>|null} */
  #refreshPromise = null;
  /** @type {() => void} */
  #unsubscribeRevision;
  /** @type {() => number} */
  #now;
  /** @type {number} */
  #refreshMarginMs;
  #disposed = false;

  /**
   * @param {GoTrueClientLike} client
   * @param {{ scope?: string, store?: AuthSessionCoordinatorLike, now?: () => number, refreshMarginMs?: number }} [options]
   */
  constructor(client, { scope, store, now = Date.now, refreshMarginMs = 60_000 } = {}) {
    if (!client || typeof client.signInWithPassword !== 'function'
      || typeof client.refresh !== 'function' || typeof client.signOut !== 'function') {
      throw new Error('SupabaseAuth needs a GoTrue client');
    }
    if (!store && (typeof scope !== 'string' || scope.length === 0)) {
      throw new Error('SupabaseAuth needs a project scope');
    }
    if (typeof now !== 'function' || !Number.isFinite(refreshMarginMs) || refreshMarginMs < 0) {
      throw new Error('SupabaseAuth needs a valid clock and refresh margin');
    }
    this.#client = client;
    this.#store = store ?? new AuthSessionCoordinator(/** @type {string} */ (scope));
    this.#record = this.#store.read();
    this.#now = now;
    this.#refreshMarginMs = refreshMarginMs;
    this.#unsubscribeRevision = this.#store.onRevision((revision) => this.#receiveRevision(revision));
  }

  async getAccessToken({ forceRefresh = false } = {}) {
    if (this.#disposed) throw makeError('auth_required', { cause: 'SupabaseAuth is disposed' });
    if (!forceRefresh && this.#session
      && this.#session.expiresAt * 1_000 - this.#now() > this.#refreshMarginMs) {
      return this.#session.accessToken;
    }
    if (!this.#refreshPromise) {
      const refresh = this.#refreshWithRetry();
      this.#refreshPromise = refresh;
      void refresh.finally(() => {
        if (this.#refreshPromise === refresh) this.#refreshPromise = null;
      }).catch(() => {});
    }
    return this.#refreshPromise;
  }

  async registrationAttempt({ forceRefresh = false } = {}) {
    const accessToken = await this.getAccessToken({ forceRefresh });
    return { accessToken, ...jwtClaims(accessToken) };
  }

  subject() {
    if (this.#session) return this.#session.subject;
    return this.#record?.state === 'active'
      ? /** @type {AuthSubject} */ (this.#record.subject)
      : null;
  }

  /** @param {PasswordCredentials} credentials */
  async signIn(credentials) {
    const result = await this.#store.runExclusive(this.#record, async (transaction) => {
      const tokens = await this.#client.signInWithPassword(credentials);
      const claims = this.#validatedClaims(tokens.accessToken);
      const committed = transaction.commit({
        state: 'active',
        refreshToken: tokens.refreshToken,
        issuer: claims.issuer,
        subject: claims.subject,
      });
      return { tokens, claims, record: committed.record };
    });
    this.#install(result.tokens, result.claims, result.record);
    this.#notify();
  }

  async signOut() {
    if (this.#record?.state !== 'active') {
      const hadSession = this.#session !== null || this.#record?.state === 'expired';
      this.#session = null;
      if (hadSession) this.#notify();
      return;
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      /** @type {unknown} */
      let remoteError = null;
      /** @type {string|null} */
      let accessToken = null;
      try {
        accessToken = await this.getAccessToken();
      } catch (error) {
        if (!isAppError(error) || (error.code !== 'auth_required' && error.code !== 'session_expired')) {
          remoteError = error;
        }
      }
      const claims = accessToken ? this.#validatedClaims(accessToken) : null;

      const outcome = /** @type {LogoutOutcome} */ (await this.#store.runExclusive(this.#record, async (transaction) => {
        const current = transaction.record();
        if (current?.state === 'active' && claims
          && (current.issuer !== claims.issuer || current.subject !== claims.subject)) {
          return { kind: 'retry', record: current };
        }
        if (current?.state !== 'active') return { kind: 'done', record: current };
        try {
          if (accessToken) await this.#client.signOut(accessToken);
        } catch (error) {
          remoteError = error;
        }
        return { kind: 'done', record: transaction.commit({ state: 'signed_out' }).record };
      }));

      this.#record = outcome.record;
      this.#session = null;
      if (outcome.kind === 'retry') continue;
      this.#notify();
      if (remoteError) throw remoteError;
      return;
    }
    throw makeError('request_failed', { cause: 'Supabase Auth identity changed during logout' });
  }

  /** @param {() => void} cb */
  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    return { canSignUp: false, canLogin: true, sync: true };
  }

  dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#unsubscribeRevision();
    this.#store.close?.();
    this.#subs.clear();
    this.#session = null;
  }

  async #refreshWithRetry() {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const outcome = /** @type {RefreshOutcome} */ (await this.#store.runExclusive(this.#record, async (transaction) => {
        const current = transaction.record();
        if (current?.state !== 'active') return { kind: 'inactive', record: current };
        try {
          const tokens = await this.#client.refresh(current.refreshToken);
          const claims = this.#validatedClaims(tokens.accessToken);
          if (claims.issuer !== current.issuer || claims.subject !== current.subject) {
            const expired = transaction.commit({ state: 'expired' }).record;
            return { kind: 'expired', record: expired };
          }
          const committed = transaction.commit({
            state: 'active',
            refreshToken: tokens.refreshToken,
            issuer: claims.issuer,
            subject: claims.subject,
          });
          return { kind: 'refreshed', tokens, claims, record: committed.record };
        } catch (error) {
          if (!isAppError(error) || error.code !== 'session_expired') throw error;
          const latest = this.#store.read();
          if (latest?.state === 'active'
            && (latest.revision !== current.revision || latest.refreshToken !== current.refreshToken)) {
            return { kind: 'retry', record: latest };
          }
          const expired = transaction.commit({ state: 'expired' }).record;
          return { kind: 'expired', record: expired };
        }
      }));

      if (outcome.kind === 'retry') {
        this.#record = outcome.record;
        this.#session = null;
        continue;
      }
      if (outcome.kind === 'refreshed') {
        this.#install(outcome.tokens, outcome.claims, outcome.record);
        return outcome.tokens.accessToken;
      }
      this.#record = outcome.record;
      this.#session = null;
      if (outcome.kind === 'expired') {
        this.#notify();
        throw makeError('session_expired', { cause: 'Supabase Auth session expired' });
      }
      throw this.#missingSessionError();
    }
    throw makeError('request_failed', { cause: 'Supabase Auth session changed during refresh' });
  }

  /** @param {GoTrueTokenSet} tokens @param {{ issuer: AuthIssuer, subject: AuthSubject }} claims @param {AuthSessionRecord} record */
  #install(tokens, claims, record) {
    this.#record = record;
    this.#session = {
      accessToken: tokens.accessToken,
      expiresAt: tokens.expiresAt,
      issuer: claims.issuer,
      subject: claims.subject,
    };
  }

  /** @param {string} accessToken */
  #validatedClaims(accessToken) {
    try {
      return jwtClaims(accessToken);
    } catch {
      throw makeError('request_failed', { cause: 'Supabase Auth returned invalid JWT claims' });
    }
  }

  #missingSessionError() {
    return this.#record?.state === 'expired'
      ? makeError('session_expired', { cause: 'Supabase Auth session expired' })
      : makeError('auth_required', { cause: 'SupabaseAuth: no session' });
  }

  /** @param {number} revision */
  #receiveRevision(revision) {
    if (this.#disposed || revision <= 0) return;
    void this.#store.runExclusive(this.#record, (transaction) => transaction.record())
      .then((record) => {
        if (this.#disposed || !record || this.#sameRecord(record, this.#record)) return;
        this.#record = record;
        this.#session = null;
        this.#notify();
      })
      .catch(() => {
        // A later operation rereads storage under the same lock; invalidation is best effort.
      });
  }

  /** @param {AuthSessionRecord} left @param {AuthSessionRecord|null} right */
  #sameRecord(left, right) {
    if (!right || left.revision !== right.revision || left.state !== right.state) return false;
    if (left.state !== 'active' || right.state !== 'active') return true;
    return left.refreshToken === right.refreshToken
      && left.issuer === right.issuer
      && left.subject === right.subject;
  }

  #notify() {
    for (const cb of this.#subs) {
      try {
        cb();
      } catch (error) {
        console.warn('[openom] auth onChange subscriber threw', error);
      }
    }
  }
}

/**
 * SessionController — the app-facing handle over a swappable `#auth` backend. It IS an AuthSession
 * (delegates the whole seam) so the rest of the app depends on one stable object and one "who's
 * logged in" truth, while the provider under it is chosen once at composition (the swap point).
 */
export class SessionController {
  /** @type {AuthProvider} */
  #auth;

  /** @param {AuthProvider} auth */
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
  onChange(cb) {
    return this.#auth.onChange(cb);
  }
  capabilities() {
    return this.#auth.capabilities();
  }

  /** @param {PasswordCredentials} credentials */
  signIn(credentials) {
    if (!this.#auth.capabilities().canLogin || typeof this.#auth.signIn !== 'function') {
      throw new Error('auth provider does not support interactive sign-in');
    }
    return this.#auth.signIn(credentials);
  }

  signOut() {
    if (typeof this.#auth.signOut !== 'function') {
      throw new Error('auth provider does not support interactive sign-out');
    }
    return this.#auth.signOut();
  }

  dispose() {
    return this.#auth.dispose?.();
  }
}
