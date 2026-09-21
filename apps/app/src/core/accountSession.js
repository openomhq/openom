// AccountSession is the application's sole source of cryptographic identity. Auth-provider subjects belong
// to SessionController and identify who authenticated a network request; this facade reports whose account
// keys are resident in the Rust/wasm host. Those values may coincide in dev but are never derived from one
// another. Server binding between them is deliberately Phase 2, not this local-custody session.

const STATES = new Set(['none', 'locked', 'unlocked']);

export class AccountSession {
  #core;
  #state = Object.freeze({ account: 'none' });
  #subs = new Set();

  constructor(core) {
    if (!core) throw new Error('AccountSession needs an app-core account backend');
    this.#core = core;
  }

  state() {
    return this.#state;
  }

  memberId() {
    return this.#state.memberId ?? null;
  }

  onChange(callback) {
    this.#subs.add(callback);
    return () => this.#subs.delete(callback);
  }

  async initialize() {
    const account = await this.#core.accountStatus();
    if (!STATES.has(account)) throw new Error(`unknown account state: ${account}`);
    if (account === 'unlocked') {
      this.#publish(account, await this.#core.accountPublicIdentity());
    } else {
      this.#publish(account);
    }
    return this.#state;
  }

  async createAccount(passphrase) {
    const opened = await this.#core.accountCreate(passphrase);
    const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
    this.#publish('unlocked', identity);
    return identity;
  }

  async unlock(passphrase) {
    const identity = await this.#core.accountUnlock(passphrase);
    this.#publish('unlocked', identity);
    return identity;
  }

  async recover(recoveryCode, newPassphrase) {
    const opened = await this.#core.accountRecover({ recoveryCode, newPassphrase });
    const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
    this.#publish('unlocked', identity);
    return identity;
  }

  async changePassphrase(current, next) {
    return this.#core.accountChangePassphrase({ current, next });
  }

  async rotateRoot(passphrase) {
    return this.#core.accountRotateRoot({ passphrase });
  }

  async registerProof(issuer, subject, timestamp) {
    return this.#core.accountRegisterProof({ issuer, subject, timestamp });
  }

  async publicIdentity() {
    const identity = await this.#core.accountPublicIdentity();
    this.#publish('unlocked', identity);
    return identity;
  }

  async lock() {
    await this.#core.accountLock();
    this.#publish(this.#state.account === 'none' ? 'none' : 'locked');
  }

  #publish(account, identity = null) {
    const next = Object.freeze(identity?.memberId
      ? { account, memberId: identity.memberId }
      : { account });
    if (next.account === this.#state.account && next.memberId === this.#state.memberId) return;
    this.#state = next;
    for (const callback of this.#subs) {
      try {
        callback(this.#state);
      } catch (error) {
        console.warn('[openom] account session subscriber threw', error);
      }
    }
  }
}
