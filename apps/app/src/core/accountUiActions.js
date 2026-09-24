/**
 * Account UI action state. This coordinates user-triggered auth/account verbs but renders no DOM and owns
 * no auth or identity state. Views consume `state()` and call these methods through `main.js`.
 */

/** @typedef {import('./types/accountUi.js').AccountUiActionsOptions} AccountUiActionsOptions */
/** @typedef {import('./types/accountUi.js').AccountUiOperation} AccountUiOperation */
/** @typedef {import('./types/accountUi.js').AccountUiScreen} AccountUiScreen */
/** @typedef {import('./types/accountUi.js').AccountUiState} AccountUiState */
/** @typedef {import('./types/session.js').PasswordCredentials} PasswordCredentials */

const SCREENS = new Set(['overview', 'signIn', 'signUp', 'confirmationRequired', 'restore', 'conflict']);

/** @param {AccountUiState} state @returns {Readonly<AccountUiState>} */
function publicState(state) {
  return Object.freeze({ ...state });
}

export class AccountUiActions {
  /** @type {AccountUiActionsOptions['account']} */
  #account;
  /** @type {AccountUiActionsOptions['auth']} */
  #auth;
  /** @type {NonNullable<AccountUiActionsOptions['onChange']>} */
  #onChange;
  /** @type {AccountUiActionsOptions['errorText']} */
  #errorText;
  /** @type {AccountUiActionsOptions['logError']} */
  #logError;
  /** @type {AccountUiState} */
  #state = Object.freeze({ screen: null, busy: null, error: '', notice: null, discovery: 'unknown' });

  /** @param {AccountUiActionsOptions} options */
  constructor({ account, auth, onChange = () => {}, errorText, logError }) {
    if (!account || typeof account.probe !== 'function' || typeof account.enableSync !== 'function') {
      throw new TypeError('AccountUiActions needs an account facade');
    }
    if (!auth || typeof auth.signUp !== 'function' || typeof auth.signIn !== 'function'
      || typeof auth.signOut !== 'function') {
      throw new TypeError('AccountUiActions needs an interactive auth controller');
    }
    if (typeof onChange !== 'function' || typeof errorText !== 'function' || typeof logError !== 'function') {
      throw new TypeError('AccountUiActions needs UI error adapters');
    }
    this.#account = account;
    this.#auth = auth;
    this.#onChange = onChange;
    this.#errorText = errorText;
    this.#logError = logError;
  }

  /** @returns {Readonly<AccountUiState>} */
  state() {
    return publicState(this.#state);
  }

  /** @param {AccountUiScreen} [screen] */
  show(screen = 'overview') {
    if (!SCREENS.has(screen)) throw new TypeError(`unknown account UI screen: ${screen}`);
    this.#update({ screen, error: '', notice: screen === 'confirmationRequired' ? this.#state.notice : null });
  }

  close() {
    this.#update({ screen: null, error: '', notice: null });
  }

  /** @param {PasswordCredentials} credentials */
  signUp(credentials) {
    return this.#run('signUp', async () => {
      const result = await this.#auth.signUp(credentials);
      if (result.status === 'confirmationRequired') {
        this.#update({
          screen: 'confirmationRequired',
          notice: 'confirmationRequired',
          discovery: 'unknown',
        });
        return result;
      }
      await this.#probeAfterAuthentication();
      return result;
    });
  }

  /** @param {PasswordCredentials} credentials */
  signIn(credentials) {
    return this.#run('signIn', async () => {
      await this.#auth.signIn(credentials);
      return this.#probeAfterAuthentication();
    });
  }

  signOut() {
    return this.#run('signOut', async () => {
      await this.#auth.signOut();
      this.#update({ screen: 'overview', notice: null, discovery: 'unknown' });
    });
  }

  enableSync() {
    return this.#run('enableSync', async () => {
      const result = await this.#account.enableSync();
      this.#update({
        screen: result.conflict === null ? 'overview' : 'conflict',
        notice: null,
      });
      return result;
    });
  }

  async #probeAfterAuthentication() {
    const probe = await this.#account.probe();
    const account = this.#account.state();
    let screen = 'overview';
    if (account.conflict?.reason === 'remote_restore_available') screen = 'restore';
    else if (account.conflict !== null) screen = 'conflict';
    this.#update({ screen, notice: null, discovery: probe.status });
    return probe.status;
  }

  /** @template Result @param {AccountUiOperation} operation @param {() => Promise<Result>} action */
  async #run(operation, action) {
    if (this.#state.busy !== null) return null;
    this.#update({ busy: operation, error: '' });
    try {
      return await action();
    } catch (error) {
      const normalized = this.#logError(operation, error);
      this.#update({ error: this.#errorText(normalized) });
      return null;
    } finally {
      this.#update({ busy: null });
    }
  }

  /** @param {Partial<AccountUiState>} change */
  #update(change) {
    this.#state = Object.freeze({ ...this.#state, ...change });
    this.#onChange(this.state());
  }
}
