import { AccountSession } from './accountSession.js';
import { SessionController } from './session.js';

/** @typedef {import('./types/appCoreApi.js').AppCoreFacade} AppCoreFacade */
/** @typedef {import('./types/session.js').AuthProvider} AuthProvider */
/** @typedef {import('./remoteStore.js').RemoteStore} RemoteStore */
/** @typedef {{ readonly createAuth: (account: AccountSession) => AuthProvider, readonly createRemote?: (auth: SessionController) => RemoteStore | null }} AccountCompositionOptions */

/** Construct the single account facade and attach its provider-auth and transport dependencies. */
/** @param {AppCoreFacade} core @param {AccountCompositionOptions} options */
export async function composeAccountSession(core, { createAuth, createRemote = () => null }) {
  if (typeof createAuth !== 'function') throw new Error('account composition needs an auth factory');
  const account = new AccountSession(core);
  /** @type {SessionController | null} */
  let auth = null;
  try {
    await account.initialize();
    auth = new SessionController(createAuth(account));
    const session = auth;
    const remote = createRemote(session);
    account.attachSync({ auth: session, remote });
    return {
      account,
      auth: session,
      remote,
      dispose() {
        session.dispose();
        account.dispose();
      },
    };
  } catch (error) {
    auth?.dispose();
    account.dispose();
    throw error;
  }
}
