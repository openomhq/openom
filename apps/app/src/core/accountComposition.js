import { AccountSession } from './accountSession.js';
import { SessionController } from './session.js';

/** Construct the single account facade and attach its provider-auth and transport dependencies. */
export async function composeAccountSession(core, { createAuth, createRemote = () => null }) {
  if (typeof createAuth !== 'function') throw new Error('account composition needs an auth factory');
  const account = new AccountSession(core);
  let auth = null;
  try {
    await account.initialize();
    auth = new SessionController(createAuth(account));
    const remote = createRemote(auth);
    account.attachSync({ auth, remote });
    return {
      account,
      auth,
      remote,
      dispose() {
        auth.dispose();
        account.dispose();
      },
    };
  } catch (error) {
    auth?.dispose();
    account.dispose();
    throw error;
  }
}
