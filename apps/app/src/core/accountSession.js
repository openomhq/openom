import { isAppError, makeError } from './errorModel.js';

/** @typedef {import('./types/appCoreApi.js').AppCoreFacade} AppCoreFacade */
/** @typedef {import('./types/appCoreApi.js').AccountSyncState} AccountSyncState */
/** @typedef {import('./types/appCoreApi.js').AccountSyncRecord} AccountSyncRecord */
/** @typedef {import('./types/appCoreApi.js').AccountCandidateCredential} AccountCandidateCredential */
/** @typedef {import('./types/contracts.js').AccountBackupCheckpoint} AccountBackupCheckpoint */
/** @typedef {import('./types/contracts.js').AccountBinding} AccountBinding */
/** @typedef {import('./types/contracts.js').AccountVersion} AccountVersion */
/** @typedef {import('./types/domain.js').AccountBlobHashBytes} AccountBlobHashBytes */
/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').Passphrase} Passphrase */
/** @typedef {import('./types/domain.js').RecoveryCode} RecoveryCode */
/** @typedef {import('./types/session.js').AuthRegistrationAttempt} AuthRegistrationAttempt */
/** @typedef {import('./types/session.js').AuthSession} AuthSession */
/** @typedef {import('./types/accountSession.js').AccountAuthState} AccountAuthState */
/** @typedef {import('./types/accountSession.js').AccountBindingClassification} AccountBindingClassification */
/** @typedef {import('./types/accountSession.js').AccountConflict} AccountConflict */
/** @typedef {import('./types/accountSession.js').AccountCustodyState} AccountCustodyState */
/** @typedef {import('./types/accountSession.js').AccountPendingAction} AccountPendingAction */
/** @typedef {import('./types/accountSession.js').AccountProbe} AccountProbe */
/** @typedef {import('./types/accountSession.js').AccountSessionOptions} AccountSessionOptions */
/** @typedef {import('./types/accountSession.js').AccountSessionState} AccountSessionState */
/** @typedef {import('./types/accountSession.js').InternalAccountSessionState} InternalAccountSessionState */
/** @typedef {import('./types/accountSession.js').KeptOfflineContext} KeptOfflineContext */
/** @typedef {import('./types/accountSession.js').RegisteredAccountProbe} RegisteredAccountProbe */
/** @typedef {import('./types/accountSession.js').RemoteAccountBackup} RemoteAccountBackup */
/** @typedef {import('./types/accountSession.js').UnregisteredAccountProbe} UnregisteredAccountProbe */
/** @typedef {import('./remoteStore.js').RemoteStore} RemoteStore */

const ACCOUNT_STATES = new Set(['none', 'locked', 'unlocked']);
const MAX_CLOCK_OFFSET_SECONDS = 24 * 60 * 60;
const MAX_BACKUP_SNAPSHOT_ATTEMPTS = 2;

/** @param {Uint8Array | null | undefined} left @param {Uint8Array | null | undefined} right */
function bytesEqual(left, right) {
  return left instanceof Uint8Array
    && right instanceof Uint8Array
    && left.length === right.length
    && left.every((byte, index) => byte === right[index]);
}

/** @param {AccountBinding | null} left @param {AccountBinding | null} right */
function bindingEqual(left, right) {
  return left !== null && right !== null
    && left.issuer === right.issuer
    && left.subject === right.subject
    && left.memberId === right.memberId;
}

/** @param {AccountVersion | null} left @param {AccountVersion | null} right */
function versionEqual(left, right) {
  return left !== null && right !== null
    && left.generation === right.generation
    && bytesEqual(left.blobHash, right.blobHash);
}

/** @param {Uint8Array} bytes @returns {Promise<AccountBlobHashBytes>} */
async function blobHash(bytes) {
  return /** @type {AccountBlobHashBytes} */ (
    new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(bytes)))
  );
}

/** @param {RemoteAccountBackup} remote @param {AccountBackupCheckpoint | null} checkpoint */
async function remoteMatchesCheckpoint(remote, checkpoint) {
  if (!checkpoint || remote.etag !== checkpoint.etag) return false;
  if (checkpoint.version === null) return remote.keystore === null;
  if (remote.keystore === null || remote.generation !== checkpoint.version.generation) return false;
  return bytesEqual(await blobHash(remote.keystore), checkpoint.version.blobHash);
}

/** Exhaustive default-deny classification before credential or backup-version verification. */
/** @param {{ record: AccountSyncRecord | null, attempt: AuthRegistrationAttempt, remote: RemoteAccountBackup | null }} input @returns {Readonly<AccountBindingClassification>} */
export function classifyAccountBindingState({ record, attempt, remote }) {
  const localMemberId = record?.identity.memberId ?? null;
  const localBinding = record?.binding ?? null;
  if (remote === null) {
    if (record === null) return Object.freeze({ action: 'none' });
    if (localBinding === null) return Object.freeze({ action: 'register' });
    const sameSubject = localBinding.issuer === attempt.issuer
      && localBinding.subject === attempt.subject;
    return Object.freeze({
      action: 'conflict',
      reason: sameSubject ? 'registration_preconditions_ambiguous' : 'local_auth_binding_mismatch',
    });
  }
  if (record === null) {
    return Object.freeze({
      action: 'conflict',
      reason: remote.keystore === null ? 'remote_identity_without_backup' : 'remote_restore_available',
    });
  }
  if (localBinding !== null
    && (localBinding.issuer !== attempt.issuer || localBinding.subject !== attempt.subject)) {
    return Object.freeze({ action: 'conflict', reason: 'local_auth_binding_mismatch' });
  }
  if (remote.memberId !== localMemberId) {
    return Object.freeze({
      action: 'conflict',
      reason: 'local_remote_identity_mismatch',
      restoreAvailable: remote.keystore !== null,
    });
  }
  return Object.freeze({ action: 'reconcile' });
}

/** @param {AccountConflict | null} conflict @returns {Readonly<AccountConflict> | null} */
function cloneConflict(conflict) {
  return conflict === null ? null : Object.freeze({ ...conflict });
}

/** @param {InternalAccountSessionState} state @returns {AccountSessionState} */
function publicState(state) {
  return Object.freeze({
    ...state,
    pending: new Set(state.pending),
    conflict: cloneConflict(state.conflict),
    retainedIdentities: Object.freeze(state.retainedIdentities.map((identity) => Object.freeze({ ...identity }))),
  });
}

/** @param {InternalAccountSessionState} left @param {InternalAccountSessionState} right */
function sameState(left, right) {
  return left.auth === right.auth
    && left.account === right.account
    && left.binding === right.binding
    && left.syncDisposition === right.syncDisposition
    && left.memberId === right.memberId
    && left.storagePersistence === right.storagePersistence
    && left.pending.join('|') === right.pending.join('|')
    && JSON.stringify(left.retainedIdentities) === JSON.stringify(right.retainedIdentities)
    && JSON.stringify(left.conflict) === JSON.stringify(right.conflict);
}

export class AccountSession {
  /** @type {AppCoreFacade} */
  #core;
  /** @type {AuthSession | null} */
  #auth = null;
  /** @type {RemoteStore | null} */
  #remote = null;
  /** @type {(() => void) | null} */
  #unsubscribeAuth = null;
  /** @type {AccountSessionOptions['wakeTarget']} */
  #wakeTarget;
  /** @type {AccountSessionOptions['visibilityTarget']} */
  #visibilityTarget;
  /** @type {AccountSessionOptions['locks']} */
  #backupLocks;
  /** @type {string} */
  #backupLockName;
  /** @type {() => void} */
  #onOnline;
  /** @type {() => void} */
  #onVisibility;
  /** @type {AccountCustodyState} */
  #account = 'none';
  /** @type {MemberId | null} */
  #memberId = null;
  /** @type {AccountSyncState} */
  #sync = { record: null, storagePersistence: 'unavailable' };
  /** @type {AccountAuthState} */
  #authState = 'signedOut';
  /** @type {AccountProbe | null} */
  #remoteProbe = null;
  /** @type {AccountConflict | null} */
  #conflict = null;
  /** @type {KeptOfflineContext | null} */
  #keptOfflineFor = null;
  /** @type {Set<AccountPendingAction>} */
  #volatilePending = new Set();
  /** @type {InternalAccountSessionState} */
  #state = Object.freeze({
    auth: 'signedOut',
    account: 'none',
    binding: 'unbound',
    syncDisposition: 'remote',
    pending: Object.freeze([]),
    conflict: null,
    retainedIdentities: Object.freeze([]),
    storagePersistence: 'unavailable',
  });
  /** @type {Set<(state: AccountSessionState) => void>} */
  #subs = new Set();
  /** @type {Promise<unknown>} */
  #tail = Promise.resolve();
  /** @type {Promise<unknown> | null} */
  #enableSyncPromise = null;
  /** @type {Promise<unknown> | null} */
  #retryPendingPromise = null;
  /** @type {number} */
  #clockOffsetSeconds = 0;

  /** @param {AppCoreFacade} core @param {AccountSessionOptions} [options] */
  constructor(core, {
    wakeTarget = globalThis,
    visibilityTarget = globalThis.document ?? null,
    locks = globalThis.navigator?.locks ?? null,
    profile = 'default',
  } = {}) {
    if (!core) throw new Error('AccountSession needs an app-core account backend');
    this.#core = core;
    this.#wakeTarget = wakeTarget;
    this.#visibilityTarget = visibilityTarget;
    this.#backupLocks = locks;
    this.#backupLockName = `openom.account.backup.${profile}`;
    this.#onOnline = () => this.#triggerPendingRetry({ discover: true });
    this.#onVisibility = () => {
      if (this.#visibilityTarget?.visibilityState !== 'hidden') {
        this.#triggerPendingRetry({ discover: true });
      }
    };
    this.#wakeTarget?.addEventListener?.('online', this.#onOnline);
    this.#visibilityTarget?.addEventListener?.('visibilitychange', this.#onVisibility);
  }

  /** @returns {AccountSessionState} */
  state() {
    return publicState(this.#state);
  }

  /** @returns {MemberId | null} */
  memberId() {
    return this.#memberId;
  }

  /** @param {(state: AccountSessionState) => void} callback */
  onChange(callback) {
    this.#subs.add(callback);
    return () => this.#subs.delete(callback);
  }

  async initialize() {
    const account = await this.#core.accountStatus();
    if (!ACCOUNT_STATES.has(account)) throw new Error(`unknown account state: ${account}`);
    this.#account = account;
    this.#memberId = account === 'unlocked'
      ? (await this.#core.accountPublicIdentity()).memberId
      : null;
    await this.#refreshLocalSync();
    this.#triggerPendingRetry();
    return this.state();
  }

  /** @param {{ auth: AuthSession, remote: RemoteStore | null }} dependencies */
  attachSync({ auth, remote }) {
    if (typeof auth?.registrationAttempt !== 'function'
      || typeof auth?.subject !== 'function'
      || typeof auth?.onChange !== 'function') {
      throw new Error('AccountSession needs an AuthSession registration seam');
    }
    if (remote !== null && (typeof remote?.me !== 'function' || typeof remote?.register !== 'function'
      || typeof remote?.putKeystore !== 'function')) {
      throw new Error('AccountSession needs an account RemoteStore');
    }
    this.#unsubscribeAuth?.();
    this.#auth = auth;
    this.#remote = remote;
    this.#authState = auth.subject() ? 'signedIn' : 'signedOut';
    this.#remoteProbe = null;
    this.#conflict = null;
    this.#keptOfflineFor = null;
    this.#unsubscribeAuth = auth.onChange(() => this.#onAuthChange());
    this.#publish();
    this.#triggerPendingRetry();
    return this.state();
  }

  /** @param {Passphrase} passphrase */
  async createAccount(passphrase) {
    const opened = await this.#core.accountCreate(passphrase);
    const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
    if (!identity.memberId) throw makeError('internal', { cause: 'created account omitted its member identity' });
    this.#setCustody('unlocked', identity.memberId);
    await this.#refreshLocalSync();
    this.#clearRemoteContext();
    return identity;
  }

  /** @param {Passphrase} passphrase */
  async unlock(passphrase) {
    const identity = await this.#core.accountUnlock(passphrase);
    this.#setCustody('unlocked', identity.memberId);
    await this.#refreshLocalSync();
    this.#clearRemoteContext();
    return identity;
  }

  /** @param {RecoveryCode} recoveryCode @param {Passphrase} newPassphrase */
  recover(recoveryCode, newPassphrase) {
    return this.#serialize(async () => {
      const opened = await this.#core.accountRecover({ recoveryCode, newPassphrase });
      const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
      if (!identity.memberId) throw makeError('internal', { cause: 'recovered account omitted its member identity' });
      this.#setCustody('unlocked', identity.memberId);
      return this.#completeCredentialMutation(identity);
    });
  }

  /** @param {Passphrase} current @param {Passphrase} next */
  changePassphrase(current, next) {
    return this.#serialize(async () => {
      const changed = await this.#core.accountChangePassphrase({ current, next });
      return this.#completeCredentialMutation(changed);
    });
  }

  /** @param {Passphrase} passphrase */
  revokeCredentials(passphrase) {
    return this.#serialize(async () => {
      const rotated = await this.#core.accountRotateRoot({ passphrase });
      return this.#completeCredentialMutation(rotated);
    });
  }

  /** @param {AuthIssuer} issuer @param {AuthSubject} subject @param {number} timestamp */
  async registerProof(issuer, subject, timestamp) {
    return this.#core.accountRegisterProof({ issuer, subject, timestamp });
  }

  async publicIdentity() {
    const identity = await this.#core.accountPublicIdentity();
    this.#setCustody('unlocked', identity.memberId);
    return identity;
  }

  async lock() {
    await this.#core.accountLock();
    this.#setCustody(this.#account === 'none' ? 'none' : 'locked', null);
  }

  probe() {
    return this.#serialize(() => this.#probeRemote());
  }

  register() {
    return this.#serialize(() => this.#register());
  }

  backup() {
    return this.#serialize(() => this.#backup());
  }

  retryPending() {
    if (this.#retryPendingPromise) return this.#retryPendingPromise;
    const operation = this.#serialize(() => this.#retryPending());
    this.#retryPendingPromise = operation;
    void operation.then(
      () => { if (this.#retryPendingPromise === operation) this.#retryPendingPromise = null; },
      () => { if (this.#retryPendingPromise === operation) this.#retryPendingPromise = null; },
    );
    return operation;
  }

  enableSync() {
    if (this.#enableSyncPromise) return this.#enableSyncPromise;
    const operation = this.#serialize(async () => {
      const probe = await this.#probeRemote();
      if (probe.status === 'unregistered') await this.#register(probe);
      else this.#assertProbeMatchesLocal(probe);
      return this.#backup();
    });
    this.#enableSyncPromise = operation;
    void operation.then(
      () => { if (this.#enableSyncPromise === operation) this.#enableSyncPromise = null; },
      () => { if (this.#enableSyncPromise === operation) this.#enableSyncPromise = null; },
    );
    return operation;
  }

  /** @param {AccountCandidateCredential} credential */
  restore(credential) {
    return this.#serialize(() => this.#restoreRemoteIdentity(credential, false));
  }

  /** @param {AccountCandidateCredential} credential */
  adoptRemoteIdentity(credential) {
    return this.#serialize(() => this.#restoreRemoteIdentity(credential, true));
  }

  keepLocalOffline() {
    return this.#serialize(async () => {
      const probe = await this.#probeRemote();
      if (!this.#sync.record || this.#conflict === null) {
        throw makeError('invalid_request', { cause: 'no local identity conflict to keep offline' });
      }
      this.#conflict = null;
      this.#keptOfflineFor = {
        issuer: probe.attempt.issuer,
        subject: probe.attempt.subject,
      };
      this.#remoteProbe = null;
      this.#publish();
      return this.state();
    });
  }

  dispose() {
    this.#unsubscribeAuth?.();
    this.#unsubscribeAuth = null;
    this.#wakeTarget?.removeEventListener?.('online', this.#onOnline);
    this.#visibilityTarget?.removeEventListener?.('visibilitychange', this.#onVisibility);
    this.#auth = null;
    this.#remote = null;
    this.#subs.clear();
  }

  /** @template Value @param {() => Promise<Value> | Value} operation @returns {Promise<Value>} */
  #serialize(operation) {
    const run = () => operation();
    const result = this.#tail.then(run, run);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  /** @template {object} Result @param {Result} result */
  async #completeCredentialMutation(result) {
    await this.#refreshLocalSync();
    this.#clearRemoteContext();
    if (this.#sync.record?.pendingBackup === null) return { ...result, pending: false };
    if (!this.#canRetryPending()) return { ...result, pending: true };
    try {
      await this.#backup({ pendingOnly: true });
      return { ...result, pending: this.#sync.record?.pendingBackup !== null };
    } catch (error) {
      await this.#refreshLocalSync();
      return {
        ...result,
        pending: this.#sync.record?.pendingBackup !== null,
        uploadError: isAppError(error) ? error.code : 'unavailable',
      };
    }
  }

  async #retryPending() {
    await this.#refreshLocalSync();
    if (this.#sync.record?.pendingBackup === null || !this.#canRetryPending()) return this.state();
    return this.#backup({ pendingOnly: true });
  }

  #canRetryPending() {
    return this.#account === 'unlocked'
      && this.#sync.record !== null
      && this.#remote !== null
      && this.#auth?.subject() !== null
      && this.#keptOfflineFor === null;
  }

  /** @param {{ readonly discover?: boolean }} [options] */
  #triggerPendingRetry({ discover = false } = {}) {
    if (this.#auth === null || this.#remote === null) return;
    if (!discover && this.#sync.record?.pendingBackup == null) return;
    void this.retryPending().catch(() => {
      // Durable intent remains visible in state; a later wake retries it.
    });
  }

  /** @param {UnregisteredAccountProbe | null} [initialProbe] */
  async #register(initialProbe = null) {
    this.#requireUnlockedLocalAccount();
    this.#volatilePending.add('register');
    this.#publish();
    let forceRefresh = false;
    let authRetried = false;
    let staleRetried = false;
    try {
      const { remote } = this.#requireNetwork();
      /** @type {AccountProbe | null} */
      let probe = initialProbe;
      for (;;) {
        probe ??= await this.#probeRemote({ forceRefresh });
        if (probe.status === 'registered') {
          this.#assertProbeMatchesLocal(probe);
          return this.state();
        }
        this.#assertRegistrationIsUnambiguous(probe);
        const timestamp = this.#registrationTimestamp();
        const identity = await this.#core.accountPublicIdentity();
        const signature = await this.registerProof(
          probe.attempt.issuer, probe.attempt.subject, timestamp,
        );
        try {
          const registered = await remote.register({
            memberId: identity.memberId,
            authorPublicKey: identity.authorPublicKey,
            signature,
            ts: timestamp,
          }, { accessToken: probe.attempt.accessToken });
          if (registered.memberId !== identity.memberId) {
            throw makeError('identity_conflict', { cause: 'register returned another member identity' });
          }
          const confirmed = await this.#probeRemoteWithAttempt(probe.attempt);
          this.#assertProbeMatchesLocal(confirmed);
          return this.state();
        } catch (error) {
          if (isAppError(error) && error.code === 'stale_timestamp' && !staleRetried
            && this.#adoptServerClock(error.args?.server_time)) {
            staleRetried = true;
            probe = null;
            continue;
          }
          if (isAppError(error) && error.code === 'auth_required' && !authRetried) {
            authRetried = true;
            forceRefresh = true;
            probe = null;
            continue;
          }
          if (isAppError(error) && error.code === 'identity_conflict') {
            this.#setConflict({ code: 'identity_conflict', reason: 'registration_refused' });
          }
          this.#markExpired(error);
          throw error;
        }
      }
    } finally {
      this.#volatilePending.delete('register');
      this.#publish();
    }
  }

  /** @param {{ readonly pendingOnly?: boolean }} [options] */
  #backup({ pendingOnly = false } = {}) {
    const operation = () => this.#backupUnderLock({ pendingOnly });
    if (typeof this.#backupLocks?.request !== 'function') return operation();
    return this.#backupLocks.request(this.#backupLockName, operation);
  }

  /** @param {{ readonly pendingOnly: boolean }} options */
  async #backupUnderLock({ pendingOnly }) {
    await this.#refreshLocalSync();
    const { record, memberId } = this.#requireUnlockedLocalAccount();
    const { remote } = this.#requireNetwork();
    if (pendingOnly && record.pendingBackup === null) return this.state();
    for (let snapshotAttempt = 0; snapshotAttempt < MAX_BACKUP_SNAPSHOT_ATTEMPTS; snapshotAttempt += 1) {
      const probe = await this.#probeRemote();
      this.#assertProbeMatchesLocal(probe);
      const binding = this.#bindingFor(probe.attempt, memberId);
      const staged = await this.#core.accountStageBackup({ kind: 'backup', binding });
      this.#acceptSync(staged);
      const expected = staged.record?.pendingBackup;
      if (!expected) return this.state();

      const snapshot = await this.#core.accountSnapshot();
      if (snapshot.generation !== expected.version.generation
        || !bytesEqual(snapshot.blobHash, expected.version.blobHash)) {
        await this.#refreshLocalSync();
        continue;
      }

      try {
        const accepted = await remote.putKeystore(snapshot.keystore, snapshot.generation, {
          etag: probe.remote.etag,
          accessToken: probe.attempt.accessToken,
        });
        this.#assertAttemptStillCurrent(probe.attempt);
        const acknowledged = await this.#core.accountAcknowledgeBackup({
          expected,
          checkpoint: { etag: accepted.etag, version: expected.version },
        });
        this.#acceptSync(acknowledged);
        if (!acknowledged.cleared) {
          this.#remoteProbe = null;
          this.#publish();
          return this.state();
        }
        this.#conflict = null;
        this.#remoteProbe = {
          ...probe,
          remote: {
            ...probe.remote,
            keystore: snapshot.keystore,
            generation: snapshot.generation,
            etag: accepted.etag,
          },
        };
        this.#publish();
        return this.state();
      } catch (error) {
        if (isAppError(error)
          && (error.code === 'account_backup_precondition_failed' || error.code === 'generation_rollback')) {
          await this.#surfaceBackupConflict(error, probe);
        }
        this.#markExpired(error);
        throw error;
      }
    }
    throw makeError('version_conflict', { cause: 'account snapshot changed while staging backup' });
  }

  /** @param {AccountCandidateCredential} credential @param {boolean} allowReplacement */
  async #restoreRemoteIdentity(credential, allowReplacement) {
    this.#volatilePending.add('restore');
    this.#publish();
    try {
      const probe = await this.#probeRemote({ forceRefresh: true });
      if (probe.status !== 'registered') throw makeError('unregistered', { httpStatus: 403 });
      if (probe.remote.keystore === null) {
        throw makeError('invalid_request', { cause: 'the bound remote identity has no account backup' });
      }
      const durable = this.#sync.record;
      const recoveryResume = 'recoveryCode' in credential && typeof credential.recoveryCode === 'string'
        && durable?.identity.memberId === probe.remote.memberId
        && durable.pendingBackup?.kind === 'revoke'
        && bindingEqual(durable.pendingBackup.binding, this.#bindingFor(probe.attempt, probe.remote.memberId))
        && await remoteMatchesCheckpoint(probe.remote, durable.acknowledgedBackup);
      if (recoveryResume) {
        try {
          await this.#backup({ pendingOnly: true });
          return {
            memberId: probe.remote.memberId,
            pending: this.#sync.record?.pendingBackup !== null,
            resumed: true,
          };
        } catch (error) {
          return {
            memberId: probe.remote.memberId,
            pending: true,
            resumed: true,
            uploadError: isAppError(error) ? error.code : 'unavailable',
          };
        }
      }
      const localMemberId = this.#localMemberId();
      const differs = localMemberId !== null && localMemberId !== probe.remote.memberId;
      if (differs !== allowReplacement) {
        throw makeError('identity_conflict', {
          cause: differs
            ? 'explicit adoptRemoteIdentity is required to preserve local custody'
            : 'adoptRemoteIdentity requires a differing local identity',
        });
      }
      this.#assertAttemptStillCurrent(probe.attempt);
      const remoteHash = await blobHash(probe.remote.keystore);
      const binding = this.#bindingFor(probe.attempt, probe.remote.memberId);
      const adopted = await this.#core.accountAdoptCandidate({
        expectedMemberId: probe.remote.memberId,
        keystore: probe.remote.keystore,
        credential,
        binding,
        checkpoint: {
          etag: probe.remote.etag,
          version: { generation: probe.remote.generation, blobHash: remoteHash },
        },
      });
      if (!adopted.memberId) throw makeError('internal', { cause: 'adopted account omitted its member identity' });
      this.#setCustody('unlocked', adopted.memberId);
      await this.#refreshLocalSync();
      this.#remoteProbe = probe;
      this.#conflict = null;
      this.#publish();
      if (!adopted.recoveryCode) return { memberId: adopted.memberId };
      try {
        await this.#backup({ pendingOnly: true });
        return {
          memberId: adopted.memberId,
          recoveryCode: adopted.recoveryCode,
          pending: this.#sync.record?.pendingBackup !== null,
        };
      } catch (error) {
        await this.#refreshLocalSync();
        return {
          memberId: adopted.memberId,
          recoveryCode: adopted.recoveryCode,
          pending: true,
          uploadError: isAppError(error) ? error.code : 'unavailable',
        };
      }
    } finally {
      this.#volatilePending.delete('restore');
      this.#publish();
    }
  }

  /** @param {import('./errorModel.js').AppError} error @param {RegisteredAccountProbe} probe */
  async #surfaceBackupConflict(error, probe) {
    const { remote: remoteStore } = this.#requireNetwork();
    /** @type {Awaited<ReturnType<RemoteStore['getKeystore']>> | null} */
    let remote = null;
    try {
      remote = await remoteStore.getKeystore({ accessToken: probe.attempt.accessToken });
    } catch {
      remote = null;
    }
    const local = this.#sync.record?.identity;
    const rollback = remote !== null && remote.keystore !== null && local !== undefined
      && remote.generation < local.effectiveFloor;
    this.#setConflict({
      code: rollback ? 'account_backup_rollback' : error.code,
      reason: 'backup_reconciliation_required',
      localGeneration: local?.version.generation ?? null,
      remoteGeneration: remote?.generation ?? null,
      remoteEtag: remote?.etag ?? null,
    });
  }

  /** @param {{ readonly forceRefresh?: boolean }} [options] @returns {Promise<AccountProbe>} */
  async #probeRemote({ forceRefresh = false } = {}) {
    const { auth } = this.#requireNetwork();
    let refresh = forceRefresh;
    for (;;) {
      try {
        const attempt = await auth.registrationAttempt({ forceRefresh: refresh });
        return await this.#probeRemoteWithAttempt(attempt);
      } catch (error) {
        if (!refresh && isAppError(error) && error.code === 'auth_required') {
          refresh = true;
          continue;
        }
        this.#markExpired(error);
        throw error;
      }
    }
  }

  /** @param {AuthRegistrationAttempt} attempt @returns {Promise<AccountProbe>} */
  async #probeRemoteWithAttempt(attempt) {
    const { remote: remoteStore } = this.#requireNetwork();
    this.#validateAttempt(attempt);
    this.#assertAttemptStillCurrent(attempt);
    this.#authState = 'signedIn';
    try {
      const remote = await remoteStore.me({ accessToken: attempt.accessToken });
      this.#assertAttemptStillCurrent(attempt);
      /** @type {RegisteredAccountProbe} */
      const probe = { status: 'registered', attempt, remote };
      await this.#acceptRegisteredProbe(probe);
      return probe;
    } catch (error) {
      if (isAppError(error) && error.code === 'unregistered') {
        this.#assertAttemptStillCurrent(attempt);
        /** @type {UnregisteredAccountProbe} */
        const probe = { status: 'unregistered', attempt, remote: null };
        this.#acceptUnregisteredProbe(probe);
        return probe;
      }
      throw error;
    }
  }

  /** @param {RegisteredAccountProbe} probe */
  async #acceptRegisteredProbe(probe) {
    const localMemberId = this.#localMemberId();
    const localBinding = this.#sync.record?.binding ?? null;
    const classification = classifyAccountBindingState({
      record: this.#sync.record,
      attempt: probe.attempt,
      remote: probe.remote,
    });
    /** @type {AccountConflict | null} */
    let conflict = classification.action === 'conflict' ? {
      code: 'identity_conflict',
      reason: classification.reason,
      ...(localMemberId === null ? {} : { localMemberId }),
      ...(probe.remote.memberId ? { remoteMemberId: probe.remote.memberId } : {}),
      ...(classification.restoreAvailable === undefined
        ? {}
        : { restoreAvailable: classification.restoreAvailable }),
    } : null;
    if (classification.action === 'conflict') {
      // Default-deny classification completes before any remote generation/hash is considered.
    } else {
      const record = this.#sync.record;
      if (record === null || localMemberId === null) {
        throw makeError('internal', { cause: 'reconciliation requires a local account record' });
      }
      if (probe.remote.keystore !== null) {
        const local = record.identity;
        const remoteHash = await blobHash(probe.remote.keystore);
        const pendingFromCheckpoint = record.pendingBackup !== null
          && versionEqual(record.pendingBackup.version, local.version)
          && await remoteMatchesCheckpoint(probe.remote, record.acknowledgedBackup);
        if (!pendingFromCheckpoint && probe.remote.generation < local.effectiveFloor) {
          conflict = {
            code: 'account_backup_rollback', reason: 'remote_generation_below_local_floor',
            localGeneration: local.effectiveFloor,
            remoteGeneration: probe.remote.generation,
          };
        } else if (!pendingFromCheckpoint && (probe.remote.generation !== local.version.generation
          || !bytesEqual(remoteHash, local.version.blobHash))) {
          conflict = {
            code: 'account_backup_precondition_failed', reason: 'remote_backup_requires_verification',
            localGeneration: local.version.generation,
            remoteGeneration: probe.remote.generation,
            remoteEtag: probe.remote.etag,
          };
        }
        if (conflict === null) await this.#confirmProbeBinding(probe, localBinding, localMemberId);
      } else {
        await this.#confirmProbeBinding(probe, localBinding, localMemberId);
      }
    }
    this.#remoteProbe = probe;
    this.#conflict = conflict;
    this.#publish();
  }

  /** @param {RegisteredAccountProbe} probe @param {AccountBinding | null} localBinding @param {MemberId} localMemberId */
  async #confirmProbeBinding(probe, localBinding, localMemberId) {
    const binding = this.#bindingFor(probe.attempt, localMemberId);
    if (!bindingEqual(localBinding, binding)) {
      this.#acceptSync(await this.#core.accountConfirmBinding(binding));
    }
  }

  /** @param {UnregisteredAccountProbe} probe */
  #acceptUnregisteredProbe(probe) {
    const classification = classifyAccountBindingState({
      record: this.#sync.record,
      attempt: probe.attempt,
      remote: null,
    });
    this.#remoteProbe = probe;
    this.#conflict = classification.action !== 'conflict' ? null : {
      code: 'identity_conflict',
      reason: classification.reason,
      localMemberId: this.#localMemberId(),
    };
    this.#publish();
  }

  /** @param {AccountProbe} probe @returns {asserts probe is RegisteredAccountProbe} */
  #assertProbeMatchesLocal(probe) {
    if (probe.status !== 'registered') throw makeError('unregistered', { httpStatus: 403 });
    if (this.#conflict !== null || probe.remote.memberId !== this.#localMemberId()) {
      throw makeError(this.#conflict?.code ?? 'identity_conflict', { cause: this.#conflict?.reason });
    }
  }

  /** @param {AccountProbe} probe @returns {asserts probe is UnregisteredAccountProbe} */
  #assertRegistrationIsUnambiguous(probe) {
    if (probe.status !== 'unregistered') throw makeError('identity_conflict');
    const record = this.#sync.record;
    if (!record || this.#account !== 'unlocked' || this.#conflict !== null
      || record.acknowledgedBackup !== null || record.binding !== null) {
      if (this.#conflict === null) {
        this.#setConflict({
          code: 'identity_conflict',
          reason: 'registration_preconditions_ambiguous',
          localMemberId: this.#localMemberId(),
        });
      }
      throw makeError('identity_conflict', { cause: 'registration preconditions are ambiguous' });
    }
  }

  /** @param {AuthRegistrationAttempt} attempt @param {MemberId} memberId @returns {AccountBinding} */
  #bindingFor(attempt, memberId) {
    return { issuer: attempt.issuer, subject: attempt.subject, memberId };
  }

  /** @param {AuthRegistrationAttempt} attempt */
  #validateAttempt(attempt) {
    if (typeof attempt?.accessToken !== 'string' || attempt.accessToken.length === 0
      || typeof attempt?.issuer !== 'string'
      || typeof attempt?.subject !== 'string' || attempt.subject.length === 0) {
      throw makeError('auth_required', { cause: 'auth provider returned an invalid registration attempt' });
    }
  }

  /** @param {AuthRegistrationAttempt} attempt */
  #assertAttemptStillCurrent(attempt) {
    const currentSubject = this.#auth?.subject() ?? null;
    if (currentSubject === null) throw makeError('auth_required', { cause: 'auth session changed during account sync' });
    if (currentSubject !== attempt.subject) {
      this.#setConflict({
        code: 'identity_conflict',
        reason: 'auth_identity_changed_during_operation',
        localMemberId: this.#localMemberId(),
      });
      throw makeError('identity_conflict', { cause: 'auth identity changed during account sync' });
    }
  }

  /** @returns {{ auth: AuthSession, remote: RemoteStore }} */
  #requireNetwork() {
    if (!this.#auth || !this.#auth.subject()) throw makeError('auth_required');
    if (!this.#remote) throw makeError('unavailable', { cause: 'account sync backend is not configured' });
    return { auth: this.#auth, remote: this.#remote };
  }

  /** @returns {{ record: AccountSyncRecord, memberId: MemberId }} */
  #requireUnlockedLocalAccount() {
    if (this.#account !== 'unlocked' || !this.#memberId || !this.#sync.record) {
      throw makeError('invalid_request', { cause: 'account sync requires an unlocked local account' });
    }
    return { record: this.#sync.record, memberId: this.#memberId };
  }

  /** @returns {MemberId | null} */
  #localMemberId() {
    return this.#sync.record?.identity.memberId ?? null;
  }

  #registrationTimestamp() {
    return Math.floor(Date.now() / 1000) + this.#clockOffsetSeconds;
  }

  /** @param {unknown} serverTime */
  #adoptServerClock(serverTime) {
    if (typeof serverTime !== 'number' || !Number.isSafeInteger(serverTime) || serverTime < 0) return false;
    const offset = serverTime - Math.floor(Date.now() / 1000);
    if (Math.abs(offset) > MAX_CLOCK_OFFSET_SECONDS) return false;
    this.#clockOffsetSeconds = offset;
    return true;
  }

  #onAuthChange() {
    this.#authState = this.#auth?.subject() ? 'signedIn' : 'signedOut';
    this.#remoteProbe = null;
    this.#conflict = null;
    this.#keptOfflineFor = null;
    this.#publish();
    this.#triggerPendingRetry();
  }

  /** @param {unknown} error */
  #markExpired(error) {
    if (isAppError(error) && (error.code === 'auth_required' || error.code === 'session_expired')) {
      this.#authState = 'expired';
      this.#remoteProbe = null;
      this.#publish();
    }
  }

  #clearRemoteContext() {
    this.#remoteProbe = null;
    this.#conflict = null;
    this.#keptOfflineFor = null;
    this.#publish();
  }

  /** @param {AccountConflict} conflict */
  #setConflict(conflict) {
    this.#conflict = conflict;
    this.#publish();
  }

  /** @param {AccountCustodyState} account @param {MemberId | null} memberId */
  #setCustody(account, memberId) {
    this.#account = account;
    this.#memberId = memberId;
    this.#publish();
  }

  async #refreshLocalSync() {
    this.#acceptSync(await this.#core.accountSyncState());
  }

  /** @param {AccountSyncState} sync */
  #acceptSync(sync) {
    this.#sync = {
      record: sync?.record ?? null,
      storagePersistence: sync?.storagePersistence ?? 'unavailable',
    };
    this.#publish();
  }

  /** @returns {import('./types/accountSession.js').AccountBindingState} */
  #bindingState() {
    if (this.#conflict === null && this.#remoteProbe?.status === 'registered') {
      return this.#remoteProbe.remote.keystore === null ? 'bound' : 'backedUp';
    }
    const record = this.#sync.record;
    if (!record?.binding) return 'unbound';
    return record.acknowledgedBackup?.version
      && versionEqual(record.acknowledgedBackup.version, record.identity.version)
      ? 'backedUp'
      : 'bound';
  }

  /** @returns {AccountPendingAction[]} */
  #pending() {
    const pending = new Set(this.#volatilePending);
    const durable = this.#sync.record?.pendingBackup?.kind;
    if (durable) pending.add(durable);
    return [...pending].sort();
  }

  #publish() {
    /** @type {InternalAccountSessionState} */
    const next = {
      auth: this.#authState,
      account: this.#account,
      binding: this.#bindingState(),
      syncDisposition: this.#keptOfflineFor === null ? 'remote' : 'localOnly',
      pending: Object.freeze(this.#pending()),
      conflict: this.#conflict,
      retainedIdentities: Object.freeze((this.#sync.record?.retainedIdentities ?? []).map((identity) => ({
        memberId: identity.memberId,
        generation: identity.version.generation,
        floor: identity.effectiveFloor,
      }))),
      storagePersistence: this.#sync.storagePersistence,
      ...(this.#memberId ? { memberId: this.#memberId } : {}),
    };
    if (sameState(next, this.#state)) return;
    this.#state = Object.freeze(next);
    for (const callback of this.#subs) {
      try {
        callback(this.state());
      } catch (error) {
        console.warn('[openom] account session subscriber threw', error);
      }
    }
  }
}
