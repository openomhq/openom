import { isAppError, makeError } from './errorModel.js';

const ACCOUNT_STATES = new Set(['none', 'locked', 'unlocked']);
const MAX_CLOCK_OFFSET_SECONDS = 24 * 60 * 60;
const MAX_BACKUP_SNAPSHOT_ATTEMPTS = 2;

function bytesEqual(left, right) {
  return left instanceof Uint8Array
    && right instanceof Uint8Array
    && left.length === right.length
    && left.every((byte, index) => byte === right[index]);
}

function bindingEqual(left, right) {
  return left !== null && right !== null
    && left.issuer === right.issuer
    && left.subject === right.subject
    && left.memberId === right.memberId;
}

function versionEqual(left, right) {
  return left !== null && right !== null
    && left.generation === right.generation
    && bytesEqual(left.blobHash, right.blobHash);
}

async function blobHash(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function remoteMatchesCheckpoint(remote, checkpoint) {
  if (!checkpoint || remote.etag !== checkpoint.etag) return false;
  if (checkpoint.version === null) return remote.keystore === null;
  if (remote.keystore === null || remote.generation !== checkpoint.version.generation) return false;
  return bytesEqual(await blobHash(remote.keystore), checkpoint.version.blobHash);
}

/** Exhaustive default-deny classification before credential or backup-version verification. */
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

function cloneConflict(conflict) {
  return conflict === null ? null : Object.freeze({ ...conflict });
}

function publicState(state) {
  return Object.freeze({
    ...state,
    pending: new Set(state.pending),
    conflict: cloneConflict(state.conflict),
    retainedIdentities: Object.freeze(state.retainedIdentities.map((identity) => Object.freeze({ ...identity }))),
  });
}

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
  #core;
  #auth = null;
  #remote = null;
  #unsubscribeAuth = null;
  #wakeTarget;
  #visibilityTarget;
  #backupLocks;
  #backupLockName;
  #onOnline;
  #onVisibility;
  #account = 'none';
  #memberId = null;
  #sync = { record: null, storagePersistence: 'unavailable' };
  #authState = 'signedOut';
  #remoteProbe = null;
  #conflict = null;
  #keptOfflineFor = null;
  #volatilePending = new Set();
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
  #subs = new Set();
  #tail = Promise.resolve();
  #enableSyncPromise = null;
  #retryPendingPromise = null;
  #clockOffsetSeconds = 0;

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

  state() {
    return publicState(this.#state);
  }

  memberId() {
    return this.#memberId;
  }

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

  async createAccount(passphrase) {
    const opened = await this.#core.accountCreate(passphrase);
    const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
    this.#setCustody('unlocked', identity.memberId);
    await this.#refreshLocalSync();
    this.#clearRemoteContext();
    return identity;
  }

  async unlock(passphrase) {
    const identity = await this.#core.accountUnlock(passphrase);
    this.#setCustody('unlocked', identity.memberId);
    await this.#refreshLocalSync();
    this.#clearRemoteContext();
    return identity;
  }

  recover(recoveryCode, newPassphrase) {
    return this.#serialize(async () => {
      const opened = await this.#core.accountRecover({ recoveryCode, newPassphrase });
      const identity = opened.memberId ? opened : { ...opened, ...(await this.#core.accountPublicIdentity()) };
      this.#setCustody('unlocked', identity.memberId);
      return this.#completeCredentialMutation(identity);
    });
  }

  changePassphrase(current, next) {
    return this.#serialize(async () => {
      const changed = await this.#core.accountChangePassphrase({ current, next });
      return this.#completeCredentialMutation(changed);
    });
  }

  revokeCredentials(passphrase) {
    return this.#serialize(async () => {
      const rotated = await this.#core.accountRotateRoot({ passphrase });
      return this.#completeCredentialMutation(rotated);
    });
  }

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

  restore(credential) {
    return this.#serialize(() => this.#restoreRemoteIdentity(credential, false));
  }

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

  #serialize(operation) {
    const run = () => operation();
    const result = this.#tail.then(run, run);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

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

  #triggerPendingRetry({ discover = false } = {}) {
    if (this.#auth === null || this.#remote === null) return;
    if (!discover && this.#sync.record?.pendingBackup == null) return;
    void this.retryPending().catch(() => {
      // Durable intent remains visible in state; a later wake retries it.
    });
  }

  async #register(initialProbe = null) {
    this.#requireUnlockedLocalAccount();
    this.#volatilePending.add('register');
    this.#publish();
    let forceRefresh = false;
    let authRetried = false;
    let staleRetried = false;
    try {
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
          const registered = await this.#remote.register({
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

  #backup({ pendingOnly = false } = {}) {
    const operation = () => this.#backupUnderLock({ pendingOnly });
    if (typeof this.#backupLocks?.request !== 'function') return operation();
    return this.#backupLocks.request(this.#backupLockName, operation);
  }

  async #backupUnderLock({ pendingOnly }) {
    await this.#refreshLocalSync();
    this.#requireUnlockedLocalAccount();
    if (pendingOnly && this.#sync.record.pendingBackup === null) return this.state();
    for (let snapshotAttempt = 0; snapshotAttempt < MAX_BACKUP_SNAPSHOT_ATTEMPTS; snapshotAttempt += 1) {
      const probe = await this.#probeRemote();
      this.#assertProbeMatchesLocal(probe);
      const binding = this.#bindingFor(probe.attempt, this.#localMemberId());
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
        const accepted = await this.#remote.putKeystore(snapshot.keystore, snapshot.generation, {
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
      const recoveryResume = typeof credential?.recoveryCode === 'string'
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

  async #surfaceBackupConflict(error, probe) {
    let remote = null;
    try {
      remote = await this.#remote.getKeystore({ accessToken: probe.attempt.accessToken });
    } catch {
      remote = null;
    }
    const local = this.#sync.record?.identity;
    const rollback = remote?.keystore !== null && local && remote.generation < local.effectiveFloor;
    this.#setConflict({
      code: rollback ? 'account_backup_rollback' : error.code,
      reason: 'backup_reconciliation_required',
      localGeneration: local?.version.generation ?? null,
      remoteGeneration: remote?.generation ?? null,
      remoteEtag: remote?.etag ?? null,
    });
  }

  async #probeRemote({ forceRefresh = false } = {}) {
    this.#requireNetwork();
    let refresh = forceRefresh;
    for (;;) {
      try {
        const attempt = await this.#auth.registrationAttempt({ forceRefresh: refresh });
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

  async #probeRemoteWithAttempt(attempt) {
    this.#validateAttempt(attempt);
    this.#assertAttemptStillCurrent(attempt);
    this.#authState = 'signedIn';
    try {
      const remote = await this.#remote.me({ accessToken: attempt.accessToken });
      this.#assertAttemptStillCurrent(attempt);
      const probe = { status: 'registered', attempt, remote };
      await this.#acceptRegisteredProbe(probe);
      return probe;
    } catch (error) {
      if (isAppError(error) && error.code === 'unregistered') {
        this.#assertAttemptStillCurrent(attempt);
        const probe = { status: 'unregistered', attempt, remote: null };
        this.#acceptUnregisteredProbe(probe);
        return probe;
      }
      throw error;
    }
  }

  async #acceptRegisteredProbe(probe) {
    const localMemberId = this.#localMemberId();
    const localBinding = this.#sync.record?.binding ?? null;
    const classification = classifyAccountBindingState({
      record: this.#sync.record,
      attempt: probe.attempt,
      remote: probe.remote,
    });
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
    } else if (probe.remote.keystore !== null) {
      const local = this.#sync.record.identity;
      const remoteHash = await blobHash(probe.remote.keystore);
      const pendingFromCheckpoint = this.#sync.record.pendingBackup !== null
        && versionEqual(this.#sync.record.pendingBackup.version, local.version)
        && await remoteMatchesCheckpoint(probe.remote, this.#sync.record.acknowledgedBackup);
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
    this.#remoteProbe = probe;
    this.#conflict = conflict;
    this.#publish();
  }

  async #confirmProbeBinding(probe, localBinding, localMemberId) {
    const binding = this.#bindingFor(probe.attempt, localMemberId);
    if (!bindingEqual(localBinding, binding)) {
      this.#acceptSync(await this.#core.accountConfirmBinding(binding));
    }
  }

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

  #assertProbeMatchesLocal(probe) {
    if (probe.status !== 'registered') throw makeError('unregistered', { httpStatus: 403 });
    if (this.#conflict !== null || probe.remote.memberId !== this.#localMemberId()) {
      throw makeError(this.#conflict?.code ?? 'identity_conflict', { cause: this.#conflict?.reason });
    }
  }

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

  #bindingFor(attempt, memberId) {
    return { issuer: attempt.issuer, subject: attempt.subject, memberId };
  }

  #validateAttempt(attempt) {
    if (typeof attempt?.accessToken !== 'string' || attempt.accessToken.length === 0
      || typeof attempt?.issuer !== 'string'
      || typeof attempt?.subject !== 'string' || attempt.subject.length === 0) {
      throw makeError('auth_required', { cause: 'auth provider returned an invalid registration attempt' });
    }
  }

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

  #requireNetwork() {
    if (!this.#auth || !this.#auth.subject()) throw makeError('auth_required');
    if (!this.#remote) throw makeError('unavailable', { cause: 'account sync backend is not configured' });
  }

  #requireUnlockedLocalAccount() {
    if (this.#account !== 'unlocked' || !this.#memberId || !this.#sync.record) {
      throw makeError('invalid_request', { cause: 'account sync requires an unlocked local account' });
    }
  }

  #localMemberId() {
    return this.#sync.record?.identity.memberId ?? null;
  }

  #registrationTimestamp() {
    return Math.floor(Date.now() / 1000) + this.#clockOffsetSeconds;
  }

  #adoptServerClock(serverTime) {
    if (!Number.isSafeInteger(serverTime) || serverTime < 0) return false;
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

  #setConflict(conflict) {
    this.#conflict = conflict;
    this.#publish();
  }

  #setCustody(account, memberId) {
    this.#account = account;
    this.#memberId = memberId;
    this.#publish();
  }

  async #refreshLocalSync() {
    this.#acceptSync(await this.#core.accountSyncState());
  }

  #acceptSync(sync) {
    this.#sync = {
      record: sync?.record ?? null,
      storagePersistence: sync?.storagePersistence ?? 'unavailable',
    };
    this.#publish();
  }

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

  #pending() {
    const pending = new Set(this.#volatilePending);
    const durable = this.#sync.record?.pendingBackup?.kind;
    if (durable) pending.add(durable);
    return [...pending].sort();
  }

  #publish() {
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
