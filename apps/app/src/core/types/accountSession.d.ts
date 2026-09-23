import type {
  AccountGeneration,
  AccountKeystoreBytes,
  AccountBackupEtag,
  AuthIssuer,
  AuthSubject,
  MemberId,
} from './domain.js';
import type {
  AccountBackupCheckpoint,
  AccountBinding,
  AccountVersion,
} from './contracts.js';
import type {
  AccountCandidateCredential,
  AccountSyncState,
} from './appCoreApi.js';
import type { AuthRegistrationAttempt } from './session.js';

export type AccountCustodyState = 'none' | 'locked' | 'unlocked';
export type AccountAuthState = 'signedOut' | 'signedIn' | 'expired';
export type AccountBindingState = 'unbound' | 'bound' | 'backedUp';
export type AccountSyncDisposition = 'remote' | 'localOnly';
export type AccountPendingAction = 'register' | 'restore' | 'backup' | 'revoke';
export type StoragePersistence = 'granted' | 'denied' | 'unavailable';

export interface RemoteAccountBackup {
  readonly memberId: MemberId;
  readonly keystore: AccountKeystoreBytes | null;
  readonly generation: AccountGeneration;
  readonly etag: AccountBackupEtag;
}

export interface RegisteredAccountProbe {
  readonly status: 'registered';
  readonly attempt: AuthRegistrationAttempt;
  readonly remote: RemoteAccountBackup;
}

export interface UnregisteredAccountProbe {
  readonly status: 'unregistered';
  readonly attempt: AuthRegistrationAttempt;
  readonly remote: null;
}

export type AccountProbe = RegisteredAccountProbe | UnregisteredAccountProbe;

export interface AccountConflict {
  readonly code: string;
  readonly reason: string;
  readonly localMemberId?: MemberId | null;
  readonly remoteMemberId?: MemberId;
  readonly restoreAvailable?: boolean;
  readonly localGeneration?: AccountGeneration | null;
  readonly remoteGeneration?: AccountGeneration | null;
  readonly remoteEtag?: AccountBackupEtag | null;
}

export interface RetainedAccountIdentity {
  readonly memberId: MemberId;
  readonly generation: AccountGeneration;
  readonly floor: AccountGeneration;
}

export interface AccountSessionState {
  readonly auth: AccountAuthState;
  readonly account: AccountCustodyState;
  readonly binding: AccountBindingState;
  readonly syncDisposition: AccountSyncDisposition;
  readonly pending: ReadonlySet<AccountPendingAction>;
  readonly conflict: AccountConflict | null;
  readonly retainedIdentities: ReadonlyArray<RetainedAccountIdentity>;
  readonly storagePersistence: StoragePersistence;
  readonly memberId?: MemberId;
}

export interface InternalAccountSessionState {
  readonly auth: AccountAuthState;
  readonly account: AccountCustodyState;
  readonly binding: AccountBindingState;
  readonly syncDisposition: AccountSyncDisposition;
  readonly pending: ReadonlyArray<AccountPendingAction>;
  readonly conflict: AccountConflict | null;
  readonly retainedIdentities: ReadonlyArray<RetainedAccountIdentity>;
  readonly storagePersistence: StoragePersistence;
  readonly memberId?: MemberId;
}

export type AccountBindingClassification =
  | { readonly action: 'none' | 'register' | 'reconcile' }
  | { readonly action: 'conflict'; readonly reason: string; readonly restoreAvailable?: boolean };

export interface AccountSessionOptions {
  readonly wakeTarget?: Pick<EventTarget, 'addEventListener' | 'removeEventListener'>;
  readonly visibilityTarget?: (Pick<Document, 'addEventListener' | 'removeEventListener' | 'visibilityState'>) | null;
  readonly locks?: { request<Value>(name: string, callback: () => Promise<Value> | Value): Promise<Value> } | null;
  readonly profile?: string;
}

export interface KeptOfflineContext {
  readonly issuer: AuthIssuer;
  readonly subject: AuthSubject;
}

export interface BackupConflictRemote {
  readonly keystore: AccountKeystoreBytes | null;
  readonly generation: AccountGeneration;
  readonly etag: AccountBackupEtag;
}

export type RestoreCredential = AccountCandidateCredential;
export type LocalAccountSync = AccountSyncState;
export type LocalAccountBinding = AccountBinding;
export type LocalAccountVersion = AccountVersion;
export type LocalAccountCheckpoint = AccountBackupCheckpoint;
