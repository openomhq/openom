import type {
  AccountBlobHashBytes,
  AccountBackupEtag,
  AccountGeneration,
  AccountKeystoreBytes,
  AccountRecordRevision,
  AuthIssuer,
  AuthSubject,
  AuthorPublicKeyBytes,
  DocId,
  HpkePublicKeyBytes,
  KeyringEngine,
  MemberId,
  ReplicaId,
  TreeId,
  TreeUuid,
} from './domain.js';

export interface TreeIdentity {
  readonly bytes: TreeId;
  readonly uuid: TreeUuid;
}

export interface WasmTreeContext {
  readonly treeId: TreeId;
  readonly replicaId: ReplicaId;
  readonly docId: DocId;
  readonly engine: KeyringEngine;
}

export interface AccountVersion {
  readonly generation: AccountGeneration;
  readonly blobHash: AccountBlobHashBytes;
}

export interface AccountPublicIdentity {
  readonly memberId: MemberId;
  readonly authorPublicKey: AuthorPublicKeyBytes;
  readonly hpkePublicKey: HpkePublicKeyBytes;
}

export interface AccountBinding {
  readonly issuer: AuthIssuer;
  readonly subject: AuthSubject;
  readonly memberId: MemberId;
}

export interface AccountIdentitySnapshot {
  readonly memberId: MemberId;
  readonly keystore: AccountKeystoreBytes;
  readonly version: AccountVersion;
  readonly floor: AccountGeneration;
}

export interface AccountBackupCheckpoint {
  readonly etag: AccountBackupEtag;
  readonly version: AccountVersion | null;
}

export type AccountBackupKind = 'backup' | 'revoke';

export interface PendingAccountBackup {
  readonly kind: AccountBackupKind;
  readonly version: AccountVersion;
  readonly binding: AccountBinding;
}

export interface AccountRecord {
  readonly revision: AccountRecordRevision;
  readonly identity: AccountIdentitySnapshot;
  readonly retainedIdentities: ReadonlyArray<AccountIdentitySnapshot>;
  readonly binding: AccountBinding | null;
  readonly acknowledgedBackup: AccountBackupCheckpoint | null;
  readonly pendingBackup: PendingAccountBackup | null;
}
