import type {
  AccountBlobHashBytes,
  AccountGeneration,
  AccountKeystoreBytes,
  AppSecretEnvelopeBytes,
  AppSecretPlaintextBytes,
  AuthorPublicKeyBytes,
  ClaimsJson,
  CoveredFrontierJson,
  DidKey,
  FramedKeyringHopsBytes,
  HistoryDeltaEnvelopeBytes,
  HistoryDeltaJson,
  HpkePublicKeyBytes,
  JsonValueText,
  KeyringBytes,
  KeyringEngine,
  KeyringRevision,
  KeyringWatermarkBytes,
  LiveRecordsJson,
  MemberId,
  OplogJson,
  PendingReviewsJson,
  PredicateUri,
  ProjectionJson,
  ProposalEnvelopeBytes,
  PullFrontierJson,
  RecoveryCode,
  RecordId,
  RemovalOperationId,
  ReplicaCounter,
  ReplicaHex,
  TreeObjectBytes,
  TreeObjectKey,
  TypeUri,
} from './domain.js';
import type {
  AccountHandle as RawAccountHandle,
  AccountOpenResult as RawAccountOpenResult,
  AccountPublicIdentity as RawAccountPublicIdentity,
  AccountSnapshot as RawAccountSnapshot,
  AccountUpdateResult as RawAccountUpdateResult,
  AppCoreHandle as RawAppCoreHandle,
  DagBackfilled as RawDagBackfilled,
  KeyringWalk as RawKeyringWalk,
  MembershipChange as RawMembershipChange,
  OpenResult as RawOpenResult,
} from '../../vendor/app-core/openom_app_core.js';

export interface TreeObject {
  readonly key: TreeObjectKey;
  readonly bytes: TreeObjectBytes;
}

export interface ExportedTreeObject extends TreeObject {
  readonly pointer: boolean;
}

export interface CoreSyncResult {
  readonly put: ExportedTreeObject[];
  readonly folded: number;
  readonly covered: CoveredFrontierJson;
}

interface AppCoreHandleRefinements {
  adoptEpochs(keyring: KeyringBytes): number;
  approvePending(replica: ReplicaHex, counter: ReplicaCounter): boolean;
  approveProposal(proposal: ProposalEnvelopeBytes): number;
  assertAnchor(id: RecordId, typeUri: TypeUri): void;
  assertClaim(target: RecordId, predicate: PredicateUri, valueJson: JsonValueText): void;
  discardPending(replica: ReplicaHex, counter: ReplicaCounter): boolean;
  export(): ExportedTreeObject[];
  import(objects: ReadonlyArray<TreeObject>): void;
  liveClaimsOf(target: RecordId, predicate: PredicateUri): ClaimsJson;
  liveClaimsOfAny(target: RecordId): ClaimsJson;
  liveRecords(): LiveRecordsJson;
  openAppSecret(sealed: AppSecretEnvelopeBytes): AppSecretPlaintextBytes;
  openHistoryDelta(envelope: HistoryDeltaEnvelopeBytes): HistoryDeltaJson;
  oplog(): OplogJson;
  pendingReviews(): PendingReviewsJson;
  planFetch(keys: ReadonlyArray<TreeObjectKey>): TreeObjectKey[];
  project(): ProjectionJson;
  propose(): ProposalEnvelopeBytes | undefined;
  pullFrontier(): PullFrontierJson;
  removeRecord(target: RecordId): RemovalOperationId;
  resolveId(anchor: RecordId): RecordId | undefined;
  revoke(removalOperationId: RemovalOperationId): void;
  sealAppSecret(plaintext: AppSecretPlaintextBytes): AppSecretEnvelopeBytes;
  setMembership(
    engine: KeyringEngine,
    head: KeyringBytes,
    retained: ReadonlyArray<readonly [KeyringRevision, KeyringBytes]>,
  ): number;
  setModerators(dids: ReadonlyArray<DidKey>): void;
  subsumedFrontier(): CoveredFrontierJson;
  supersedeClaim(
    prior: RecordId,
    target: RecordId,
    predicate: PredicateUri,
    valueJson: JsonValueText,
  ): void;
  sync(
    remote: ReadonlyArray<TreeObject>,
    present: ReadonlyArray<TreeObjectKey>,
    compactK: number,
  ): CoreSyncResult;
}

export type AppCoreHandle = Omit<RawAppCoreHandle, keyof AppCoreHandleRefinements> &
  AppCoreHandleRefinements;

export type AccountHandle = Omit<RawAccountHandle, 'generation' | 'memberId'> & {
  readonly generation: AccountGeneration;
  readonly memberId: MemberId;
};

export type AccountOpenResult = Omit<
  RawAccountOpenResult,
  'blobHash' | 'generation' | 'keystore' | 'recoveryCode' | 'takeHandle'
> & {
  readonly blobHash: AccountBlobHashBytes;
  readonly generation: AccountGeneration;
  readonly keystore: AccountKeystoreBytes;
  readonly recoveryCode: RecoveryCode;
  takeHandle(): AccountHandle | undefined;
};

export type AccountPublicIdentity = Omit<
  RawAccountPublicIdentity,
  'authorPublicKey' | 'hpkePublicKey' | 'memberId'
> & {
  readonly authorPublicKey: AuthorPublicKeyBytes;
  readonly hpkePublicKey: HpkePublicKeyBytes;
  readonly memberId: MemberId;
};

export type AccountSnapshot = Omit<
  RawAccountSnapshot,
  'blobHash' | 'generation' | 'keystore'
> & {
  readonly blobHash: AccountBlobHashBytes;
  readonly generation: AccountGeneration;
  readonly keystore: AccountKeystoreBytes;
};

export type AccountUpdateResult = Omit<
  RawAccountUpdateResult,
  'blobHash' | 'generation' | 'keystore' | 'recoveryCode'
> & {
  readonly blobHash: AccountBlobHashBytes;
  readonly generation: AccountGeneration;
  readonly keystore: AccountKeystoreBytes;
  readonly recoveryCode: RecoveryCode;
};

export type OpenResult = Omit<
  RawOpenResult,
  'didKey' | 'keyring' | 'keystore' | 'recoveryCode' | 'takeHandle' | 'watermark'
> & {
  readonly didKey: DidKey;
  readonly keyring: KeyringBytes;
  readonly keystore: AccountKeystoreBytes;
  readonly recoveryCode: RecoveryCode;
  readonly watermark: KeyringWatermarkBytes;
  takeHandle(): AppCoreHandle | undefined;
};

export type MembershipChange = Omit<RawMembershipChange, 'keyring' | 'watermark'> & {
  readonly keyring: KeyringBytes;
  readonly watermark: KeyringWatermarkBytes;
};

export type DagBackfilled = Omit<RawDagBackfilled, 'keyring' | 'watermark'> & {
  readonly keyring: KeyringBytes;
  readonly watermark: KeyringWatermarkBytes;
};

export type KeyringWalk = Omit<
  RawKeyringWalk,
  'bodiesFramed' | 'headKeyring' | 'revision'
> & {
  readonly bodiesFramed: FramedKeyringHopsBytes;
  readonly headKeyring: KeyringBytes;
  readonly revision: KeyringRevision;
};
