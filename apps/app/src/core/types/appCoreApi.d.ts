import type { Remote } from '../../vendor/comlink.js';
import type {
  AccountBlobHashBytes,
  AccountGeneration,
  AccountKeystoreBytes,
  AccountRecordRevision,
  AuthIssuer,
  AuthSubject,
  AuthorPublicKeyBytes,
  ClaimsJson,
  CoveredFrontierJson,
  DagAnchorPinBytes,
  DidKey,
  DocId,
  HpkePublicKeyBytes,
  InviteId,
  InviteLink,
  InviteMacBytes,
  InvitePinBytes,
  JsonValueText,
  KeyringEngine,
  KeyringHashBytes,
  KeyringRevision,
  KeyringUpdateBytes,
  LiveRecordsJson,
  MemberId,
  MemberRole,
  OplogJson,
  Passphrase,
  PredicateUri,
  ProjectionJson,
  ProposalEnvelopeBytes,
  ProposalId,
  RecoveryCode,
  RecordId,
  RegistrationProofBytes,
  RemoteTreeKey,
  RemovalOperationId,
  ReplicaHex,
  ReplicaId,
  ResetAuthorityBytes,
  TreeId,
  TreeObjectBytes,
  TreeObjectKey,
  TreeUuid,
  TypeUri,
} from './domain.js';
import type {
  AccountBackupCheckpoint,
  AccountBinding,
  AccountPublicIdentity,
  AccountVersion,
  PendingAccountBackup,
} from './contracts.js';

export type Awaitable<Value> = Value | Promise<Value>;
export type StoragePersistence = 'granted' | 'denied' | 'unavailable';
export type AccountCustodyStatus = 'none' | 'locked' | 'unlocked';

export interface AccountSyncIdentity {
  readonly memberId: MemberId;
  readonly version: AccountVersion;
  readonly floor: AccountGeneration;
  readonly effectiveFloor: AccountGeneration;
}

export interface AccountSyncRecord {
  readonly revision: AccountRecordRevision;
  readonly identity: AccountSyncIdentity;
  readonly retainedIdentities: ReadonlyArray<AccountSyncIdentity>;
  readonly binding: AccountBinding | null;
  readonly acknowledgedBackup: AccountBackupCheckpoint | null;
  readonly pendingBackup: PendingAccountBackup | null;
}

export interface AccountSyncState {
  readonly record: AccountSyncRecord | null;
  readonly storagePersistence: StoragePersistence;
}

export interface AccountBackupAcknowledged extends AccountSyncState {
  readonly cleared: boolean;
}

export interface AccountCreated {
  readonly recoveryCode: RecoveryCode;
  readonly generation: AccountGeneration;
  readonly storagePersistence?: StoragePersistence;
  readonly memberId?: MemberId;
  readonly authorPublicKey?: AuthorPublicKeyBytes;
  readonly hpkePublicKey?: HpkePublicKeyBytes;
}

export interface AccountRecovered {
  readonly recoveryCode: RecoveryCode;
  readonly generation: AccountGeneration;
  readonly memberId?: MemberId;
  readonly authorPublicKey?: AuthorPublicKeyBytes;
  readonly hpkePublicKey?: HpkePublicKeyBytes;
}

export interface AccountSnapshot {
  readonly keystore: AccountKeystoreBytes;
  readonly generation: AccountGeneration;
  readonly blobHash: AccountBlobHashBytes;
  readonly memberId?: MemberId;
  readonly authorPublicKey?: AuthorPublicKeyBytes;
  readonly hpkePublicKey?: HpkePublicKeyBytes;
}

export interface AdoptedAccount extends AccountRecovered {
  readonly blobHash: AccountBlobHashBytes;
}

export type AccountCandidateCredential =
  | { readonly passphrase: Passphrase }
  | { readonly recoveryCode: RecoveryCode; readonly newPassphrase: Passphrase };

export interface TreeOpenResult {
  readonly didKey: DidKey;
  readonly memberId?: MemberId;
  readonly needsReseal?: boolean;
  readonly needsBackfill?: boolean;
  readonly needsRrkBackfill?: boolean;
  readonly writeEpochUnreachable?: boolean;
}

export interface InviteClaim {
  readonly inviteId: InviteId;
  readonly memberId: MemberId;
  readonly authorPublicKey: AuthorPublicKeyBytes;
  readonly hpkePublicKey: HpkePublicKeyBytes;
  readonly tag: InviteMacBytes;
}

export interface PendingInvite {
  readonly inviteId: InviteId;
  readonly uuid: TreeUuid;
  readonly role: MemberRole;
  readonly engine: KeyringEngine;
  readonly pin: InvitePinBytes;
  readonly metaMac: InviteMacBytes;
  readonly recipientPin: string | null;
  readonly expiry: number;
}

export interface MintedInvite {
  readonly inviteId: InviteId;
  readonly link: InviteLink;
  readonly pending: PendingInvite;
}

export interface PendingProposal {
  readonly id: ProposalId;
  readonly proposer: MemberId;
  readonly sizeBytes: number;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface CreatedProposal {
  readonly id: ProposalId;
  readonly expiresAt: string;
}

export interface PendingReview {
  readonly replica: ReplicaHex;
  readonly counter: number;
  readonly authorMemberId: MemberId;
  readonly kind: string;
}

export interface HistoryOptions {
  readonly since?: number;
  readonly limit?: number;
}

export interface HistoryEntry {
  readonly author: MemberId;
  readonly createdAt: string;
  readonly replica: ReplicaHex;
  readonly counter: number;
  readonly size: number;
  readonly viewable: boolean;
  readonly ops: unknown;
}

export interface HistoryPage {
  readonly entries: ReadonlyArray<HistoryEntry>;
  readonly nextCursor: number | null;
}

export interface SyncOk {
  readonly state: 'ok';
  readonly pending?: number;
  readonly anomalies: number;
}

export interface SyncError {
  readonly state: 'error';
  readonly error: unknown;
}

export interface SyncIdle {
  readonly state: 'busy' | 'no-transport' | 'stopped';
}

export type SyncResult = SyncOk | SyncError | SyncIdle;

export interface RemoteBlobMeta {
  readonly key: TreeObjectKey;
}

export interface RemoteKeyringRevision {
  readonly revision: KeyringRevision;
  readonly bytes: KeyringUpdateBytes;
}

export interface RemoteKeyringWalk {
  readonly revisions: ReadonlyArray<RemoteKeyringRevision>;
  readonly head: KeyringRevision;
}

export interface RemoteProposal extends PendingProposal {
  readonly payload: ProposalEnvelopeBytes;
}

export interface RemoteHistoryEntry {
  readonly memberId: MemberId;
  readonly createdAt: string;
  readonly replica: ReplicaHex;
  readonly counter: number;
  readonly size: number;
  readonly seq: number;
}

export interface RemoteHistoryPage {
  readonly entries: ReadonlyArray<RemoteHistoryEntry>;
  readonly nextCursor: number | null;
}

export interface AppCoreTransport {
  createTree(tree: RemoteTreeKey): Awaitable<unknown>;
  blobList(prefix: RemoteTreeKey): Awaitable<ReadonlyArray<RemoteBlobMeta>>;
  blobGet(key: TreeObjectKey): Awaitable<TreeObjectBytes | null>;
  blobPut(
    key: TreeObjectKey,
    bytes: TreeObjectBytes,
    pointer: boolean,
    covered?: CoveredFrontierJson,
  ): Awaitable<unknown>;
  putFrontier(tree: RemoteTreeKey, frontier: Readonly<Record<string, number>>): Awaitable<unknown>;
  readKeyring(tree: TreeUuid, from: KeyringRevision): Awaitable<RemoteKeyringWalk>;
  putKeyring(tree: TreeUuid, update: KeyringUpdateBytes): Awaitable<unknown>;
  getAccess(tree: TreeUuid): Awaitable<unknown>;
  putAccess(tree: TreeUuid, body: unknown): Awaitable<unknown>;
  createProposal(tree: RemoteTreeKey, proposal: ProposalEnvelopeBytes): Awaitable<CreatedProposal>;
  listProposals(tree: RemoteTreeKey): Awaitable<ReadonlyArray<RemoteProposal>>;
  deleteProposal(tree: RemoteTreeKey, proposalId: ProposalId): Awaitable<unknown>;
  getHistory(tree: RemoteTreeKey, options: HistoryOptions): Awaitable<RemoteHistoryPage>;
}

export interface AppCoreService {
  ping(): Awaitable<boolean>;
  warm(): Awaitable<void>;
  accountCreate(passphrase: Passphrase): Awaitable<AccountCreated>;
  accountUnlock(passphrase: Passphrase): Awaitable<AccountPublicIdentity>;
  accountStatus(): Awaitable<AccountCustodyStatus>;
  accountLock(): Awaitable<void>;
  accountRecover(options: {
    readonly recoveryCode: RecoveryCode;
    readonly newPassphrase: Passphrase;
  }): Awaitable<AccountRecovered>;
  accountSnapshot(): Awaitable<AccountSnapshot>;
  accountSyncState(): Awaitable<AccountSyncState>;
  accountConfirmBinding(binding: AccountBinding): Awaitable<AccountSyncState>;
  accountStageBackup(options: {
    readonly kind: 'backup' | 'revoke';
    readonly binding: AccountBinding;
  }): Awaitable<AccountSyncState>;
  accountAcknowledgeBackup(options: {
    readonly expected: PendingAccountBackup;
    readonly checkpoint: AccountBackupCheckpoint;
  }): Awaitable<AccountBackupAcknowledged>;
  accountAdoptCandidate(options: {
    readonly expectedMemberId: MemberId;
    readonly keystore: AccountKeystoreBytes;
    readonly credential: AccountCandidateCredential;
    readonly binding: AccountBinding;
    readonly checkpoint: AccountBackupCheckpoint;
  }): Awaitable<AdoptedAccount>;
  accountChangePassphrase(options: {
    readonly current: Passphrase;
    readonly next: Passphrase;
  }): Awaitable<{ readonly generation: AccountGeneration }>;
  accountPublicIdentity(): Awaitable<AccountPublicIdentity>;
  accountRotateRoot(options: {
    readonly passphrase: Passphrase;
  }): Awaitable<{ readonly recoveryCode: RecoveryCode; readonly generation: AccountGeneration }>;
  accountRegisterProof(options: {
    readonly issuer: AuthIssuer;
    readonly subject: AuthSubject;
    readonly timestamp: number;
  }): Awaitable<RegistrationProofBytes>;
  hasKeyring(docId: DocId): Awaitable<boolean>;
  attachTransport(docId: DocId, transport: AppCoreTransport): Awaitable<void>;
  openDev(
    treeId: TreeId,
    replicaId: ReplicaId,
    createdBy: DidKey,
    docId: DocId,
    persist?: boolean,
  ): Awaitable<boolean>;
  provisionTree(options: {
    readonly treeId: TreeId;
    readonly docId: DocId;
    readonly engine?: KeyringEngine;
  }): Awaitable<TreeOpenResult>;
  openTree(options: {
    readonly treeId: TreeId;
    readonly docId: DocId;
    readonly engine?: KeyringEngine;
  }): Awaitable<TreeOpenResult>;
  resetCore(docId: DocId): Awaitable<void>;
  close(docId: DocId): Awaitable<void>;
  setModerators(docId: DocId, dids: ReadonlyArray<DidKey>): Awaitable<void>;
  assertAnchor(docId: DocId, id: RecordId, typeUri: TypeUri): Awaitable<void>;
  assertClaim(
    docId: DocId,
    target: RecordId,
    predicate: PredicateUri,
    valueJson: JsonValueText,
  ): Awaitable<void>;
  supersedeClaim(
    docId: DocId,
    prior: RecordId,
    target: RecordId,
    predicate: PredicateUri,
    valueJson: JsonValueText,
  ): Awaitable<void>;
  removeRecord(docId: DocId, target: RecordId): Awaitable<RemovalOperationId>;
  revoke(docId: DocId, removalOperationId: RemovalOperationId): Awaitable<void>;
  commit(docId: DocId): Awaitable<void>;
  canCommitDirectly(docId: DocId): Awaitable<boolean>;
  submitEdit(docId: DocId): Awaitable<
    | { readonly committed: true }
    | { readonly proposed: true; readonly proposal: CreatedProposal | null }
  >;
  proposeEdit(docId: DocId): Awaitable<CreatedProposal | null>;
  pendingProposals(docId: DocId): Awaitable<ReadonlyArray<PendingProposal>>;
  approveProposal(docId: DocId, proposalId: ProposalId): Awaitable<number>;
  rejectProposal(docId: DocId, proposalId: ProposalId): Awaitable<void>;
  history(docId: DocId, options?: HistoryOptions): Awaitable<HistoryPage>;
  project(docId: DocId): Awaitable<ProjectionJson>;
  oplog(docId: DocId): Awaitable<OplogJson>;
  pendingReviews(docId: DocId): Awaitable<ReadonlyArray<PendingReview>>;
  approvePending(
    docId: DocId,
    pending: { readonly replica: ReplicaHex; readonly counter: number },
  ): Awaitable<boolean>;
  discardPending(
    docId: DocId,
    pending: { readonly replica: ReplicaHex; readonly counter: number },
  ): Awaitable<boolean>;
  liveRecords(docId: DocId): Awaitable<LiveRecordsJson>;
  liveClaimsOf(docId: DocId, target: RecordId, predicate: PredicateUri): Awaitable<ClaimsJson>;
  liveClaimsOfAny(docId: DocId, target: RecordId): Awaitable<ClaimsJson>;
  resolveId(docId: DocId, anchor: RecordId): Awaitable<RecordId | undefined>;
  pendingCount(docId: DocId): Awaitable<number>;
  provisionMember(passphrase: Passphrase): Awaitable<
    AccountPublicIdentity & { readonly recoveryCode: RecoveryCode }
  >;
  inviteMember(docId: DocId, options: {
    readonly role: MemberRole;
    readonly recipientPin?: string | null;
    readonly ttlMs?: number;
    readonly base?: string;
  }): Awaitable<MintedInvite>;
  admitMember(docId: DocId, options: {
    readonly passphrase: Passphrase;
    readonly treeId: TreeId;
    readonly ownerMemberId: MemberId;
    readonly inviteId: InviteId;
    readonly claim: InviteClaim;
  }): Awaitable<void>;
  addMember(docId: DocId, options: {
    readonly passphrase: Passphrase;
    readonly treeId: TreeId;
    readonly ownerMemberId: MemberId;
    readonly newMemberId: MemberId;
    readonly role: MemberRole;
    readonly memberAuthorPublic: AuthorPublicKeyBytes;
    readonly memberHpkePublic: HpkePublicKeyBytes;
    readonly engine?: KeyringEngine;
  }): Awaitable<unknown>;
  removeMember(docId: DocId, options: {
    readonly passphrase: Passphrase;
    readonly treeId: TreeId;
    readonly ownerMemberId: MemberId;
    readonly removeMemberId: MemberId;
    readonly engine?: KeyringEngine;
  }): Awaitable<unknown>;
  changeRole(docId: DocId, options: {
    readonly passphrase: Passphrase;
    readonly treeId: TreeId;
    readonly ownerMemberId: MemberId;
    readonly targetMemberId: MemberId;
    readonly newRole: MemberRole;
    readonly engine?: KeyringEngine;
  }): Awaitable<unknown>;
  joinAsMember(options: {
    readonly docId: DocId;
    readonly treeId: TreeId;
    readonly treeUuid?: TreeUuid;
    readonly passphrase: Passphrase;
    readonly memberId?: MemberId;
    readonly engine?: KeyringEngine;
    readonly pin?: InvitePinBytes;
    readonly pinnedRevision?: KeyringRevision;
    readonly pinnedHash?: KeyringHashBytes;
  }): Awaitable<{ readonly didKey: DidKey }>;
  syncKeyring(docId: DocId, treeId: TreeId): Awaitable<{ readonly changed: boolean }>;
  syncNow(docId: DocId): Awaitable<SyncResult>;
}

export interface WebAppCoreService extends AppCoreService {
  restoreTree(options: {
    readonly treeId: TreeId;
    readonly docId: DocId;
    readonly engine?: KeyringEngine;
  }): Awaitable<TreeOpenResult>;
  setCompactK(compactK: number): Awaitable<void>;
  confirmRotationCore(options: {
    readonly docId: DocId;
    readonly resetAuthority: ResetAuthorityBytes;
    readonly engine?: KeyringEngine;
  }): Awaitable<boolean>;
  backfillRrkCore(options: {
    readonly treeId: TreeId;
    readonly docId: DocId;
    readonly engine?: KeyringEngine;
  }): Awaitable<{ readonly backfilled: boolean }>;
  resolvedOwnerKeyCore(options: {
    readonly docId: DocId;
    readonly engine?: KeyringEngine;
  }): Awaitable<AuthorPublicKeyBytes>;
  confirmRecoveryCore(options: {
    readonly docId: DocId;
    readonly ownerKey: AuthorPublicKeyBytes;
    readonly engine?: KeyringEngine;
  }): Awaitable<boolean>;
  keyringHash(docId: DocId): Awaitable<{
    readonly revision: KeyringRevision;
    readonly hash: KeyringHashBytes;
  }>;
  dagAnchorPin(docId: DocId): Awaitable<DagAnchorPinBytes>;
  clearPersisted(docId: DocId): Awaitable<void>;
}

export type AppCoreClient = Remote<AppCoreService>;
export type WebAppCoreClient = Remote<WebAppCoreService>;
