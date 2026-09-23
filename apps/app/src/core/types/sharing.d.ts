import type {
  DagAnchorPinBytes,
  DocId,
  FramedKeyringHopsBytes,
  KeyringBytes,
  KeyringEngine,
  KeyringHashBytes,
  KeyringRevision,
  KeyringUpdateBytes,
  KeyringWatermarkBytes,
  MemberId,
  ReplicaId,
  TreeId,
  TrustedSignersBytes,
} from './domain.js';
import type { Awaitable, RemoteKeyringWalk } from './appCoreApi.js';
import type { KeyringWalk, MembershipChange, OpenResult } from './wasm.js';

export interface KeyringHeadRecord {
  readonly engine?: KeyringEngine;
  readonly bytes: KeyringBytes;
}

export interface RetainedKeyringRevision {
  readonly revision: KeyringRevision;
  readonly bytes: KeyringBytes;
}

export interface KeyringStore {
  saveHead(docId: DocId, engine: KeyringEngine, bytes: KeyringBytes): Awaitable<void>;
  loadHead(docId: DocId): Awaitable<KeyringHeadRecord | null>;
  load(docId: DocId): Awaitable<KeyringBytes | null>;
  save(docId: DocId, revision: KeyringRevision, bytes: KeyringBytes): Awaitable<void>;
  at(docId: DocId, revision: KeyringRevision): Awaitable<KeyringBytes | null>;
  head(docId: DocId): Awaitable<RetainedKeyringRevision | null>;
}

export interface KeyringTransport {
  readKeyring(docId: DocId, from: KeyringRevision): Awaitable<RemoteKeyringWalk>;
  putKeyring(docId: DocId, update: KeyringUpdateBytes): Awaitable<unknown>;
}

export interface VerifiedSigner {
  readonly memberId: MemberId;
  readonly authorPublicKey: Uint8Array;
}

export interface SyncChainDeps {
  readonly wasm: {
    syncKeyring(
      anchor: KeyringBytes,
      treeId: TreeId,
      hops: FramedKeyringHopsBytes,
    ): MembershipChange;
    unwrapChainKeyring(update: KeyringUpdateBytes): KeyringBytes;
  };
  readonly transport: Pick<KeyringTransport, 'readKeyring'>;
  readonly keyringStore: KeyringStore;
}

export interface RestoreOwnerDeps {
  readonly wasm: {
    unwrapChainKeyring(update: KeyringUpdateBytes): KeyringBytes;
    unwrapDagKeyring(update: KeyringUpdateBytes): KeyringBytes;
    verifyKeyringWalk(
      treeId: TreeId,
      hops: FramedKeyringHopsBytes,
      pinnedRevision: KeyringRevision,
      pinnedHash: KeyringHashBytes,
    ): KeyringWalk;
    keyringHash(keyring: KeyringBytes): KeyringHashBytes;
  };
  readonly transport: Pick<KeyringTransport, 'readKeyring'>;
  readonly keyringStore: KeyringStore;
  readonly openOwner: (engine: KeyringEngine, keyring: KeyringBytes) => Awaitable<OpenResult>;
  readonly persistWatermark: (watermark: KeyringWatermarkBytes) => Awaitable<void>;
  readonly freeOpened?: (opened: OpenResult) => void;
}

export interface PublishChainDeps {
  readonly wasm: {
    wrapChainKeyringUpdate(keyring: KeyringBytes): KeyringUpdateBytes;
  };
  readonly transport: KeyringTransport;
  readonly keyringStore: KeyringStore;
}

export interface JoinChainDeps {
  readonly wasm: {
    verifyKeyringWalk(
      treeId: TreeId,
      hops: FramedKeyringHopsBytes,
      pinnedRevision: KeyringRevision,
      pinnedHash: KeyringHashBytes,
    ): KeyringWalk;
    unlockAsMember(
      engine: KeyringEngine,
      keyring: KeyringBytes,
      treeId: TreeId,
      trustedSigners: TrustedSignersBytes,
      replicaId: ReplicaId,
      minRevision: KeyringRevision,
      docId: DocId,
    ): OpenResult;
  };
  readonly transport: Pick<KeyringTransport, 'readKeyring'>;
  readonly keyringStore: KeyringStore;
  readonly verifyFingerprint?: (
    signers: ReadonlyArray<VerifiedSigner>,
    fingerprint: string,
  ) => Awaitable<boolean>;
}

export interface JoinDagDeps {
  readonly wasm: {
    unwrapDagKeyring(update: KeyringUpdateBytes): KeyringBytes;
    verifyDagAnchor(
      keyring: KeyringBytes,
      treeId: TreeId,
      pin: DagAnchorPinBytes,
    ): MembershipChange;
    unlockAsMember: JoinChainDeps['wasm']['unlockAsMember'];
  };
  readonly transport: Pick<KeyringTransport, 'readKeyring'>;
  readonly keyringStore: KeyringStore;
}

export interface PublishDagDeps {
  readonly wasm: {
    unwrapDagKeyring(update: KeyringUpdateBytes): KeyringBytes;
    wrapDagKeyringUpdate(
      keyring: KeyringBytes,
      treeId: TreeId,
      revision: KeyringRevision,
    ): KeyringUpdateBytes;
  };
  readonly transport: KeyringTransport;
  readonly keyringStore: KeyringStore;
}

export interface SyncDagDeps {
  readonly wasm: {
    unwrapDagKeyring(update: KeyringUpdateBytes): KeyringBytes;
    dagAnchorPin(keyring: KeyringBytes): DagAnchorPinBytes;
    keyringSummary(engine: KeyringEngine, keyring: KeyringBytes): string;
    keyringCovers(
      engine: KeyringEngine,
      keyring: KeyringBytes,
      storedBasis: ReadonlyArray<string>,
    ): boolean;
    acceptRemoteDagAnchor(
      local: KeyringBytes,
      remote: KeyringBytes,
      treeId: TreeId,
      pin: DagAnchorPinBytes,
      floor: KeyringWatermarkBytes,
    ): MembershipChange;
  };
  readonly transport: Pick<KeyringTransport, 'readKeyring'>;
  readonly keyringStore: KeyringStore;
}
