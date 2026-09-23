import type {
  AccountGeneration,
  AccountKeystoreBytes,
  AppSecretEnvelopeBytes,
  AppSecretPlaintextBytes,
  AuthIssuer,
  AuthSubject,
  AuthorPublicKeyBytes,
  ClaimsJson,
  CoveredFrontierJson,
  DagAnchorPinBytes,
  DidKey,
  DocId,
  FramedKeyringHopsBytes,
  HistoryDeltaEnvelopeBytes,
  HistoryDeltaJson,
  HpkePublicKeyBytes,
  InvitePinBytes,
  JsonValueText,
  KeyringBytes,
  KeyringEngine,
  KeyringHashBytes,
  KeyringSummaryJson,
  KeyringUpdateBytes,
  LiveRecordsJson,
  MemberId,
  MemberRole,
  OplogJson,
  Passphrase,
  PendingReviewsJson,
  PredicateUri,
  ProjectionJson,
  ProposalEnvelopeBytes,
  RecordId,
  RecoveryCode,
  RegistrationProofBytes,
  RemovalOperationId,
  ReplicaHex,
  TreeObjectBytes,
  TreeObjectKey,
  TreeId,
  TypeUri,
} from './domain.js';
import type {
  AccountBackupCheckpoint,
  AccountBinding,
  AccountPublicIdentity,
  PendingAccountBackup,
} from './contracts.js';
import type {
  AccountBackupAcknowledged,
  AccountCreated,
  AccountCustodyStatus,
  AccountRecovered,
  AccountSnapshot,
  AccountSyncState,
  AdoptedAccount,
  TreeOpenResult,
} from './appCoreApi.js';

declare const nativeBytesBrand: unique symbol;

export type NativeBytes<Value extends Uint8Array = Uint8Array> = ReadonlyArray<number> & {
  readonly [nativeBytesBrand]: Value;
};
export type NativeStoredObject = readonly [TreeObjectKey, NativeBytes<TreeObjectBytes>];

export interface NativeAddedMember {
  readonly keyring: KeyringUpdateBytes;
  readonly firstShare: boolean;
}

export interface NativeRemovedMember {
  readonly keyring: KeyringUpdateBytes;
  readonly historyPreserved: boolean;
}

export interface NativeRoleChanged {
  readonly keyring: KeyringUpdateBytes;
  readonly demote: boolean;
}

export interface NativeInviteMaterial {
  readonly engine: KeyringEngine;
  readonly pin: InvitePinBytes;
}

export interface NativeKeyringRevisionPayload {
  readonly update: KeyringUpdateBytes;
  readonly body: KeyringBytes;
}

export interface NativeUploadObject {
  readonly key: TreeObjectKey;
  readonly bytes: TreeObjectBytes;
  readonly pointer: boolean;
}

export interface NativeSyncResult {
  readonly uploads: ReadonlyArray<NativeUploadObject>;
  readonly folded: number;
  readonly covered: CoveredFrontierJson;
}

export interface NativeCommandMap {
  account_create: {
    args: { readonly passphrase: Passphrase };
    result: AccountCreated;
  };
  account_unlock: {
    args: { readonly passphrase: Passphrase };
    result: AccountPublicIdentity;
  };
  account_status: { args: undefined; result: AccountCustodyStatus };
  account_lock: { args: undefined; result: void };
  account_recover: {
    args: { readonly recoveryCode: RecoveryCode; readonly newPassphrase: Passphrase };
    result: AccountRecovered;
  };
  account_public_identity: { args: undefined; result: AccountPublicIdentity };
  account_snapshot: { args: undefined; result: AccountSnapshot };
  account_sync_state: { args: undefined; result: AccountSyncState };
  account_confirm_binding: {
    args: { readonly binding: AccountBinding };
    result: AccountSyncState;
  };
  account_stage_backup: {
    args: { readonly kind: 'backup' | 'revoke'; readonly binding: AccountBinding };
    result: AccountSyncState;
  };
  account_acknowledge_backup: {
    args: {
      readonly expected: PendingAccountBackup;
      readonly checkpoint: AccountBackupCheckpoint;
    };
    result: AccountBackupAcknowledged;
  };
  account_adopt_candidate: {
    args: {
      readonly expectedMemberId: MemberId;
      readonly candidate: NativeBytes<AccountKeystoreBytes>;
      readonly passphrase: Passphrase;
      readonly binding: AccountBinding;
      readonly checkpoint: AccountBackupCheckpoint;
    };
    result: AdoptedAccount;
  };
  account_adopt_recovery_candidate: {
    args: {
      readonly expectedMemberId: MemberId;
      readonly candidate: NativeBytes<AccountKeystoreBytes>;
      readonly recoveryCode: RecoveryCode;
      readonly newPassphrase: Passphrase;
      readonly binding: AccountBinding;
      readonly checkpoint: AccountBackupCheckpoint;
    };
    result: AdoptedAccount;
  };
  account_change_passphrase: {
    args: { readonly newPassphrase: Passphrase };
    result: { readonly generation: AccountGeneration };
  };
  account_rotate_root: {
    args: { readonly passphrase: Passphrase };
    result: { readonly recoveryCode: RecoveryCode; readonly generation: AccountGeneration };
  };
  account_register_proof: {
    args: { readonly issuer: AuthIssuer; readonly subject: AuthSubject; readonly timestamp: number };
    result: RegistrationProofBytes;
  };
  core_provision: {
    args: { readonly doc: DocId; readonly treeId: NativeBytes<TreeId> };
    result: Pick<TreeOpenResult, 'didKey'>;
  };
  core_unlock: {
    args: { readonly doc: DocId; readonly treeId: NativeBytes<TreeId> };
    result: TreeOpenResult;
  };
  core_derive_member_id: {
    args: { readonly authorPublicKey: NativeBytes<AuthorPublicKeyBytes> };
    result: MemberId;
  };
  core_add_member: {
    args: {
      readonly doc: DocId;
      readonly treeId: NativeBytes<TreeId>;
      readonly member: {
        readonly memberId: MemberId;
        readonly role: MemberRole;
        readonly authorPublicKey: NativeBytes<AuthorPublicKeyBytes>;
        readonly hpkePublicKey: NativeBytes<HpkePublicKeyBytes>;
      };
    };
    result: NativeAddedMember;
  };
  core_remove_member: {
    args: { readonly doc: DocId; readonly treeId: NativeBytes<TreeId>; readonly removeMemberId: MemberId };
    result: NativeRemovedMember;
  };
  core_change_role: {
    args: {
      readonly doc: DocId;
      readonly treeId: NativeBytes<TreeId>;
      readonly targetMemberId: MemberId;
      readonly newRole: MemberRole;
    };
    result: NativeRoleChanged;
  };
  core_join_as_member: {
    args: {
      readonly doc: DocId;
      readonly treeId: NativeBytes<TreeId>;
      readonly hops: NativeBytes<FramedKeyringHopsBytes>;
      readonly pinnedRevision: number;
      readonly pinnedHash: NativeBytes<KeyringHashBytes>;
    };
    result: { readonly didKey: DidKey };
  };
  core_join_dag_anchor: {
    args: {
      readonly doc: DocId;
      readonly treeId: NativeBytes<TreeId>;
      readonly anchor: NativeBytes<KeyringBytes>;
      readonly pin: NativeBytes<DagAnchorPinBytes>;
    };
    result: { readonly didKey: DidKey };
  };
  core_has_keyring: { args: { readonly doc: DocId }; result: boolean };
  core_bootstrap: { args: { readonly doc: DocId }; result: void };
  core_assert_anchor: {
    args: { readonly doc: DocId; readonly id: RecordId; readonly typeUri: TypeUri };
    result: void;
  };
  core_commit: { args: { readonly doc: DocId }; result: void };
  core_can_commit_directly: { args: { readonly doc: DocId }; result: boolean };
  core_open_history_delta: {
    args: { readonly doc: DocId; readonly envelope: NativeBytes<HistoryDeltaEnvelopeBytes> };
    result: HistoryDeltaJson;
  };
  core_propose: { args: { readonly doc: DocId }; result: ProposalEnvelopeBytes };
  core_approve_proposal: {
    args: { readonly doc: DocId; readonly proposal: NativeBytes<ProposalEnvelopeBytes> };
    result: number;
  };
  core_project: { args: { readonly doc: DocId }; result: ProjectionJson };
  core_membership_summary: { args: { readonly doc: DocId }; result: KeyringSummaryJson };
  core_invite_material: { args: { readonly doc: DocId }; result: NativeInviteMaterial };
  core_assert_claim: {
    args: {
      readonly doc: DocId;
      readonly target: RecordId;
      readonly predicate: PredicateUri;
      readonly valueJson: JsonValueText;
    };
    result: void;
  };
  core_supersede_claim: {
    args: {
      readonly doc: DocId;
      readonly prior: RecordId;
      readonly target: RecordId;
      readonly predicate: PredicateUri;
      readonly valueJson: JsonValueText;
    };
    result: void;
  };
  core_remove_record: {
    args: { readonly doc: DocId; readonly target: RecordId };
    result: RemovalOperationId;
  };
  core_revoke: {
    args: { readonly doc: DocId; readonly removalOpId: RemovalOperationId };
    result: void;
  };
  core_reset: { args: { readonly doc: DocId }; result: void };
  core_set_moderators: {
    args: { readonly doc: DocId; readonly moderators: ReadonlyArray<DidKey> };
    result: void;
  };
  core_close: { args: { readonly doc: DocId }; result: void };
  core_oplog: { args: { readonly doc: DocId }; result: OplogJson };
  core_live_records: { args: { readonly doc: DocId }; result: LiveRecordsJson };
  core_live_claims_of: {
    args: { readonly doc: DocId; readonly target: RecordId; readonly predicate: PredicateUri };
    result: ClaimsJson;
  };
  core_live_claims_of_any: {
    args: { readonly doc: DocId; readonly target: RecordId };
    result: ClaimsJson;
  };
  core_resolve_id: {
    args: { readonly doc: DocId; readonly anchor: RecordId };
    result: RecordId | null;
  };
  core_pending_count: { args: { readonly doc: DocId }; result: number };
  core_anomalies: { args: { readonly doc: DocId }; result: number };
  core_pull_frontier: {
    args: { readonly doc: DocId };
    result: Readonly<Record<string, number>>;
  };
  core_pending_reviews: { args: { readonly doc: DocId }; result: PendingReviewsJson };
  core_approve_pending: {
    args: { readonly doc: DocId; readonly replica: ReplicaHex; readonly counter: number };
    result: boolean;
  };
  core_discard_pending: {
    args: { readonly doc: DocId; readonly replica: ReplicaHex; readonly counter: number };
    result: boolean;
  };
  core_sync_keyring: {
    args: {
      readonly doc: DocId;
      readonly treeId: NativeBytes<TreeId>;
      readonly hops: NativeBytes<FramedKeyringHopsBytes>;
    };
    result: void;
  };
  core_keyring_head: { args: { readonly doc: DocId }; result: number };
  core_keyring_publish_payload_at: {
    args: { readonly doc: DocId; readonly revision: number };
    result: NativeKeyringRevisionPayload;
  };
  core_sync: {
    args: {
      readonly doc: DocId;
      readonly remote: ReadonlyArray<NativeStoredObject>;
      readonly present: ReadonlyArray<TreeObjectKey>;
      readonly compactK: number;
    };
    result: NativeSyncResult;
  };
  core_plan_fetch: {
    args: { readonly doc: DocId; readonly keys: ReadonlyArray<TreeObjectKey> };
    result: TreeObjectKey[];
  };
  core_seal_app_secret: {
    args: { readonly doc: DocId; readonly bytes: NativeBytes<AppSecretPlaintextBytes> };
    result: AppSecretEnvelopeBytes;
  };
  core_open_app_secret: {
    args: { readonly doc: DocId; readonly sealed: NativeBytes<AppSecretEnvelopeBytes> };
    result: AppSecretPlaintextBytes;
  };
}

export type NativeCommand = keyof NativeCommandMap;
export type NativeCommandArgs<Command extends NativeCommand> = NativeCommandMap[Command]['args'];
export type NativeCommandResult<Command extends NativeCommand> = NativeCommandMap[Command]['result'];
export type NativeCommandParameters<Command extends NativeCommand> =
  NativeCommandArgs<Command> extends undefined ? [] : [args: NativeCommandArgs<Command>];
export interface NativeInvoke {
  <Command extends NativeCommand>(
    command: Command,
    ...parameters: NativeCommandParameters<Command>
  ): Promise<NativeCommandResult<Command>>;
}
export type NativeResultDecoders = {
  readonly [Command in NativeCommand]: (
    value: unknown,
  ) => NativeCommandResult<Command>;
};
