declare const domainBrand: unique symbol;

type DomainValue<Value, Name extends string> = Value & {
  readonly [domainBrand]: Name;
};

export type TreeId = DomainValue<Uint8Array, 'TreeId'>;
export type ReplicaId = DomainValue<Uint8Array, 'ReplicaId'>;
export type MemberId = DomainValue<string, 'MemberId'>;
export type DocId = DomainValue<string, 'DocId'>;
export type TreeUuid = DomainValue<string, 'TreeUuid'>;
export type DidKey = DomainValue<string, 'DidKey'>;
export type RecordId = DomainValue<string, 'RecordId'>;
export type RemovalOperationId = DomainValue<string, 'RemovalOperationId'>;
export type ReplicaHex = DomainValue<string, 'ReplicaHex'>;
export type InviteId = DomainValue<string, 'InviteId'>;
export type InviteLink = DomainValue<string, 'InviteLink'>;
export type ProposalId = DomainValue<string, 'ProposalId'>;
export type RemoteTreeKey = DomainValue<string, 'RemoteTreeKey'>;
export type TypeUri = DomainValue<string, 'TypeUri'>;
export type PredicateUri = DomainValue<string, 'PredicateUri'>;
export type JsonValueText = DomainValue<string, 'JsonValueText'>;
export type AuthIssuer = DomainValue<string, 'AuthIssuer'>;
export type AuthSubject = DomainValue<string, 'AuthSubject'>;
export type AccountBackupEtag = DomainValue<string, 'AccountBackupEtag'>;
export type StorageCasToken = DomainValue<string, 'StorageCasToken'>;

export type Passphrase = DomainValue<string, 'Passphrase'>;
export type RecoveryCode = DomainValue<string, 'RecoveryCode'>;

export type AccountKeystoreBytes = DomainValue<Uint8Array, 'AccountKeystoreBytes'>;
export type AccountBlobHashBytes = DomainValue<Uint8Array, 'AccountBlobHashBytes'>;
export type KeyringBytes = DomainValue<Uint8Array, 'KeyringBytes'>;
export type KeyringWatermarkBytes = DomainValue<Uint8Array, 'KeyringWatermarkBytes'>;
export type TrustedSignersBytes = DomainValue<Uint8Array, 'TrustedSignersBytes'>;
export type AuthorPublicKeyBytes = DomainValue<Uint8Array, 'AuthorPublicKeyBytes'>;
export type HpkePublicKeyBytes = DomainValue<Uint8Array, 'HpkePublicKeyBytes'>;
export type KeyringHashBytes = DomainValue<Uint8Array, 'KeyringHashBytes'>;
export type DagAnchorPinBytes = DomainValue<Uint8Array, 'DagAnchorPinBytes'>;
export type FramedKeyringHopsBytes = DomainValue<Uint8Array, 'FramedKeyringHopsBytes'>;
export type KeyringUpdateBytes = DomainValue<Uint8Array, 'KeyringUpdateBytes'>;
export type RegistrationProofBytes = DomainValue<Uint8Array, 'RegistrationProofBytes'>;
export type ResetAuthorityBytes = DomainValue<Uint8Array, 'ResetAuthorityBytes'>;
export type AppSecretPlaintextBytes = DomainValue<Uint8Array, 'AppSecretPlaintextBytes'>;
export type AppSecretEnvelopeBytes = DomainValue<Uint8Array, 'AppSecretEnvelopeBytes'>;
export type ProposalEnvelopeBytes = DomainValue<Uint8Array, 'ProposalEnvelopeBytes'>;
export type ProposalCiphertextHashBytes = DomainValue<Uint8Array, 'ProposalCiphertextHashBytes'>;
export type HistoryDeltaEnvelopeBytes = DomainValue<Uint8Array, 'HistoryDeltaEnvelopeBytes'>;
export type TreeObjectBytes = DomainValue<Uint8Array, 'TreeObjectBytes'>;
export type InvitePinBytes = DomainValue<Uint8Array, 'InvitePinBytes'>;
export type InviteMacBytes = DomainValue<Uint8Array, 'InviteMacBytes'>;
export type KeyringSummaryJson = DomainValue<string, 'KeyringSummaryJson'>;
export type ClaimsJson = DomainValue<string, 'ClaimsJson'>;
export type CoveredFrontierJson = DomainValue<string, 'CoveredFrontierJson'>;
export type HistoryDeltaJson = DomainValue<string, 'HistoryDeltaJson'>;
export type LiveRecordsJson = DomainValue<string, 'LiveRecordsJson'>;
export type OplogJson = DomainValue<string, 'OplogJson'>;
export type PendingReviewsJson = DomainValue<string, 'PendingReviewsJson'>;
export type ProjectionJson = DomainValue<string, 'ProjectionJson'>;
export type PullFrontierJson = DomainValue<string, 'PullFrontierJson'>;
export type TreeObjectKey = DomainValue<string, 'TreeObjectKey'>;

export type AccountGeneration = DomainValue<number, 'AccountGeneration'>;
export type AccountRecordRevision = DomainValue<number, 'AccountRecordRevision'>;
export type KeyringRevision = DomainValue<number, 'KeyringRevision'>;
export type ReplicaCounter = DomainValue<bigint, 'ReplicaCounter'>;

export type KeyringEngine = 'chain' | 'dag';
export type MemberRole = 'owner' | 'co-owner' | 'maintainer' | 'editor' | 'viewer';
export type AccountTreeRole = 'founder' | 'member' | 'absent';
