import type { AuthIssuer, AuthSubject, MemberId } from './domain.js';

export interface AuthRegistrationAttempt {
  readonly accessToken: string;
  readonly issuer: AuthIssuer;
  readonly subject: AuthSubject;
}

export interface AuthCapabilities {
  readonly canRegister: boolean;
  readonly canLogin: boolean;
  readonly sync: boolean;
}

export interface AuthSession {
  getAccessToken(options?: { readonly forceRefresh?: boolean }): Promise<string>;
  registrationAttempt(options?: { readonly forceRefresh?: boolean }): Promise<AuthRegistrationAttempt>;
  subject(): AuthSubject | null;
  onChange(callback: () => void): () => void;
  capabilities(): AuthCapabilities;
  dispose?(): void;
}

export interface AccountIdentitySource {
  memberId(): MemberId | null;
  onChange(callback: () => void): () => void;
}

export interface PasswordCredentials {
  readonly email: string;
  readonly password: string;
}

export interface GoTrueTokenSet {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: number;
}

export interface GoTrueClientLike {
  signInWithPassword(credentials: PasswordCredentials): Promise<GoTrueTokenSet>;
  refresh(refreshToken: string): Promise<GoTrueTokenSet>;
  signOut(accessToken: string): Promise<void>;
}

export interface ActiveAuthSessionRecord {
  readonly version: 1;
  readonly revision: number;
  readonly state: 'active';
  readonly refreshToken: string;
  readonly issuer: string;
  readonly subject: string;
}

export interface InactiveAuthSessionRecord {
  readonly version: 1;
  readonly revision: number;
  readonly state: 'signed_out' | 'expired';
}

export type AuthSessionRecord = ActiveAuthSessionRecord | InactiveAuthSessionRecord;
export type AuthSessionRecordState =
  | Omit<ActiveAuthSessionRecord, 'version' | 'revision'>
  | Omit<InactiveAuthSessionRecord, 'version' | 'revision'>;

export interface AuthSessionTransactionLike {
  record(): AuthSessionRecord | null;
  commit(state: AuthSessionRecordState): { record: AuthSessionRecord; persisted: boolean };
}

export interface AuthSessionCoordinatorLike {
  read(): AuthSessionRecord | null;
  runExclusive<Result>(
    fallback: AuthSessionRecord | null,
    operation: (transaction: AuthSessionTransactionLike) => Result | PromiseLike<Result>,
  ): Promise<Awaited<Result>>;
  onRevision(callback: (revision: number) => void): () => void;
  close?(): void;
}
