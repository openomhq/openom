import type { AuthIssuer, AuthSubject, MemberId } from './domain.js';

export interface AuthRegistrationAttempt {
  readonly accessToken: string;
  readonly issuer: AuthIssuer;
  readonly subject: AuthSubject;
}

export interface AuthCapabilities {
  readonly canSignUp: boolean;
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

export interface InteractiveAuthSession extends AuthSession {
  signUp(credentials: PasswordCredentials): Promise<AuthSignUpResult>;
  signIn(credentials: PasswordCredentials): Promise<void>;
  signOut(): Promise<void>;
}

export type AuthProvider = AuthSession & Partial<Pick<InteractiveAuthSession, 'signUp' | 'signIn' | 'signOut'>>;

export interface AccountIdentitySource {
  memberId(): MemberId | null;
  onChange(callback: () => void): () => void;
}

export interface PasswordCredentials {
  readonly email: string;
  readonly password: string;
}

export type AuthSignUpResult =
  | { readonly status: 'signedIn' }
  | { readonly status: 'confirmationRequired' };

export interface GoTrueTokenSet {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: number;
}

export interface GoTrueClientLike {
  signUp(credentials: PasswordCredentials): Promise<GoTrueSignUpResult>;
  signInWithPassword(credentials: PasswordCredentials): Promise<GoTrueTokenSet>;
  refresh(refreshToken: string): Promise<GoTrueTokenSet>;
  signOut(accessToken: string): Promise<void>;
}

export type GoTrueSignUpResult =
  | { readonly status: 'signedIn'; readonly tokens: GoTrueTokenSet }
  | { readonly status: 'confirmationRequired' };

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
