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

export interface SupabaseSessionLike {
  readonly access_token: string;
  readonly user: { readonly id: AuthSubject };
}

export interface SupabaseClientLike {
  readonly auth: {
    signInWithPassword(credentials: unknown): Promise<unknown>;
    signOut(): Promise<unknown>;
  };
}
